package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/githttp"
	"github.com/baocin/gitscan/internal/preflight"
	"github.com/baocin/gitscan/internal/queue"
	"github.com/baocin/gitscan/internal/ratelimit"
	"github.com/baocin/gitscan/internal/scanner"
	"github.com/baocin/gitscan/web"
)

// Version information (set at build time)
var (
	Version   = "dev"
	BuildTime = "unknown"
	GitCommit = "unknown"
)

func main() {
	// Parse command line flags
	var (
		listenAddr   = flag.String("listen", ":6633", "HTTP listen address")
		tlsAddr      = flag.String("tls-listen", ":8443", "HTTPS listen address")
		tlsCert      = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey       = flag.String("tls-key", "", "TLS private key file")
		dbPath       = flag.String("db", "gitscan.db", "SQLite database path")
		cacheDir     = flag.String("cache-dir", "/tmp/gitscan-cache", "Repository cache directory")
		openGrepPath = flag.String("opengrep", "opengrep", "Path to opengrep binary")
		rulesPath    = flag.String("rules", "", "Path to opengrep rules directory")
		showVersion  = flag.Bool("version", false, "Show version and exit")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("gitscan %s (built %s, commit %s)\n", Version, BuildTime, GitCommit)
		os.Exit(0)
	}

	log.Printf("Starting gitscan server %s", Version)

	// Initialize database
	database, err := db.New(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer database.Close()
	log.Printf("Database initialized: %s", *dbPath)

	// Initialize cache
	cacheCfg := cache.DefaultConfig()
	cacheCfg.CacheDir = *cacheDir
	repoCache, err := cache.New(database, cacheCfg)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}
	log.Printf("Cache directory: %s", *cacheDir)

	// Initialize scanner
	scannerCfg := scanner.DefaultConfig()
	scannerCfg.BinaryPath = *openGrepPath
	scannerCfg.RulesPath = *rulesPath
	scan := scanner.New(scannerCfg)

	// Check if scanner is available
	if available, path := scan.IsAvailable(); available {
		log.Printf("Scanner initialized: %s (found at %s)", *openGrepPath, path)
	} else {
		log.Printf("WARNING: Scanner binary '%s' not found in PATH - scans will fail!", *openGrepPath)
	}

	// Initialize rate limiter
	limiterCfg := ratelimit.DefaultConfig()
	limiter := ratelimit.New(database, limiterCfg)
	log.Printf("Rate limiter: %d req/min, %d req/hour per IP", limiterCfg.IPPerMinute, limiterCfg.IPPerHour)

	// Initialize preflight checker
	preflightCfg := preflight.DefaultConfig()
	preflightChecker := preflight.NewChecker(preflightCfg)
	log.Printf("Preflight: max transfer %dMB, min free disk %dGB", preflightCfg.MaxTransferBytes/(1024*1024), preflightCfg.MinFreeDiskBytes/(1024*1024*1024))

	// Initialize queue manager
	queueCfg := queue.DefaultConfig()
	queueManager := queue.NewManager(queueCfg)
	log.Printf("Queue: %d public slots, %d private slots", queueCfg.MaxConcurrentPublic, queueCfg.MaxConcurrentPrivate)

	// Create git HTTP handler
	handlerCfg := githttp.DefaultConfig()
	gitHandler := githttp.NewHandler(database, repoCache, scan, limiter, preflightChecker, queueManager, handlerCfg)

	// Create web handler for marketing pages
	webHandler, err := web.NewHandler()
	if err != nil {
		log.Fatalf("Failed to initialize web handler: %v", err)
	}

	// Set up HTTP server with routes
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// Version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"version":"%s","build_time":"%s","git_commit":"%s"}`, Version, BuildTime, GitCommit)
	})

	// Static files
	mux.HandleFunc("/static/", webHandler.ServeStatic)

	// Web pages
	mux.HandleFunc("/pricing", webHandler.ServePricing)
	mux.HandleFunc("/r/", webHandler.ServeReport)

	// Smart router: web pages vs git protocol
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Serve homepage at root
		if path == "/" {
			webHandler.ServeHome(w, r)
			return
		}

		// Check if this is a git request (starts with supported host or mode)
		gitHosts := []string{"github.com", "gitlab.com", "bitbucket.org"}
		gitModes := []string{"scan", "clone", "json", "plain"}

		pathPart := strings.TrimPrefix(path, "/")
		firstPart := strings.Split(pathPart, "/")[0]

		isGitRequest := false
		for _, host := range gitHosts {
			if firstPart == host {
				isGitRequest = true
				break
			}
		}
		for _, mode := range gitModes {
			if firstPart == mode {
				isGitRequest = true
				break
			}
		}

		if isGitRequest {
			gitHandler.ServeHTTP(w, r)
			return
		}

		// Default: 404
		http.NotFound(w, r)
	})

	// Create HTTP server
	httpServer := &http.Server{
		Addr:         *listenAddr,
		Handler:      logRequest(mux),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	// Start servers
	errChan := make(chan error, 2)

	// Start HTTP server
	go func() {
		log.Printf("HTTP server listening on %s", *listenAddr)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			errChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if certificates provided
	var httpsServer *http.Server
	if *tlsCert != "" && *tlsKey != "" {
		httpsServer = &http.Server{
			Addr:         *tlsAddr,
			Handler:      logRequest(mux),
			ReadTimeout:  5 * time.Minute,
			WriteTimeout: 5 * time.Minute,
			IdleTimeout:  60 * time.Second,
		}
		go func() {
			log.Printf("HTTPS server listening on %s", *tlsAddr)
			if err := httpsServer.ListenAndServeTLS(*tlsCert, *tlsKey); err != http.ErrServerClosed {
				errChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
	case err := <-errChan:
		log.Printf("Server error: %v", err)
	}

	// Graceful shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP server shutdown error: %v", err)
	}
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			log.Printf("HTTPS server shutdown error: %v", err)
		}
	}

	log.Println("Server stopped")
}

// logRequest is a middleware that logs HTTP requests
func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, r)

		log.Printf("%s %s %s %d %v",
			r.Method,
			r.URL.Path,
			r.RemoteAddr,
			wrapped.statusCode,
			time.Since(start),
		)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
