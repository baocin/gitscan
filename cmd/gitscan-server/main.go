package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/githttp"
	"github.com/baocin/gitscan/internal/ratelimit"
	"github.com/baocin/gitscan/internal/scanner"
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
		listenAddr   = flag.String("listen", ":8080", "HTTP listen address")
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
	log.Printf("Scanner initialized: %s", *openGrepPath)

	// Initialize rate limiter
	limiterCfg := ratelimit.DefaultConfig()
	limiter := ratelimit.New(database, limiterCfg)
	log.Printf("Rate limiter: %d req/min, %d req/hour per IP", limiterCfg.IPPerMinute, limiterCfg.IPPerHour)

	// Create git HTTP handler
	gitHandler := githttp.NewHandler(database, repoCache, scan, limiter)

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

	// Git protocol handler (catch-all for repo paths)
	mux.Handle("/", gitHandler)

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
