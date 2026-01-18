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
	"github.com/baocin/gitscan/internal/metrics"
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
		scanTimeout  = flag.Int("scan-timeout", 180, "Scan timeout in seconds (default: 180s/3min)")
		resetDB      = flag.Bool("reset-db", true, "Reset database on startup (default: true)")
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

	// Reset database if requested
	if *resetDB {
		if err := database.ResetTables(); err != nil {
			log.Fatalf("Failed to reset database: %v", err)
		}
	}

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
	scannerCfg.Timeout = time.Duration(*scanTimeout) * time.Second
	scan := scanner.New(scannerCfg)

	// Check if scanner is available
	if available, path := scan.IsAvailable(); available {
		log.Printf("Scanner initialized: %s (found at %s, timeout: %ds)", *openGrepPath, path, *scanTimeout)
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

	// Initialize metrics
	metricsCollector := metrics.New()
	log.Printf("Metrics collector initialized")

	// Create git HTTP handler
	handlerCfg := githttp.DefaultConfig()
	gitHandler := githttp.NewHandler(database, repoCache, scan, limiter, preflightChecker, queueManager, metricsCollector, handlerCfg)

	// Create web handler for marketing pages
	webHandler, err := web.NewHandler(database)
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

	// Metrics endpoint
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		data, err := metricsCollector.JSON()
		if err != nil {
			http.Error(w, "Failed to encode metrics", http.StatusInternalServerError)
			return
		}
		w.Write(data)
	})

	// Static files
	mux.HandleFunc("/static/", webHandler.ServeStatic)

	// Web pages
	mux.HandleFunc("/pricing", webHandler.ServePricing)
	mux.HandleFunc("/pricing/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/pricing", http.StatusMovedPermanently)
	})
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

	// Create HTTP server with security middleware
	httpServer := &http.Server{
		Addr:         *listenAddr,
		Handler:      logRequest(blockSuspiciousPaths(database, mux)),
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
			Handler:      logRequest(blockSuspiciousPaths(database, mux)),
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

// blockSuspiciousPaths is a middleware that blocks common hacking/scanning attempts
func blockSuspiciousPaths(database *db.DB, next http.Handler) http.Handler {
	// Configuration for auto-ban
	const (
		suspiciousRequestThreshold = 5                // Ban after 5 suspicious requests
		suspiciousRequestWindow    = 5 * time.Minute  // Within 5 minutes
		banDuration                = 24 * time.Hour   // Ban for 24 hours
		tarpitDelay                = 30 * time.Second // Delay suspicious requests by 30s
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Extract client IP
		clientIP := r.RemoteAddr
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			clientIP = strings.TrimSpace(parts[0])
		} else if xri := r.Header.Get("X-Real-IP"); xri != "" {
			clientIP = xri
		} else if idx := strings.LastIndex(clientIP, ":"); idx != -1 {
			clientIP = clientIP[:idx]
		}

		// Check if IP is already banned
		if database != nil {
			banned, reason, err := database.IsIPBanned(clientIP)
			if err == nil && banned {
				log.Printf("[SECURITY] Rejected request from banned IP %s: %s", clientIP, reason)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Common attack patterns to block
		suspiciousPatterns := []string{
			"/.env",
			"/config.php",
			"/config.js",
			"/aws-config",
			"/aws.config",
			"/.git/",
			"/admin/.env",
			"/backend/.env",
			"/api/.env",
			"/.env.bak",
			"/.env.save",
			"/.env.local",
			"/.env.production",
			"/wp-admin",
			"/phpMyAdmin",
			"/phpmyadmin",
			"/mysql",
			"/.aws/",
			"/credentials",
			"/.ssh/",
			"/id_rsa",
			"/cdn-cgi/",
		}

		// Check if path matches any suspicious pattern
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(path, pattern) {
				// Log the suspicious request
				log.Printf("[SECURITY] Blocked suspicious request: %s %s from %s", r.Method, path, clientIP)

				// Track suspicious request in database
				if database != nil {
					database.LogSuspiciousRequest(clientIP, path, r.UserAgent())

					// Check if this IP should be auto-banned
					count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
					if err == nil && count >= suspiciousRequestThreshold {
						reason := fmt.Sprintf("Auto-banned: %d suspicious requests in %v", count, suspiciousRequestWindow)
						database.BanIP(clientIP, reason, banDuration)
						log.Printf("[SECURITY] AUTO-BANNED IP %s: %s", clientIP, reason)
					}
				}

				// Tarpit: delay response to waste attacker's time
				time.Sleep(tarpitDelay)

				// Return 403 Forbidden
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Path is clean, continue to next handler
		next.ServeHTTP(w, r)
	})
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
