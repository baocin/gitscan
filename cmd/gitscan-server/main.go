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

	"github.com/baocin/gitscan/internal/blocklist"
	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/githttp"
	"github.com/baocin/gitscan/internal/metrics"
	"github.com/baocin/gitscan/internal/preflight"
	"github.com/baocin/gitscan/internal/queue"
	"github.com/baocin/gitscan/internal/ratelimit"
	"github.com/baocin/gitscan/internal/scanner"
	"github.com/baocin/gitscan/internal/sshserver"
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
		listenAddr        = flag.String("listen", "0.0.0.0:80", "HTTP listen address")
		tlsAddr           = flag.String("tls-listen", "0.0.0.0:443", "HTTPS listen address")
		tlsCert           = flag.String("tls-cert", "", "TLS certificate file")
		tlsKey            = flag.String("tls-key", "", "TLS private key file")
		sshListenAddr     = flag.String("ssh-listen", "0.0.0.0:22", "SSH listen address for git protocol")
		sshHostKeyPath    = flag.String("ssh-host-key", "/var/lib/gitvet/ssh_host_key", "Path to SSH host key")
		enableSSH         = flag.Bool("enable-ssh", true, "Enable SSH server for git clone ssh://")
		dbPath            = flag.String("db", "gitscan.db", "SQLite database path")
		cacheDir          = flag.String("cache-dir", "/tmp/gitscan-cache", "Repository cache directory")
		maxFileSize       = flag.Int64("max-file-size", 1048576, "Max file size to download in bytes (default: 1MB)")
		openGrepPath      = flag.String("opengrep", "opengrep", "Path to opengrep binary")
		rulesPath         = flag.String("rules", "", "Path to opengrep rules directory")
		scanTimeout       = flag.Int("scan-timeout", 180, "Scan timeout in seconds (default: 180s/3min)")
		resetDB           = flag.Bool("reset-db", true, "Reset database on startup (default: true)")
		showVersion       = flag.Bool("version", false, "Show version and exit")
		allowCustomHosts  = flag.Bool("allow-custom-hosts", false, "Allow custom git hosts (self-hosted repos). Default: only github.com, gitlab.com, bitbucket.org")
		infoLeakOnly      = flag.Bool("info-leak-only", false, "Only scan for credential theft patterns (9x faster, focuses on malicious code)")
		enableBlocklist   = flag.Bool("enable-blocklist", true, "Enable threat intelligence blocklists")
		blocklistUpdate   = flag.Int("blocklist-update-hours", 12, "Hours between blocklist updates")
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
	cacheCfg.MaxFileSize = *maxFileSize
	repoCache, err := cache.New(database, cacheCfg)
	if err != nil {
		log.Fatalf("Failed to initialize cache: %v", err)
	}
	log.Printf("Cache directory: %s, max file size: %d bytes", *cacheDir, *maxFileSize)

	// Initialize scanner
	scannerCfg := scanner.DefaultConfig()
	scannerCfg.BinaryPath = *openGrepPath
	scannerCfg.RulesPath = *rulesPath
	scannerCfg.Timeout = time.Duration(*scanTimeout) * time.Second
	scannerCfg.InfoLeakOnly = *infoLeakOnly
	scan := scanner.New(scannerCfg)

	// Check if scanner is available
	if available, path := scan.IsAvailable(); available {
		mode := "full security scan"
		if *infoLeakOnly {
			mode = "info-leak only (credential theft detection, 9x faster)"
		}
		log.Printf("Scanner initialized: %s (found at %s, timeout: %ds, mode: %s)", *openGrepPath, path, *scanTimeout, mode)
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

	// Initialize blocklist if enabled
	var blocklistManager *blocklist.Manager
	if *enableBlocklist {
		blocklistCfg := blocklist.DefaultConfig()
		blocklistCfg.Enabled = true
		blocklistCfg.UpdateInterval = time.Duration(*blocklistUpdate) * time.Hour
		blocklistManager = blocklist.New(database, blocklistCfg)

		// Load existing entries from database
		ctx := context.Background()
		if err := blocklistManager.LoadFromDatabase(ctx); err != nil {
			log.Printf("[blocklist] Warning: Failed to load from database: %v", err)
		} else {
			stats := blocklistManager.GetStats()
			log.Printf("[blocklist] Loaded %d entries from database", stats.TotalEntries)
		}

		// Start automatic updates in background
		go blocklistManager.StartAutoUpdates(context.Background())
		log.Printf("[blocklist] Enabled with %d hour update interval", *blocklistUpdate)
	} else {
		log.Printf("[blocklist] Disabled")
	}

	// Create git HTTP handler
	handlerCfg := githttp.DefaultConfig()
	handlerCfg.AllowCustomHosts = *allowCustomHosts
	if *allowCustomHosts {
		log.Printf("Custom hosts enabled: self-hosted repos allowed (dangerous IPs still blocked)")
	} else {
		log.Printf("Custom hosts disabled: only github.com, gitlab.com, bitbucket.org allowed")
	}
	gitHandler := githttp.NewHandler(database, repoCache, scan, limiter, preflightChecker, queueManager, metricsCollector, handlerCfg)

	// Create web handler for marketing pages
	webHandler, err := web.NewHandler(database, metricsCollector)
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
	mux.HandleFunc("/docs", webHandler.ServeDocs)
	mux.HandleFunc("/docs/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/docs", http.StatusMovedPermanently)
	})
	mux.HandleFunc("/stats", webHandler.ServeStats)
	mux.HandleFunc("/r/", webHandler.ServeReport)
	mux.HandleFunc("/reports/", webHandler.ServeRepoReports)

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
		Handler:      logRequest(blockSuspiciousPaths(database, blocklistManager, mux)),
		ReadTimeout:  5 * time.Minute,
		WriteTimeout: 5 * time.Minute,
		IdleTimeout:  60 * time.Second,
	}

	// Start servers
	errChan := make(chan error, 3) // HTTP + HTTPS + SSH

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
			Handler:      logRequest(blockSuspiciousPaths(database, blocklistManager, mux)),
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

	// Start SSH server if enabled
	var sshSrv *sshserver.Server
	if *enableSSH {
		sshConfig := sshserver.Config{
			ListenAddr:  *sshListenAddr,
			HostKeyPath: *sshHostKeyPath,
		}
		var err error
		sshSrv, err = sshserver.New(sshConfig, gitHandler, database, blocklistManager)
		if err != nil {
			log.Fatalf("Failed to create SSH server: %v", err)
		}

		go func() {
			log.Printf("SSH server listening on %s", *sshListenAddr)
			if err := sshSrv.Listen(); err != nil {
				errChan <- fmt.Errorf("SSH server error: %w", err)
			}
		}()
	} else {
		log.Printf("SSH server disabled")
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
	if sshSrv != nil {
		if err := sshSrv.Close(); err != nil {
			log.Printf("SSH server shutdown error: %v", err)
		}
	}

	log.Println("Server stopped")
}

// blockSuspiciousPaths is a middleware that blocks common hacking/scanning attempts
func blockSuspiciousPaths(database *db.DB, blocklistMgr *blocklist.Manager, next http.Handler) http.Handler {
	// Configuration for auto-ban
	const (
		suspiciousRequestThreshold = 3                // Ban after 3 suspicious requests (reduced from 5)
		suspiciousRequestWindow    = 2 * time.Minute  // Within 2 minutes (reduced from 5)
		banDuration                = 48 * time.Hour   // Ban for 48 hours (2 days)
		tarpitDelay                = 30 * time.Second // Delay suspicious requests by 30s
	)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		method := r.Method

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

		// Check threat intelligence blocklist first (fail fast)
		// IPs in blocklist are already considered banned, no need to add to ban table
		if blocklistMgr != nil && blocklistMgr.IsLoaded() {
			blocked, source, reason := blocklistMgr.IsBlocked(clientIP)
			if blocked {
				log.Printf("[BLOCKLIST] Rejected IP %s from %s: %s", clientIP, source, reason)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
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

		// Block CONNECT method (HTTP proxy tunneling attempts)
		if method == "CONNECT" {
			log.Printf("[BLOCKED] CONNECT method from %s to %s", clientIP, path)
			if database != nil {
				database.LogSuspiciousRequest(clientIP, fmt.Sprintf("CONNECT %s", path), r.UserAgent())
				count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
				if err == nil && count >= suspiciousRequestThreshold {
					reason := fmt.Sprintf("Auto-banned: %d suspicious requests in %v", count, suspiciousRequestWindow)
					database.BanIP(clientIP, reason, banDuration)
					log.Printf("[SECURITY] AUTO-BANNED IP %s: %s", clientIP, reason)
				}
			}
			time.Sleep(tarpitDelay)
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		// Block WebDAV methods (scanning/reconnaissance attempts)
		webdavMethods := []string{"PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK"}
		for _, webdavMethod := range webdavMethods {
			if method == webdavMethod {
				log.Printf("[BLOCKED] %s method from %s to %s (WebDAV probing)", method, clientIP, path)
				if database != nil {
					database.LogSuspiciousRequest(clientIP, fmt.Sprintf("%s %s", method, path), r.UserAgent())
					count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
					if err == nil && count >= suspiciousRequestThreshold {
						reason := fmt.Sprintf("Auto-banned: %d suspicious requests (WebDAV probing) in %v", count, suspiciousRequestWindow)
						database.BanIP(clientIP, reason, banDuration)
						log.Printf("[SECURITY] AUTO-BANNED IP %s: %s", clientIP, reason)
					}
				}
				time.Sleep(tarpitDelay)
				http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
				return
			}
		}

		// Common attack patterns to block
		suspiciousPatterns := []string{
			// Environment files
			"/.env",
			"/admin/.env",
			"/backend/.env",
			"/api/.env",
			"/.env.bak",
			"/.env.save",
			"/.env.local",
			"/.env.production",
			"/aws-config",
			"/aws.config",
			"/.aws/",
			"/credentials",

			// Git/SSH access
			"/.git/",
			"/.ssh/",
			"/id_rsa",

			// PHP files (common webshells and config files)
			"/config.php",
			"/config.js",

			// WordPress/CMS
			"/wp-admin",
			"/wp-config",
			"/xmlrpc.php",
			"/phpMyAdmin",
			"/phpmyadmin",
			"/mysql",

			// Next.js/React framework probing
			"/_next/",
			"/api/route",
			"/app/api",
			"/_next/server",

			// Other framework paths
			"/graphql",
			"/actuator/",
			"/.well-known/security.txt",
			"/cdn-cgi/",

			// Common webshell names
			"/shell.php",
			"/c99.php",
			"/r57.php",
			"/wso.php",

			// Credential/config file harvesting
			"/secrets.json",
			"/credentials.json",
			"/settings.json",
			"/settings.js",
			"/docker-compose",
			"/config/master.key",
			"/serverless.yml",
			"/serverless.yaml",
			"/vercel.json",
			"/netlify.toml",
			"/appsettings",
		}

		// Check for generic PHP file requests (except legitimate ones)
		if strings.HasSuffix(path, ".php") && !isLegitimatePhpPath(path) {
			log.Printf("[BLOCKED] PHP file probe: %s from %s", path, clientIP)
			if database != nil {
				database.LogSuspiciousRequest(clientIP, path, r.UserAgent())
				count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
				if err == nil && count >= suspiciousRequestThreshold {
					reason := fmt.Sprintf("Auto-banned: %d suspicious requests (PHP probing) in %v", count, suspiciousRequestWindow)
					database.BanIP(clientIP, reason, banDuration)
					log.Printf("[SECURITY] AUTO-BANNED IP %s: %s", clientIP, reason)
				}
			}
			time.Sleep(tarpitDelay)
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Check for suspicious POST requests to non-existent paths
		if method == "POST" && (path == "/" || strings.HasPrefix(path, "/_next") || strings.HasPrefix(path, "/api") || strings.HasPrefix(path, "/app")) {
			// Allow POST to root with service parameter (for git protocol)
			if path == "/" && r.URL.Query().Get("service") != "" {
				// Legitimate git request, allow it
			} else {
				log.Printf("[BLOCKED] Suspicious POST: %s from %s", path, clientIP)
				if database != nil {
					database.LogSuspiciousRequest(clientIP, fmt.Sprintf("POST %s", path), r.UserAgent())
					count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
					if err == nil && count >= suspiciousRequestThreshold {
						reason := fmt.Sprintf("Auto-banned: %d suspicious requests (framework probing) in %v", count, suspiciousRequestWindow)
						database.BanIP(clientIP, reason, banDuration)
						log.Printf("[SECURITY] AUTO-BANNED IP %s: %s", clientIP, reason)
					}
				}
				time.Sleep(tarpitDelay)
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
		}

		// Check if path matches any suspicious pattern
		for _, pattern := range suspiciousPatterns {
			if strings.Contains(path, pattern) {
				// Log the suspicious request
				log.Printf("[BLOCKED] Suspicious path pattern '%s' in %s from %s", pattern, path, clientIP)

				// Track suspicious request in database
				if database != nil {
					database.LogSuspiciousRequest(clientIP, path, r.UserAgent())

					// Check if this IP should be auto-banned
					count, err := database.CountRecentSuspiciousRequests(clientIP, suspiciousRequestWindow)
					if err == nil && count >= suspiciousRequestThreshold {
						reason := fmt.Sprintf("Auto-banned: %d suspicious requests in %v", count, suspiciousRequestWindow)
						database.BanIP(clientIP, reason, banDuration)
						log.Printf("[SECURITY] AUTO-BANNED IP %s: %s (total suspicious: %d)", clientIP, reason, count)
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

// isLegitimatePhpPath checks if a PHP file request is legitimate
// Currently git.vet has no legitimate PHP files, so all .php requests are suspicious
func isLegitimatePhpPath(path string) bool {
	// git.vet is a Go application with no PHP files
	// All .php requests are scanning attempts
	return false
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
