package githttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/preflight"
	"github.com/baocin/gitscan/internal/queue"
	"github.com/baocin/gitscan/internal/ratelimit"
	"github.com/baocin/gitscan/internal/scanner"
)

// Config holds handler configuration
type Config struct {
	PrivateRepoDelaySeconds int    // Countdown delay for private repos (default: 10)
	StripeLink              string // Link to paid tier
	MaxRepoSizeKB           int64  // Max repo size in KB
}

// DefaultConfig returns default handler configuration
func DefaultConfig() Config {
	return Config{
		PrivateRepoDelaySeconds: 10,
		StripeLink:              "https://gitscan.io/pricing",
		MaxRepoSizeKB:           512000, // 500MB
	}
}

// Handler handles git HTTP protocol requests
type Handler struct {
	db        *db.DB
	cache     *cache.RepoCache
	scanner   *scanner.Scanner
	limiter   *ratelimit.Limiter
	preflight *preflight.Checker
	queue     *queue.Manager
	config    Config
	useColors bool
}

// NewHandler creates a new git HTTP handler
func NewHandler(database *db.DB, repoCache *cache.RepoCache, scan *scanner.Scanner, limiter *ratelimit.Limiter, pf *preflight.Checker, q *queue.Manager, config Config) *Handler {
	return &Handler{
		db:        database,
		cache:     repoCache,
		scanner:   scan,
		limiter:   limiter,
		preflight: pf,
		queue:     q,
		config:    config,
		useColors: true, // Default to colors
	}
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get client IP
	clientIP := getClientIP(r)

	// Parse the request path (now includes host: github.com/owner/repo)
	parsed, err := ParseRepoPathFull(r.URL.Path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Detect if this is a private repo request (has auth header)
	isPrivate := hasAuthHeader(r)

	// Check rate limit (use full path as identifier)
	if allowed, msg := h.limiter.Allow(clientIP, parsed.FullPath); !allowed {
		h.writeRateLimitResponse(w, msg)
		return
	}

	// Determine request type
	service := r.URL.Query().Get("service")
	if service == "" && strings.HasSuffix(r.URL.Path, "git-upload-pack") {
		service = "git-upload-pack"
	}

	// Handle different endpoints
	switch {
	case strings.Contains(r.URL.Path, "/info/refs"):
		h.handleInfoRefs(ctx, w, r, parsed, clientIP, startTime, isPrivate)
	case strings.Contains(r.URL.Path, "/git-upload-pack"):
		h.handleUploadPack(ctx, w, r, parsed, clientIP, startTime, isPrivate)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

// hasAuthHeader checks if the request includes authentication
func hasAuthHeader(r *http.Request) bool {
	// Check Basic Auth header
	if r.Header.Get("Authorization") != "" {
		return true
	}
	// Check for credentials in URL (git sometimes does this)
	if r.URL.User != nil {
		return true
	}
	return false
}

// handleInfoRefs handles the initial discovery request
func (h *Handler) handleInfoRefs(ctx context.Context, w http.ResponseWriter, r *http.Request, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool) {
	service := r.URL.Query().Get("service")
	if service != "git-upload-pack" {
		http.Error(w, "Only git-upload-pack is supported", http.StatusForbidden)
		return
	}

	// Set headers for git smart HTTP
	w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
	w.Header().Set("Cache-Control", "no-cache")

	// Write service announcement
	pkt := NewPktLineWriter(w)
	pkt.WriteString(fmt.Sprintf("# service=%s\n", service))
	pkt.WriteFlush()

	// For gitscan, we advertise a fake ref to trigger the upload-pack phase
	// The client will then request this ref, and we'll respond with our scan report

	// Create a fake commit ID (this won't be used for actual data transfer)
	fakeOID := "0000000000000000000000000000000000000000"

	// Write ref advertisement with capabilities
	caps := "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main agent=gitscan/1.0"
	pkt.WriteString(fmt.Sprintf("%s HEAD\x00%s\n", fakeOID, caps))
	pkt.WriteString(fmt.Sprintf("%s refs/heads/main\n", fakeOID))
	pkt.WriteFlush()
}

// handleUploadPack handles the pack negotiation and is where we inject our scan results
func (h *Handler) handleUploadPack(ctx context.Context, w http.ResponseWriter, r *http.Request, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool) {
	// Set headers
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")

	// Parse incoming request (want/have lines)
	_, err := ParseGitRequest(r.Body)
	if err != nil {
		h.writeErrorResponse(w, "Failed to parse request")
		return
	}

	// Create sideband writer for streaming output
	useColors := parsed.Mode != "plain"
	sb := NewSidebandWriter(w, useColors)

	// For private repos, show warning countdown
	if isPrivate {
		cancelled := h.showPrivateRepoWarning(ctx, sb)
		if cancelled {
			sb.WriteEmptyLine()
			sb.WriteProgress("Scan cancelled by user.")
			sb.WriteEmptyLine()
			sb.Flush()
			return
		}
	}

	// Start the scan process
	h.performScan(ctx, sb, parsed, clientIP, startTime, isPrivate)

	// End the connection (intentionally fail the clone for scan-only mode)
	sb.Flush()
}

// showPrivateRepoWarning displays a countdown warning for private repo scans
// Returns true if the user cancelled (Ctrl+C)
func (h *Handler) showPrivateRepoWarning(ctx context.Context, sb *SidebandWriter) bool {
	report := NewReportWriter(sb)
	boxWidth := 66

	sb.WriteEmptyLine()
	report.WriteBoxTop(boxWidth)
	report.WriteBoxLine(sb.Color(Yellow, "⚠  PRIVATE REPOSITORY DETECTED"), boxWidth)
	report.WriteBoxMiddle(boxWidth)
	report.WriteBoxLine("Your private repository code will be analyzed on our servers.", boxWidth)
	report.WriteBoxLine("Code is deleted immediately after scanning.", boxWidth)
	report.WriteBoxLine("", boxWidth)
	report.WriteBoxLine(sb.Color(Cyan, "Press Ctrl+C now to cancel if you do not consent."), boxWidth)
	report.WriteBoxMiddle(boxWidth)
	report.WriteBoxLine(fmt.Sprintf("Skip this delay: %s", h.config.StripeLink), boxWidth)
	report.WriteBoxBottom(boxWidth)
	sb.WriteEmptyLine()

	// Countdown
	for i := h.config.PrivateRepoDelaySeconds; i > 0; i-- {
		// Check if client disconnected (Ctrl+C)
		select {
		case <-ctx.Done():
			return true // User cancelled
		default:
			// Continue countdown
		}

		sb.WriteProgressf("Starting scan in %d seconds... (Ctrl+C to cancel)", i)

		// Wait 1 second, but check for cancellation every 100ms
		for j := 0; j < 10; j++ {
			select {
			case <-ctx.Done():
				return true // User cancelled during wait
			case <-time.After(100 * time.Millisecond):
				// Continue waiting
			}
		}
	}

	sb.WriteProgress(sb.Color(Green, "✓ Proceeding with scan..."))
	sb.WriteEmptyLine()
	return false
}

// checkClientDisconnected checks if the client has disconnected
func checkClientDisconnected(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
		return false
	}
}

// performScan fetches the repo, scans it, and writes results via sideband
func (h *Handler) performScan(ctx context.Context, sb *SidebandWriter, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool) {
	report := NewReportWriter(sb)
	boxWidth := 66

	sb.WriteEmptyLine()

	// Step 0: Preflight checks (disk space only, no API calls)
	if h.preflight != nil {
		sb.WriteProgress("[gitscan] Running preflight checks...")

		// Check disk space
		available, ok, err := h.preflight.CheckDiskSpace(h.cache.GetCacheDir())
		if err == nil && !ok {
			sb.WriteEmptyLine()
			report.WriteBoxTop(boxWidth)
			report.WriteBoxLine(sb.Color(Red, "ERROR: Server disk space low"), boxWidth)
			report.WriteBoxLine(fmt.Sprintf("Available: %s", preflight.FormatSize(available)), boxWidth)
			report.WriteBoxLine("Please try again later.", boxWidth)
			report.WriteBoxBottom(boxWidth)
			sb.WriteEmptyLine()
			return
		}
		sb.WriteProgressf("[gitscan] Preflight OK (disk space: %s free)", preflight.FormatSize(available))
	}

	// Check for client disconnect before starting heavy work
	if checkClientDisconnected(ctx) {
		return // Client cancelled, abort silently
	}

	// Step 1: Fetch repository (shallow clone)
	frame := 0
	sb.WriteProgressf("%s [gitscan] Fetching from %s (shallow clone)...", SpinnerFrames[frame%len(SpinnerFrames)], parsed.Host)

	// Use full path as cache key, and construct proper clone URL
	cloneURL := parsed.GetCloneURL()
	repo, err := h.cache.FetchRepo(ctx, parsed.FullPath, cloneURL, func(progress string) {
		// Check for disconnect during fetch
		if checkClientDisconnected(ctx) {
			return
		}
		frame++
		sb.WriteProgressf("%s [gitscan] %s", SpinnerFrames[frame%len(SpinnerFrames)], progress)
	})

	// Check if cancelled during fetch
	if checkClientDisconnected(ctx) {
		// Clean up partial clone if needed
		return
	}

	if err != nil {
		sb.WriteEmptyLine()
		report.WriteBoxTop(boxWidth)
		report.WriteBoxLine(sb.Color(Red, "ERROR: Failed to fetch repository"), boxWidth)
		report.WriteBoxLine(err.Error(), boxWidth)
		report.WriteBoxBottom(boxWidth)
		sb.WriteEmptyLine()
		return
	}

	sb.WriteProgressf("%s [gitscan] Fetched. %d files", IconSuccess, repo.FileCount)

	// Step 2: Check for cached scan
	cachedScan, err := h.db.GetScanByRepoAndCommit(repo.ID, repo.LastCommitSHA)
	if err == nil && cachedScan != nil {
		sb.WriteProgressf("%s [gitscan] Using cached scan results", IconSuccess)
		h.writeScanReport(sb, report, parsed, repo, cachedScan, boxWidth, true)
		return
	}

	// Check for client disconnect before scanning
	if checkClientDisconnected(ctx) {
		return
	}

	// Step 3: Run scan
	sb.WriteProgressf("%s [gitscan] Scanning with opengrep...", SpinnerFrames[frame%len(SpinnerFrames)])

	scanResult, err := h.scanner.Scan(ctx, repo.LocalPath, func(progress scanner.Progress) {
		// Check for disconnect during scan
		if checkClientDisconnected(ctx) {
			return
		}
		frame++
		sb.WriteProgressf("%s [gitscan] Scanning: %d/%d files (%d%%)",
			SpinnerFrames[frame%len(SpinnerFrames)],
			progress.FilesScanned, progress.FilesTotal, progress.Percent)
	})

	// Check if cancelled during scan
	if checkClientDisconnected(ctx) {
		return
	}

	if err != nil {
		sb.WriteEmptyLine()
		report.WriteBoxTop(boxWidth)
		report.WriteBoxLine(sb.Color(Red, "ERROR: Scan failed"), boxWidth)
		report.WriteBoxLine(err.Error(), boxWidth)
		report.WriteBoxBottom(boxWidth)
		sb.WriteEmptyLine()
		return
	}

	sb.WriteProgressf("%s [gitscan] Scan complete!", IconSuccess)

	// Step 4: Save scan results
	dbScan := &db.Scan{
		RepoID:         repo.ID,
		CommitSHA:      repo.LastCommitSHA,
		ResultsJSON:    scanResult.RawJSON,
		CriticalCount:  scanResult.CriticalCount,
		HighCount:      scanResult.HighCount,
		MediumCount:    scanResult.MediumCount,
		LowCount:       scanResult.LowCount,
		InfoCount:      scanResult.InfoCount,
		FilesScanned:   scanResult.FilesScanned,
		ScanDurationMS: scanResult.Duration.Milliseconds(),
	}
	h.db.CreateScan(dbScan)

	// Step 5: Write report
	h.writeScanReport(sb, report, parsed, repo, dbScan, boxWidth, false)

	// Log request
	responseTime := time.Since(startTime)
	h.db.LogRequest(&db.Request{
		IP:             clientIP,
		RepoURL:        parsed.FullPath,
		CommitSHA:      repo.LastCommitSHA,
		RequestMode:    parsed.Mode,
		ScanID:         &dbScan.ID,
		CacheHit:       false,
		ResponseTimeMS: responseTime.Milliseconds(),
	})
}

// writeScanReport writes the formatted scan report via sideband
func (h *Handler) writeScanReport(sb *SidebandWriter, report *ReportWriter, parsed *ParsedPath, repo *cache.CachedRepo, scan *db.Scan, width int, cacheHit bool) {
	sb.WriteEmptyLine()

	// Header
	report.WriteBoxTop(width)
	report.WriteBoxLine(sb.Bold("GITSCAN SECURITY REPORT"), width)
	report.WriteBoxLine(fmt.Sprintf("Repository: %s", parsed.FullPath), width)
	report.WriteBoxLine(fmt.Sprintf("Commit: %s", truncate(scan.CommitSHA, 12)), width)
	report.WriteBoxLine(fmt.Sprintf("Scanned: %d files in %.1fs", scan.FilesScanned, float64(scan.ScanDurationMS)/1000), width)
	if cacheHit {
		report.WriteBoxLine(sb.Color(Cyan, "(cached result)"), width)
	}

	// Summary line
	report.WriteBoxMiddle(width)
	summaryLine := fmt.Sprintf("%s %d Critical   %s %d High   %s %d Medium   %s %d Low",
		sb.Color(Red, IconCritical), scan.CriticalCount,
		sb.Color(Yellow, IconHigh), scan.HighCount,
		sb.Color(Blue, IconMedium), scan.MediumCount,
		IconLow, scan.LowCount,
	)
	report.WriteBoxLine(summaryLine, width)

	// TODO: Add individual findings from ResultsJSON
	// This would parse the SARIF output and display top findings

	// Footer
	report.WriteBoxMiddle(width)
	report.WriteBoxLine(fmt.Sprintf("Full report: https://gitscan.io/r/%s", truncate(scan.CommitSHA, 8)), width)
	// Show the actual clone URL (e.g., https://github.com/user/repo)
	cloneURL := fmt.Sprintf("https://%s/%s/%s", parsed.Host, parsed.Owner, parsed.Repo)
	report.WriteBoxLine(fmt.Sprintf("To clone: git clone %s", cloneURL), width)
	report.WriteBoxBottom(width)

	sb.WriteEmptyLine()
}

// writeRateLimitResponse writes a rate limit error via sideband-style output
func (h *Handler) writeRateLimitResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")

	sb := NewSidebandWriter(w, true)
	report := NewReportWriter(sb)
	boxWidth := 60

	sb.WriteEmptyLine()
	report.WriteBoxTop(boxWidth)
	report.WriteBoxLine(sb.Color(Yellow, "RATE LIMIT EXCEEDED"), boxWidth)
	report.WriteBoxLine("", boxWidth)
	report.WriteBoxLine(message, boxWidth)
	report.WriteBoxLine("", boxWidth)
	report.WriteBoxLine("Please wait before making more requests.", boxWidth)
	report.WriteBoxBottom(boxWidth)
	sb.WriteEmptyLine()
	sb.Flush()
}

// writeErrorResponse writes an error via sideband
func (h *Handler) writeErrorResponse(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")

	sb := NewSidebandWriter(w, true)
	sb.WriteError(message)
	sb.Flush()
}

// getClientIP extracts the client IP from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (for proxies)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// Fall back to RemoteAddr
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		return addr[:idx]
	}
	return addr
}

// truncate truncates a string to the given length
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}
