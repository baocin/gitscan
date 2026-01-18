package githttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/metrics"
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
		StripeLink:              "https://git.vet/pricing",
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
	metrics   *metrics.Metrics
	config    Config
	useColors bool
}

// NewHandler creates a new git HTTP handler
func NewHandler(database *db.DB, repoCache *cache.RepoCache, scan *scanner.Scanner, limiter *ratelimit.Limiter, pf *preflight.Checker, q *queue.Manager, m *metrics.Metrics, config Config) *Handler {
	return &Handler{
		db:        database,
		cache:     repoCache,
		scanner:   scan,
		limiter:   limiter,
		preflight: pf,
		queue:     q,
		metrics:   m,
		config:    config,
		useColors: true, // Default to colors
	}
}

// GetMetrics returns the metrics instance for external access (e.g., /metrics endpoint)
func (h *Handler) GetMetrics() *metrics.Metrics {
	return h.metrics
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
	caps := "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main agent=git.vet/1.0"
	pkt.WriteString(fmt.Sprintf("%s HEAD\x00%s\n", fakeOID, caps))
	pkt.WriteString(fmt.Sprintf("%s refs/heads/main\n", fakeOID))
	pkt.WriteFlush()
}

// handleUploadPack handles the pack negotiation and is where we inject our scan results
func (h *Handler) handleUploadPack(ctx context.Context, w http.ResponseWriter, r *http.Request, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool) {
	// Set headers
	w.Header().Set("Content-Type", "application/x-git-upload-pack-result")
	w.Header().Set("Cache-Control", "no-cache")

	// Check for secret cache bypass param
	skipCache := r.URL.Query().Has("cachebuster3000")

	// Parse incoming request (want/have lines)
	_, err := ParseGitRequest(r.Body)
	if err != nil {
		h.writeErrorResponse(w, "Failed to parse request")
		return
	}

	// Send NAK first - required by git protocol before sideband messages
	pkt := NewPktLineWriter(w)
	pkt.WriteString("NAK\n")

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
	h.performScan(ctx, sb, parsed, clientIP, startTime, isPrivate, skipCache)

	// Send empty packfile and flush to properly terminate git protocol
	sb.WriteEmptyPackfile()
	sb.Flush()
}

// showPrivateRepoWarning displays a countdown warning for private repo scans
// Returns true if the user cancelled (Ctrl+C)
func (h *Handler) showPrivateRepoWarning(ctx context.Context, sb *SidebandWriter) bool {
	report := NewReportWriter(sb)
	boxWidth := 80

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
func (h *Handler) performScan(ctx context.Context, sb *SidebandWriter, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool, skipCache bool) {
	report := NewReportWriter(sb)
	boxWidth := 80

	// Track scan metrics - this returns a done callback
	var scanDone func()
	if h.metrics != nil {
		scanDone = h.metrics.ScanStarted()
		defer func() {
			if scanDone != nil {
				scanDone()
			}
		}()
	}

	sb.WriteEmptyLine()

	// Step 0: Preflight checks (disk space only, no API calls)
	if h.preflight != nil {
		sb.WriteProgress("[git.vet] Running preflight checks...")

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
		sb.WriteProgress("[git.vet] Preflight OK")
	}

	// Check for client disconnect before starting heavy work
	if checkClientDisconnected(ctx) {
		return // Client cancelled, abort silently
	}

	// Step 1: Fetch repository
	frame := 0
	sb.WriteProgressf("%s [git.vet] Fetching from %s...", SpinnerFrames[frame%len(SpinnerFrames)], parsed.Host)

	// Use full path as cache key, and construct proper clone URL
	cloneURL := parsed.GetCloneURL()
	cloneStart := time.Now()
	repo, err := h.cache.FetchRepo(ctx, parsed.FullPath, cloneURL, func(progress string) {
		// Check for disconnect during fetch
		if checkClientDisconnected(ctx) {
			return
		}
		frame++
		// Don't show individual progress messages - keep output clean
	})
	cloneDuration := time.Since(cloneStart)

	// Check if cancelled during fetch
	if checkClientDisconnected(ctx) {
		// Clean up partial clone if needed
		return
	}

	if err != nil {
		if h.metrics != nil {
			h.metrics.CloneErrors.Add(1)
		}
		h.writeFetchError(sb, report, parsed, err, boxWidth)
		return
	}

	// Record clone time on success
	if h.metrics != nil {
		h.metrics.RecordCloneTime(cloneDuration)
	}

	sb.WriteProgressf("%s [git.vet] Repository fetched", IconSuccess)

	// Always delete the repo after scanning (success or failure)
	// This ensures we don't accumulate repos on disk
	defer func() {
		if repo != nil && repo.LocalPath != "" {
			h.cache.DeleteRepo(repo.LocalPath)
		}
	}()

	// Step 2: Check for cached scan (unless skipCache is set)
	if !skipCache {
		cachedScan, err := h.db.GetScanByRepoAndCommit(repo.ID, repo.LastCommitSHA)
		if err == nil && cachedScan != nil {
			if h.metrics != nil {
				h.metrics.CacheHits.Add(1)
			}
			sb.WriteProgressf("%s [git.vet] Using cached scan results", IconSuccess)
			h.writeScanReport(sb, report, parsed, repo, cachedScan, boxWidth, true)
			return
		}
		// Cache miss - record it
		if h.metrics != nil {
			h.metrics.CacheMisses.Add(1)
		}
	} else {
		sb.WriteProgressf("%s [git.vet] Cache bypass enabled - forcing fresh scan", IconSuccess)
	}

	// Check for client disconnect before scanning
	if checkClientDisconnected(ctx) {
		return
	}

	// Step 3: Run scan
	sb.WriteProgressf("%s [git.vet] Scanning for vulnerabilities...", SpinnerFrames[frame%len(SpinnerFrames)])

	scanStart := time.Now()
	scanResult, err := h.scanner.Scan(ctx, repo.LocalPath, func(progress scanner.Progress) {
		// Check for disconnect during scan
		if checkClientDisconnected(ctx) {
			return
		}
		frame++
		sb.WriteProgressf("%s [git.vet] Scanning for vulnerabilities...", SpinnerFrames[frame%len(SpinnerFrames)])
	})
	scanDuration := time.Since(scanStart)

	// Check if cancelled during scan
	if checkClientDisconnected(ctx) {
		return
	}

	if err != nil {
		if h.metrics != nil {
			h.metrics.ScanErrors.Add(1)
		}
		sb.WriteEmptyLine()
		report.WriteBoxTop(boxWidth)
		report.WriteBoxLine(sb.Color(Red, "ERROR: Scan failed"), boxWidth)
		report.WriteBoxLine(err.Error(), boxWidth)
		report.WriteBoxBottom(boxWidth)
		sb.WriteEmptyLine()
		return
	}

	// Record scan time on success
	if h.metrics != nil {
		h.metrics.RecordScanTime(scanDuration)
	}

	sb.WriteProgressf("%s [git.vet] Scan complete!", IconSuccess)

	// Step 4: Save scan results
	dbScan := &db.Scan{
		RepoID:         repo.ID,
		CommitSHA:      repo.LastCommitSHA,
		ResultsJSON:    scanResult.FindingsJSON,
		CriticalCount:  scanResult.CriticalCount,
		HighCount:      scanResult.HighCount,
		MediumCount:    scanResult.MediumCount,
		LowCount:       scanResult.LowCount,
		InfoCount:      scanResult.InfoCount,
		SecurityScore:  scanResult.SecurityScore,
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
	report.WriteBoxLine(sb.Bold("GIT.VET SECURITY REPORT"), width)
	report.WriteBoxLine(fmt.Sprintf("Repository: %s", parsed.FullPath), width)
	report.WriteBoxLine(fmt.Sprintf("Commit: %s", truncate(scan.CommitSHA, 12)), width)
	if repo.License != "" {
		report.WriteBoxLine(fmt.Sprintf("License: %s", repo.License), width)
	}
	report.WriteBoxLine(fmt.Sprintf("Scanned: %d files in %.1fs", scan.FilesScanned, float64(scan.ScanDurationMS)/1000), width)
	if cacheHit {
		report.WriteBoxLine(sb.Color(Cyan, "(cached result)"), width)
	}

	// Security Score
	report.WriteBoxMiddle(width)
	grade := scanner.ScoreGrade(scan.SecurityScore)
	var scoreColor string
	switch {
	case scan.SecurityScore >= 90:
		scoreColor = Green
	case scan.SecurityScore >= 70:
		scoreColor = Yellow
	case scan.SecurityScore >= 50:
		scoreColor = Yellow
	default:
		scoreColor = Red
	}
	scoreLine := fmt.Sprintf("Security Score: %s  %s",
		sb.Color(scoreColor, fmt.Sprintf("%d/100", scan.SecurityScore)),
		sb.Color(scoreColor, fmt.Sprintf("(%s)", grade)))
	report.WriteBoxLine(scoreLine, width)

	// Summary line
	report.WriteBoxMiddle(width)
	summaryLine := fmt.Sprintf("%s %d Critical   %s %d High   %s %d Medium   %s %d Low",
		sb.Color(Red, IconCritical), scan.CriticalCount,
		sb.Color(Yellow, IconHigh), scan.HighCount,
		sb.Color(Blue, IconMedium), scan.MediumCount,
		IconLow, scan.LowCount,
	)
	report.WriteBoxLine(summaryLine, width)

	// Show findings if any (from low to high priority so terminal scrolls to most important)
	totalFindings := scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount
	if totalFindings > 0 && scan.ResultsJSON != "" {
		report.WriteBoxMiddle(width)
		report.WriteBoxLine(sb.Bold("FINDINGS:"), width)
		report.WriteBoxLine("", width)

		// Parse findings from ResultsJSON
		var findings []scanner.Finding
		if err := json.Unmarshal([]byte(scan.ResultsJSON), &findings); err == nil {
			// Sort by severity (Low -> Medium -> High -> Critical for terminal scroll)
			sortedFindings := sortFindingsBySeverity(findings)

			// Show all findings
			for i, f := range sortedFindings {
				severityIcon := getSeverityIcon(sb, f.Severity)
				// Truncate message if too long
				msg := f.Message
				if len(msg) > 50 {
					msg = msg[:47] + "..."
				}
				report.WriteBoxLine(fmt.Sprintf("%s %s", severityIcon, f.RuleID), width)
				report.WriteBoxLine(fmt.Sprintf("  %s:%d", f.Path, f.StartLine), width)
				report.WriteBoxLine(fmt.Sprintf("  %s", msg), width)
				if i < len(sortedFindings)-1 {
					report.WriteBoxLine("", width)
				}
			}
		}
	}

	// Report URL section
	report.WriteBoxMiddle(width)
	reportURL := fmt.Sprintf("https://git.vet/r/%s", truncate(scan.CommitSHA, 8))
	report.WriteBoxLine(fmt.Sprintf("Full report: %s", reportURL), width)
	report.WriteBoxLine("", width)

	// QR Code - generate a real, scannable QR code linking to the report
	qrLines := GenerateScaledQR(reportURL)
	for _, line := range qrLines {
		report.WriteBoxLineCentered(line, width)
	}
	report.WriteBoxLineCentered("^ Scan QR to view full report ^", width)

	// Clone URL
	report.WriteBoxMiddle(width)
	cloneURL := fmt.Sprintf("https://%s/%s/%s", parsed.Host, parsed.Owner, parsed.Repo)
	report.WriteBoxLine(fmt.Sprintf("To clone: git clone %s", cloneURL), width)

	// Contact email
	report.WriteBoxMiddle(width)
	report.WriteBoxLine(fmt.Sprintf("Questions? %s", sb.Color(Cyan, "gitvet@steele.red")), width)
	report.WriteBoxBottom(width)

	sb.WriteEmptyLine()
}

// getSeverityIcon returns the colored icon for a severity level
func getSeverityIcon(sb *SidebandWriter, severity string) string {
	switch strings.ToLower(severity) {
	case "critical", "error":
		return sb.Color(Red, IconCritical)
	case "high", "warning":
		return sb.Color(Yellow, IconHigh)
	case "medium":
		return sb.Color(Blue, IconMedium)
	case "low", "info":
		return IconLow
	default:
		return IconInfo
	}
}

// sortFindingsBySeverity sorts findings from low to high priority
// so terminal scrolls up to most important findings at the end
func sortFindingsBySeverity(findings []scanner.Finding) []scanner.Finding {
	// Create a copy to avoid modifying original
	sorted := make([]scanner.Finding, len(findings))
	copy(sorted, findings)

	// Sort by severity priority (low first, critical last)
	severityOrder := map[string]int{
		"info": 0, "low": 1, "medium": 2, "high": 3, "warning": 3, "critical": 4, "error": 4,
	}

	for i := 0; i < len(sorted)-1; i++ {
		for j := i + 1; j < len(sorted); j++ {
			iPriority := severityOrder[strings.ToLower(sorted[i].Severity)]
			jPriority := severityOrder[strings.ToLower(sorted[j].Severity)]
			if iPriority > jPriority {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	return sorted
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

// writeFetchError writes a user-friendly error message based on the error type
func (h *Handler) writeFetchError(sb *SidebandWriter, report *ReportWriter, parsed *ParsedPath, err error, boxWidth int) {
	sb.WriteEmptyLine()
	report.WriteBoxTop(boxWidth)

	// Check for specific error types from cache package
	var repoErr *cache.RepoError
	if errors.As(err, &repoErr) {
		switch {
		case errors.Is(repoErr.Type, cache.ErrRepoNotFound):
			report.WriteBoxLine(sb.Color(Red, "REPOSITORY NOT FOUND"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("The repository could not be found. Please check:", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("  - The repository URL is spelled correctly", boxWidth)
			report.WriteBoxLine("  - The repository exists on "+parsed.Host, boxWidth)
			report.WriteBoxLine("  - The repository is public (not private)", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine(sb.Color(Cyan, "Example usage:"), boxWidth)
			report.WriteBoxLine("  git clone https://git.vet/github.com/owner/repo", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrRepoPrivate):
			report.WriteBoxLine(sb.Color(Red, "PRIVATE REPOSITORY"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("This repository requires authentication.", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("git.vet can only scan public repositories.", boxWidth)
			report.WriteBoxLine("For private repository scanning, consider:", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("  - Running opengrep locally on your machine", boxWidth)
			report.WriteBoxLine("  - Using GitHub's built-in code scanning", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrNetworkError):
			report.WriteBoxLine(sb.Color(Red, "CONNECTION ERROR"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("Could not connect to "+parsed.Host+".", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("This could be due to:", boxWidth)
			report.WriteBoxLine("  - Network connectivity issues", boxWidth)
			report.WriteBoxLine("  - The host being temporarily unavailable", boxWidth)
			report.WriteBoxLine("  - DNS resolution problems", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("Please verify the URL and try again.", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrInvalidURL):
			report.WriteBoxLine(sb.Color(Red, "INVALID URL"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("The repository URL format is invalid.", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine(sb.Color(Cyan, "Correct format:"), boxWidth)
			report.WriteBoxLine("  git clone https://git.vet/<host>/<owner>/<repo>", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine(sb.Color(Cyan, "Examples:"), boxWidth)
			report.WriteBoxLine("  git clone https://git.vet/github.com/torvalds/linux", boxWidth)
			report.WriteBoxLine("  git clone https://git.vet/gitlab.com/inkscape/inkscape", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrCloneTimeout):
			report.WriteBoxLine(sb.Color(Red, "CLONE TIMEOUT"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("The repository took too long to clone.", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("This can happen with:", boxWidth)
			report.WriteBoxLine("  - Very large repositories", boxWidth)
			report.WriteBoxLine("  - Slow network connections", boxWidth)
			report.WriteBoxLine("  - Overloaded git servers", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("Please try again later.", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrRepoTooLarge):
			report.WriteBoxLine(sb.Color(Red, "REPOSITORY TOO LARGE"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("This repository exceeds the size limit.", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("For large repositories, consider running opengrep", boxWidth)
			report.WriteBoxLine("locally on your machine instead.", boxWidth)

		case errors.Is(repoErr.Type, cache.ErrRateLimited):
			report.WriteBoxLine(sb.Color(Yellow, "RATE LIMITED"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine("The git host is rate limiting requests.", boxWidth)
			report.WriteBoxLine("", boxWidth)
			report.WriteBoxLine("Please wait a few minutes and try again.", boxWidth)

		default:
			// Unknown RepoError type
			report.WriteBoxLine(sb.Color(Red, "FETCH ERROR"), boxWidth)
			report.WriteBoxMiddle(boxWidth)
			report.WriteBoxLine(repoErr.Message, boxWidth)
		}
	} else {
		// Generic error (not a RepoError)
		report.WriteBoxLine(sb.Color(Red, "ERROR"), boxWidth)
		report.WriteBoxMiddle(boxWidth)
		report.WriteBoxLine("Failed to fetch repository:", boxWidth)
		report.WriteBoxLine("", boxWidth)
		// Truncate long error messages
		errMsg := err.Error()
		if len(errMsg) > 60 {
			errMsg = errMsg[:57] + "..."
		}
		report.WriteBoxLine(errMsg, boxWidth)
	}

	report.WriteBoxMiddle(boxWidth)
	report.WriteBoxLine(sb.Color(Cyan, "Questions? gitvet@steele.red"), boxWidth)
	report.WriteBoxBottom(boxWidth)
	sb.WriteEmptyLine()
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
