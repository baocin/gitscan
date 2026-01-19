package githttp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

		// Log failed request
		h.db.LogRequest(&db.Request{
			IP:             clientIP,
			UserAgent:      r.Header.Get("User-Agent"),
			Referer:        r.Header.Get("Referer"),
			GitVersion:     parseGitVersion(r.Header.Get("User-Agent")),
			RepoURL:        parsed.FullPath,
			RequestMode:    parsed.Mode,
			RequestType:    "info_refs",
			HTTPMethod:     r.Method,
			Success:        false,
			ResponseTimeMS: time.Since(startTime).Milliseconds(),
			QueryParams:    serializeQueryParams(r),
			Error:          "Only git-upload-pack is supported",
		})
		return
	}

	// Set headers for git smart HTTP
	w.Header().Set("Content-Type", fmt.Sprintf("application/x-%s-advertisement", service))
	w.Header().Set("Cache-Control", "no-cache")

	// Write service announcement
	pkt := NewPktLineWriter(w)
	pkt.WriteString(fmt.Sprintf("# service=%s\n", service))
	pkt.WriteFlush()

	// For gitscan, we need to advertise a real commit OID to prevent
	// "bad object" errors. Fetch the repo to get the actual HEAD commit.
	cloneURL := fmt.Sprintf("https://%s.git", parsed.FullPath)

	// Quick fetch to get commit SHA (uses cache if available)
	repo, err := h.cache.FetchRepo(ctx, parsed.FullPath, cloneURL, nil)

	var headOID string
	if err != nil || repo == nil {
		// Fallback to a valid-looking SHA if fetch fails
		// This prevents protocol errors while still allowing the scan to proceed
		headOID = "4b825dc642cb6eb9a060e54bf8d69288fbee4904" // Empty tree SHA
	} else {
		headOID = repo.LastCommitSHA
	}

	// Write ref advertisement with capabilities
	caps := "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed symref=HEAD:refs/heads/main agent=git.vet/1.0"
	pkt.WriteString(fmt.Sprintf("%s HEAD\x00%s\n", headOID, caps))
	pkt.WriteString(fmt.Sprintf("%s refs/heads/main\n", headOID))
	pkt.WriteFlush()

	// Log info/refs request
	responseTime := time.Since(startTime)
	h.db.LogRequest(&db.Request{
		IP:             clientIP,
		UserAgent:      r.Header.Get("User-Agent"),
		Referer:        r.Header.Get("Referer"),
		GitVersion:     parseGitVersion(r.Header.Get("User-Agent")),
		RepoURL:        parsed.FullPath,
		RequestMode:    parsed.Mode,
		RequestType:    "info_refs",
		HTTPMethod:     r.Method,
		Success:        true,
		ResponseTimeMS: responseTime.Milliseconds(),
		QueryParams:    serializeQueryParams(r),
	})
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
	h.performScan(ctx, sb, r, parsed, clientIP, startTime, isPrivate, skipCache)

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
func (h *Handler) performScan(ctx context.Context, sb *SidebandWriter, r *http.Request, parsed *ParsedPath, clientIP string, startTime time.Time, isPrivate bool, skipCache bool) {
	report := NewReportWriter(sb)
	boxWidth := 80

	// Initialize request log - will be filled in as we progress
	userAgent := r.Header.Get("User-Agent")
	reqLog := &db.Request{
		IP:          clientIP,
		UserAgent:   userAgent,
		Referer:     r.Header.Get("Referer"),
		GitVersion:  parseGitVersion(userAgent),
		RepoURL:     parsed.FullPath,
		RequestMode: parsed.Mode,
		RequestType: "upload_pack",
		HTTPMethod:  r.Method,
		CacheHit:    false,
		QueryParams: serializeQueryParams(r),
	}

	// Ensure we always log the request, even on errors or early returns
	defer func() {
		reqLog.ResponseTimeMS = time.Since(startTime).Milliseconds()
		if err := h.db.LogRequest(reqLog); err != nil {
			// Log error but don't fail the request
		}
	}()

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
			reqLog.Error = "server disk space low"
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
		reqLog.Error = "client disconnected"
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
		reqLog.Error = "client disconnected during fetch"
		// Clean up partial clone if needed
		return
	}

	if err != nil {
		if h.metrics != nil {
			h.metrics.CloneErrors.Add(1)
		}
		reqLog.Error = fmt.Sprintf("fetch error: %v", err)
		log.Printf("Clone failed for %s (from %s) after %v: %v", parsed.FullPath, clientIP, cloneDuration, err)
		h.writeFetchError(sb, report, parsed, err, boxWidth)
		return
	}

	// Record clone time on success
	if h.metrics != nil {
		h.metrics.RecordCloneTime(cloneDuration)
	}

	log.Printf("Clone completed for %s: %d files, commit %s in %v", parsed.FullPath, repo.FileCount, repo.LastCommitSHA[:8], cloneDuration)
	sb.WriteProgressf("%s [git.vet] Repository fetched", IconSuccess)

	// Always delete the repo after scanning (success or failure)
	// This ensures we don't accumulate repos on disk
	defer func() {
		if repo != nil && repo.LocalPath != "" {
			h.cache.DeleteRepo(repo.LocalPath)
		}
	}()

	// Update request log with repo info now that we have it
	reqLog.CommitSHA = repo.LastCommitSHA

	// Step 2: Check for cached scan (unless skipCache is set)
	if !skipCache {
		cachedScan, err := h.db.GetScanByRepoAndCommit(repo.ID, repo.LastCommitSHA)
		if err == nil && cachedScan != nil {
			if h.metrics != nil {
				h.metrics.CacheHits.Add(1)
			}
			reqLog.CacheHit = true
			reqLog.ScanID = &cachedScan.ID
			sb.WriteProgressf("%s [git.vet] Using cached scan results", IconSuccess)

			// Output format based on mode
			if parsed.Mode == "json" {
				h.writeJSONReport(sb, parsed, repo, cachedScan)
			} else {
				h.writeScanReport(sb, report, parsed, repo, cachedScan, boxWidth, true)
			}

			// Log cache hit request
			responseTime := time.Since(startTime)
			userAgent := r.Header.Get("User-Agent")
			h.db.LogRequest(&db.Request{
				IP:             clientIP,
				UserAgent:      userAgent,
				Referer:        r.Header.Get("Referer"),
				GitVersion:     parseGitVersion(userAgent),
				RepoURL:        parsed.FullPath,
				CommitSHA:      repo.LastCommitSHA,
				RequestMode:    parsed.Mode,
				RequestType:    "upload_pack",
				HTTPMethod:     r.Method,
				ScanID:         &cachedScan.ID,
				CacheHit:       true,
				Success:        true,
				ResponseTimeMS: responseTime.Milliseconds(),
				QueryParams:    serializeQueryParams(r),
			})
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
		reqLog.Error = "client disconnected before scan"
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
		reqLog.Error = "client disconnected during scan"
		return
	}

	// Check for partial results (scan timeout but with recoverable data)
	if scanResult != nil && scanResult.IsPartial {
		// We have partial results - show warning but continue to display them
		if h.metrics != nil {
			h.metrics.ScanErrors.Add(1) // Still count as error for metrics
		}
		log.Printf("Scan partial for %s: %s, recovered %d findings in %v", parsed.FullPath, scanResult.PartialReason, len(scanResult.Findings), scanDuration)
		sb.WriteEmptyLine()
		report.WriteBoxTop(boxWidth)
		report.WriteBoxLine(sb.Color(Yellow, "⚠  WARNING: PARTIAL RESULTS"), boxWidth)
		report.WriteBoxLine(fmt.Sprintf("Scan %s", scanResult.PartialReason), boxWidth)
		report.WriteBoxLine(fmt.Sprintf("Showing findings from scanned files"), boxWidth)
		report.WriteBoxBottom(boxWidth)
		sb.WriteEmptyLine()
		// Continue to display partial results below
	} else if err != nil {
		// Complete failure with no results
		if h.metrics != nil {
			h.metrics.ScanErrors.Add(1)
		}
		reqLog.Error = fmt.Sprintf("scan error: %v", err)
		log.Printf("Scan failed for %s after %v: %v", parsed.FullPath, scanDuration, err)
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

	log.Printf("Scan completed for %s: %d findings (%d critical, %d high, %d medium, %d low) in %v",
		parsed.FullPath, len(scanResult.Findings),
		scanResult.CriticalCount, scanResult.HighCount,
		scanResult.MediumCount, scanResult.LowCount, scanDuration)
	sb.WriteProgressf("%s [git.vet] Scan complete!", IconSuccess)

	// Step 4: Save scan results
	dbScan := &db.Scan{
		RepoID:           repo.ID,
		CommitSHA:        repo.LastCommitSHA,
		ResultsJSON:      scanResult.FindingsJSON,
		CriticalCount:    scanResult.CriticalCount,
		HighCount:        scanResult.HighCount,
		MediumCount:      scanResult.MediumCount,
		LowCount:         scanResult.LowCount,
		InfoCount:        scanResult.InfoCount,
		SecurityScore:    scanResult.SecurityScore,
		FilesScanned:     scanResult.FilesScanned,
		ScanDurationMS:   scanResult.Duration.Milliseconds(),
		ScanLevel:        string(scanResult.ScanLevel),
		CachedFileCount:  scanResult.CachedFileCount,
		ScannedFileCount: scanResult.ScannedFileCount,
		IsPartial:        scanResult.IsPartial,
		PartialReason:    scanResult.PartialReason,
	}
	h.db.CreateScan(dbScan)

	// Update request log with successful scan ID
	reqLog.ScanID = &dbScan.ID
	reqLog.Success = true

	// Step 5: Write report
	// Output format based on mode
	if parsed.Mode == "json" {
		h.writeJSONReport(sb, parsed, repo, dbScan)
	} else {
		h.writeScanReport(sb, report, parsed, repo, dbScan, boxWidth, false)
	}
}

// writeScanReport writes the formatted scan report via sideband
func (h *Handler) writeScanReport(sb *SidebandWriter, report *ReportWriter, parsed *ParsedPath, repo *cache.CachedRepo, scan *db.Scan, width int, cacheHit bool) {
	sb.WriteEmptyLine()

	// Show findings first (if any) so they appear before the summary
	totalFindings := scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount
	if totalFindings > 0 && scan.ResultsJSON != "" {
		// Parse findings from ResultsJSON
		var findings []scanner.Finding
		if err := json.Unmarshal([]byte(scan.ResultsJSON), &findings); err == nil {
			// Sort by severity (Critical -> High -> Medium -> Low, worst first)
			sortedFindings := SortFindingsBySeverity(findings)

			// Show findings without box (cleaner look)
			for _, f := range sortedFindings {
				severityIcon := getSeverityIcon(sb, f.Severity)
				severityLabel := strings.ToUpper(f.Severity)
				shortRule := shortenRuleID(f.RuleID)

				// Format: ⚠ HIGH: rule-name
				sb.WriteProgress(fmt.Sprintf("%s %s: %s", severityIcon, severityLabel, shortRule))

				// Show path with line number (indented)
				pathWithLine := fmt.Sprintf("  %s:%d", f.Path, f.StartLine)
				sb.WriteProgress(shortenPath(pathWithLine, width-2))

				// Show message (indented)
				msg := fmt.Sprintf("  %s", f.Message)
				if len(msg) > width-2 {
					msg = msg[:width-5] + "..."
				}
				sb.WriteProgress(msg)
			}
			sb.WriteEmptyLine()
		}
	}

	// Main summary box
	report.WriteBoxTop(width)

	// Security Score - prominent display
	grade := scanner.ScoreGrade(scan.SecurityScore)
	var scoreColor string
	var scoreIcon string
	switch {
	case scan.SecurityScore >= 90:
		scoreColor = Green
		scoreIcon = "✓"
	case scan.SecurityScore >= 70:
		scoreColor = Yellow
		scoreIcon = "⚠"
	case scan.SecurityScore >= 50:
		scoreColor = Yellow
		scoreIcon = "⚠"
	default:
		scoreColor = Red
		scoreIcon = "✗"
	}
	scoreLine := fmt.Sprintf("%s %s: %s",
		sb.Color(scoreColor, scoreIcon),
		sb.Color(scoreColor, "SECURITY SCORE"),
		sb.Color(scoreColor, sb.Bold(fmt.Sprintf("%d/100 (%s)", scan.SecurityScore, grade))))
	report.WriteBoxLine(scoreLine, width)

	// Severity counts on same line
	report.WriteBoxMiddle(width)
	summaryLine := fmt.Sprintf("%s %d Critical    %s %d High    %s %d Medium    %s %d Low",
		sb.Color(Red, IconCritical), scan.CriticalCount,
		sb.Color(Yellow, IconHigh), scan.HighCount,
		sb.Color(Blue, IconMedium), scan.MediumCount,
		IconLow, scan.LowCount,
	)
	report.WriteBoxLine(summaryLine, width)

	// Report URL
	report.WriteBoxMiddle(width)
	reportURL := fmt.Sprintf("https://git.vet/r/%s", truncate(scan.CommitSHA, 8))
	report.WriteBoxLine(fmt.Sprintf("Full report: %s", sb.Color(Cyan, reportURL)), width)

	// Clone command
	cloneURL := fmt.Sprintf("https://%s/%s/%s", parsed.Host, parsed.Owner, parsed.Repo)
	report.WriteBoxLine(fmt.Sprintf("To clone: git clone %s", cloneURL), width)

	// Contact
	report.WriteBoxMiddle(width)
	report.WriteBoxLine(fmt.Sprintf("Questions? %s", sb.Color(Cyan, "gitvet@steele.red")), width)
	report.WriteBoxBottom(width)

	sb.WriteEmptyLine()
}

// writeJSONReport outputs scan results as JSON
func (h *Handler) writeJSONReport(sb *SidebandWriter, parsed *ParsedPath, repo *cache.CachedRepo, scan *db.Scan) {
	// Create JSON output structure
	type JSONOutput struct {
		Repository      string `json:"repository"`
		CommitSHA       string `json:"commit_sha"`
		License         string `json:"license,omitempty"`
		SecurityScore   int    `json:"security_score"`
		Grade           string `json:"grade"`
		CriticalCount   int    `json:"critical_count"`
		HighCount       int    `json:"high_count"`
		MediumCount     int    `json:"medium_count"`
		LowCount        int    `json:"low_count"`
		InfoCount       int    `json:"info_count"`
		FilesScanned    int    `json:"files_scanned"`
		ScanDurationMS  int64  `json:"scan_duration_ms"`
		ScanLevel       string `json:"scan_level,omitempty"`
		IsPartial       bool   `json:"is_partial,omitempty"`
		PartialReason   string `json:"partial_reason,omitempty"`
		Findings        json.RawMessage `json:"findings"`
		ReportURL       string `json:"report_url"`
	}

	// Prepare findings JSON
	var findingsJSON json.RawMessage
	if scan.ResultsJSON != "" {
		findingsJSON = json.RawMessage(scan.ResultsJSON)
	} else {
		findingsJSON = json.RawMessage("[]")
	}

	// Build output
	output := JSONOutput{
		Repository:     parsed.FullPath,
		CommitSHA:      scan.CommitSHA,
		License:        repo.License,
		SecurityScore:  scan.SecurityScore,
		Grade:          scanner.ScoreGrade(scan.SecurityScore),
		CriticalCount:  scan.CriticalCount,
		HighCount:      scan.HighCount,
		MediumCount:    scan.MediumCount,
		LowCount:       scan.LowCount,
		InfoCount:      scan.InfoCount,
		FilesScanned:   scan.FilesScanned,
		ScanDurationMS: scan.ScanDurationMS,
		ScanLevel:      scan.ScanLevel,
		IsPartial:      scan.IsPartial,
		PartialReason:  scan.PartialReason,
		Findings:       findingsJSON,
		ReportURL:      fmt.Sprintf("https://git.vet/r/%s", truncate(scan.CommitSHA, 8)),
	}

	// Marshal to JSON
	jsonBytes, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		sb.WriteError(fmt.Sprintf("Failed to generate JSON: %v", err))
		return
	}

	// Write JSON output
	sb.WriteEmptyLine()
	sb.WriteProgress(string(jsonBytes))
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

// SortFindingsBySeverity sorts findings from high to low priority
// so most critical issues are displayed first
func SortFindingsBySeverity(findings []scanner.Finding) []scanner.Finding {
	// Create a copy to avoid modifying original
	sorted := make([]scanner.Finding, len(findings))
	copy(sorted, findings)

	// Sort by severity priority (critical first, info last)
	severityOrder := map[string]int{
		"critical": 0, "error": 0, "high": 1, "warning": 1, "medium": 2, "low": 3, "info": 4,
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

// shortenRuleID extracts the last meaningful segment from a rule ID
// e.g., "javascript.browser.security.insecure-document-method.insecure-document-method" -> "insecure-document-method"
func shortenRuleID(ruleID string) string {
	parts := strings.Split(ruleID, ".")
	if len(parts) == 0 {
		return ruleID
	}
	// Return the last part, which is usually the most descriptive
	return parts[len(parts)-1]
}

// shortenPath intelligently truncates a file path to show filename and line number
// e.g., "src/main/resources/.../file.js:123" -> "file.js:123" or truncates middle
func shortenPath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}

	// Try to preserve filename and line number
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		// No slashes, just truncate
		if len(path) > maxLen {
			return "..." + path[len(path)-maxLen+3:]
		}
		return path
	}

	filename := path[lastSlash+1:]
	if len(filename) < maxLen-3 {
		// Filename fits, show it with "..." prefix
		return "..." + filename
	}

	// Filename itself is too long, truncate it
	if len(filename) > maxLen {
		return filename[:maxLen-3] + "..."
	}
	return filename
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

// parseGitVersion extracts git version from User-Agent header
// Examples:
//   "git/2.39.0" -> "2.39.0"
//   "git/2.39.0 (Apple Git-152)" -> "2.39.0"
//   "libgit2/1.5.0" -> "1.5.0"
//   "go-git/v5.4.2" -> "5.4.2"
func parseGitVersion(userAgent string) string {
	if userAgent == "" {
		return ""
	}

	// Try to match common patterns
	patterns := []string{
		"git/",
		"libgit2/",
		"go-git/v",
		"jgit/",
	}

	for _, pattern := range patterns {
		if idx := strings.Index(userAgent, pattern); idx >= 0 {
			start := idx + len(pattern)
			version := userAgent[start:]

			// Extract until space or end
			if spaceIdx := strings.Index(version, " "); spaceIdx > 0 {
				version = version[:spaceIdx]
			}

			return version
		}
	}

	return ""
}

// serializeQueryParams converts URL query parameters to JSON string
func serializeQueryParams(r *http.Request) string {
	if len(r.URL.Query()) == 0 {
		return ""
	}

	params := make(map[string]string)
	for key, values := range r.URL.Query() {
		if len(values) > 0 {
			params[key] = values[0] // Take first value
		}
	}

	jsonBytes, err := json.Marshal(params)
	if err != nil {
		return ""
	}

	return string(jsonBytes)
}
