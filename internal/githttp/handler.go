package githttp

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/baocin/gitscan/internal/cache"
	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/ratelimit"
	"github.com/baocin/gitscan/internal/scanner"
)

// Handler handles git HTTP protocol requests
type Handler struct {
	db        *db.DB
	cache     *cache.RepoCache
	scanner   *scanner.Scanner
	limiter   *ratelimit.Limiter
	useColors bool
}

// NewHandler creates a new git HTTP handler
func NewHandler(database *db.DB, repoCache *cache.RepoCache, scan *scanner.Scanner, limiter *ratelimit.Limiter) *Handler {
	return &Handler{
		db:        database,
		cache:     repoCache,
		scanner:   scan,
		limiter:   limiter,
		useColors: true, // Default to colors
	}
}

// ServeHTTP implements http.Handler
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	ctx := r.Context()

	// Get client IP
	clientIP := getClientIP(r)

	// Parse the request path
	mode, repoPath, err := ParseRepoPath(r.URL.Path)
	if err != nil {
		http.Error(w, "Invalid repository path", http.StatusBadRequest)
		return
	}

	// Check rate limit
	if allowed, msg := h.limiter.Allow(clientIP, repoPath); !allowed {
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
		h.handleInfoRefs(ctx, w, r, mode, repoPath, clientIP, startTime)
	case strings.Contains(r.URL.Path, "/git-upload-pack"):
		h.handleUploadPack(ctx, w, r, mode, repoPath, clientIP, startTime)
	default:
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

// handleInfoRefs handles the initial discovery request
func (h *Handler) handleInfoRefs(ctx context.Context, w http.ResponseWriter, r *http.Request, mode, repoPath, clientIP string, startTime time.Time) {
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
func (h *Handler) handleUploadPack(ctx context.Context, w http.ResponseWriter, r *http.Request, mode, repoPath, clientIP string, startTime time.Time) {
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
	useColors := mode != "plain"
	sb := NewSidebandWriter(w, useColors)

	// Start the scan process
	h.performScan(ctx, sb, mode, repoPath, clientIP, startTime)

	// End the connection (intentionally fail the clone for scan-only mode)
	sb.Flush()
}

// performScan fetches the repo, scans it, and writes results via sideband
func (h *Handler) performScan(ctx context.Context, sb *SidebandWriter, mode, repoPath, clientIP string, startTime time.Time) {
	report := NewReportWriter(sb)
	boxWidth := 66

	sb.WriteEmptyLine()

	// Step 1: Fetch repository
	frame := 0
	sb.WriteProgressf("%s [gitscan] Fetching repository...", SpinnerFrames[frame%len(SpinnerFrames)])

	repo, err := h.cache.FetchRepo(ctx, repoPath, func(progress string) {
		frame++
		sb.WriteProgressf("%s [gitscan] %s", SpinnerFrames[frame%len(SpinnerFrames)], progress)
	})
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
		h.writeScanReport(sb, report, repoPath, repo, cachedScan, boxWidth, true)
		return
	}

	// Step 3: Run scan
	sb.WriteProgressf("%s [gitscan] Scanning with opengrep...", SpinnerFrames[frame%len(SpinnerFrames)])

	scanResult, err := h.scanner.Scan(ctx, repo.LocalPath, func(progress scanner.Progress) {
		frame++
		sb.WriteProgressf("%s [gitscan] Scanning: %d/%d files (%d%%)",
			SpinnerFrames[frame%len(SpinnerFrames)],
			progress.FilesScanned, progress.FilesTotal, progress.Percent)
	})
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
	h.writeScanReport(sb, report, repoPath, repo, dbScan, boxWidth, false)

	// Log request
	responseTime := time.Since(startTime)
	h.db.LogRequest(&db.Request{
		IP:             clientIP,
		RepoURL:        repoPath,
		CommitSHA:      repo.LastCommitSHA,
		RequestMode:    mode,
		ScanID:         &dbScan.ID,
		CacheHit:       false,
		ResponseTimeMS: responseTime.Milliseconds(),
	})
}

// writeScanReport writes the formatted scan report via sideband
func (h *Handler) writeScanReport(sb *SidebandWriter, report *ReportWriter, repoPath string, repo *cache.CachedRepo, scan *db.Scan, width int, cacheHit bool) {
	sb.WriteEmptyLine()

	// Header
	report.WriteBoxTop(width)
	report.WriteBoxLine(sb.Bold("GITSCAN SECURITY REPORT"), width)
	report.WriteBoxLine(fmt.Sprintf("Repository: %s", repoPath), width)
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
	report.WriteBoxLine(fmt.Sprintf("To clone: git clone https://github.com/%s", repoPath), width)
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
