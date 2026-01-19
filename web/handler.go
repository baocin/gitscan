package web

import (
	"embed"
	"encoding/json"
	"html/template"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/githttp"
	"github.com/baocin/gitscan/internal/scanner"
)

//go:embed templates/*
var templatesFS embed.FS

//go:embed static/*
var staticFS embed.FS

// Handler serves web pages (marketing, pricing, reports)
type Handler struct {
	templates    *template.Template
	staticServer http.Handler
	db           *db.DB
}

// NewHandler creates a new web handler
func NewHandler(database *db.DB) (*Handler, error) {
	funcMap := template.FuncMap{
		"lower": strings.ToLower,
	}
	tmpl, err := template.New("").Funcs(funcMap).ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}

	// Create static file server
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}

	return &Handler{
		templates:    tmpl,
		staticServer: http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))),
		db:           database,
	}, nil
}

// ServeStatic serves static files (favicon, css, js, etc.)
func (h *Handler) ServeStatic(w http.ResponseWriter, r *http.Request) {
	h.staticServer.ServeHTTP(w, r)
}

// ServeHome serves the marketing homepage
func (h *Handler) ServeHome(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "index.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ServePricing serves the pricing page
func (h *Handler) ServePricing(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "pricing.html", nil); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// ReportData holds data for the report template
type ReportData struct {
	ReportID      string
	Found         bool
	RepoURL       string
	RepoName      string
	CommitSHA     string
	ShortCommit   string
	ScannedAt     string
	FilesScanned  int
	ScanDuration  string
	License       string
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	SecurityScore int    // 0-100 weighted security score
	SecurityGrade string // A, B, C, D, F
	TotalFindings int
	Findings      []scanner.Finding
}

// RepoReportsData holds data for the repository reports list template
type RepoReportsData struct {
	RepoURL  string
	RepoName string
	Found    bool
	Scans    []ScanSummary
}

// ScanSummary is a condensed scan view for listing pages
type ScanSummary struct {
	CommitSHA     string
	ShortCommit   string
	ScannedAt     string
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	SecurityScore int
	SecurityGrade string
	TotalFindings int
}

// ServeReport serves a scan report page
func (h *Handler) ServeReport(w http.ResponseWriter, r *http.Request) {
	// Extract report ID from path: /r/{id}
	reportID := strings.TrimPrefix(r.URL.Path, "/r/")
	if reportID == "" {
		http.Error(w, "Report ID required", http.StatusBadRequest)
		return
	}

	data := ReportData{
		ReportID: reportID,
		Found:    false,
	}

	// Look up the scan by commit prefix
	if h.db != nil {
		scan, err := h.db.GetScanByCommitPrefix(reportID)
		if err == nil && scan != nil {
			data.Found = true
			data.RepoURL = scan.RepoURL
			data.RepoName = strings.TrimPrefix(scan.RepoURL, "https://")
			data.CommitSHA = scan.CommitSHA
			data.ShortCommit = scan.CommitSHA
			if len(scan.CommitSHA) > 12 {
				data.ShortCommit = scan.CommitSHA[:12]
			}
			data.ScannedAt = scan.CreatedAt.Format(time.RFC1123)
			data.FilesScanned = scan.FilesScanned
			data.ScanDuration = formatDuration(time.Duration(scan.ScanDurationMS) * time.Millisecond)
			data.License = scan.License
			data.CriticalCount = scan.CriticalCount
			data.HighCount = scan.HighCount
			data.MediumCount = scan.MediumCount
			data.LowCount = scan.LowCount
			data.InfoCount = scan.InfoCount
			data.SecurityScore = scan.SecurityScore
			data.SecurityGrade = scanner.ScoreGrade(scan.SecurityScore)
			data.TotalFindings = scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount

			// Parse findings from results_json
			if scan.ResultsJSON != "" {
				var findings []scanner.Finding
				if err := json.Unmarshal([]byte(scan.ResultsJSON), &findings); err == nil {
					// Sort findings by severity (Critical -> High -> Medium -> Low, worst first)
					data.Findings = githttp.SortFindingsBySeverity(findings)
				}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "report.html", data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return d.Round(time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// ServeRepoReports serves a list of all scans for a repository or redirects to latest
func (h *Handler) ServeRepoReports(w http.ResponseWriter, r *http.Request) {
	// Extract repo URL from path: /reports/{host}/{owner}/{repo}[/latest]
	path := strings.TrimPrefix(r.URL.Path, "/reports/")
	if path == "" {
		http.Error(w, "Repository path required", http.StatusBadRequest)
		return
	}

	// Check if this is a /latest request
	if strings.HasSuffix(path, "/latest") {
		repoURL := strings.TrimSuffix(path, "/latest")
		h.serveLatestReport(w, r, repoURL)
		return
	}

	// Otherwise, list all scans for this repo
	repoURL := path

	data := RepoReportsData{
		RepoURL:  repoURL,
		RepoName: repoURL,
		Found:    false,
	}

	// Look up scans for this repo
	if h.db != nil {
		scans, err := h.db.GetScansByRepo(repoURL, 50)
		if err == nil && len(scans) > 0 {
			data.Found = true
			data.Scans = make([]ScanSummary, len(scans))

			for i, scan := range scans {
				shortCommit := scan.CommitSHA
				if len(scan.CommitSHA) > 12 {
					shortCommit = scan.CommitSHA[:12]
				}

				data.Scans[i] = ScanSummary{
					CommitSHA:     scan.CommitSHA,
					ShortCommit:   shortCommit,
					ScannedAt:     scan.CreatedAt.Format(time.RFC1123),
					CriticalCount: scan.CriticalCount,
					HighCount:     scan.HighCount,
					MediumCount:   scan.MediumCount,
					LowCount:      scan.LowCount,
					SecurityScore: scan.SecurityScore,
					SecurityGrade: scanner.ScoreGrade(scan.SecurityScore),
					TotalFindings: scan.CriticalCount + scan.HighCount + scan.MediumCount + scan.LowCount,
				}
			}
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "repo_reports.html", data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// serveLatestReport redirects to the latest scan report for a repository
func (h *Handler) serveLatestReport(w http.ResponseWriter, r *http.Request, repoURL string) {
	if h.db == nil {
		http.Error(w, "Database not available", http.StatusInternalServerError)
		return
	}

	scan, err := h.db.GetLatestScanByRepo(repoURL)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if scan == nil {
		// Redirect to listing page which shows styled "no scans" message
		http.Redirect(w, r, "/reports/"+repoURL, http.StatusFound)
		return
	}

	// Redirect to the commit-based report URL
	shortCommit := scan.CommitSHA
	if len(scan.CommitSHA) > 8 {
		shortCommit = scan.CommitSHA[:8]
	}

	http.Redirect(w, r, "/r/"+shortCommit, http.StatusFound)
}
