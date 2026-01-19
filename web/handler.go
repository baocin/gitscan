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

// HomeData holds data for the homepage template
type HomeData struct {
	RecentScans []db.RecentScan
}

// ServeHome serves the marketing homepage
func (h *Handler) ServeHome(w http.ResponseWriter, r *http.Request) {
	data := HomeData{}

	// Get recent public scans
	if h.db != nil {
		scans, err := h.db.GetRecentPublicScans(6)
		if err == nil {
			data.RecentScans = scans
		}
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "index.html", data); err != nil {
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
