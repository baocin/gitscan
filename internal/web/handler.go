package web

import (
	"embed"
	"html/template"
	"net/http"
	"strings"
)

//go:embed templates/*
var templatesFS embed.FS

// Handler serves web pages (marketing, pricing, reports)
type Handler struct {
	templates *template.Template
}

// NewHandler creates a new web handler
func NewHandler() (*Handler, error) {
	tmpl, err := template.ParseFS(templatesFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Handler{templates: tmpl}, nil
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

// ServeReport serves a scan report page
func (h *Handler) ServeReport(w http.ResponseWriter, r *http.Request) {
	// Extract report ID from path: /r/{id}
	reportID := strings.TrimPrefix(r.URL.Path, "/r/")
	if reportID == "" {
		http.Error(w, "Report ID required", http.StatusBadRequest)
		return
	}

	data := map[string]string{
		"ReportID": reportID,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.templates.ExecuteTemplate(w, "report.html", data); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
