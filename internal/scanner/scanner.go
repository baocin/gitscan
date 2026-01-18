package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Scanner wraps opengrep for static analysis
type Scanner struct {
	binaryPath string
	rulesPath  string
	timeout    time.Duration
}

// Config holds scanner configuration
type Config struct {
	BinaryPath string
	RulesPath  string
	Timeout    time.Duration
}

// DefaultConfig returns default scanner configuration
func DefaultConfig() Config {
	return Config{
		BinaryPath: "opengrep", // Assumes opengrep is in PATH
		RulesPath:  "",         // Use default rules
		Timeout:    60 * time.Second,
	}
}

// New creates a new scanner instance
func New(cfg Config) *Scanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 60 * time.Second
	}
	return &Scanner{
		binaryPath: cfg.BinaryPath,
		rulesPath:  cfg.RulesPath,
		timeout:    cfg.Timeout,
	}
}

// IsAvailable checks if the scanner binary is available
func (s *Scanner) IsAvailable() (bool, string) {
	path, err := exec.LookPath(s.binaryPath)
	if err != nil {
		return false, ""
	}
	return true, path
}

// GetBinaryPath returns the configured binary path
func (s *Scanner) GetBinaryPath() string {
	return s.binaryPath
}

// Progress represents scan progress
type Progress struct {
	FilesScanned int
	FilesTotal   int
	Percent      int
}

// ProgressFunc is a callback for progress updates
type ProgressFunc func(Progress)

// Result represents scan results
type Result struct {
	Findings      []Finding
	CriticalCount int
	HighCount     int
	MediumCount   int
	LowCount      int
	InfoCount     int
	FilesScanned  int
	Duration      time.Duration
	FindingsJSON  string // JSON array of Finding structs (not raw SARIF)
	ScannerUsed   string // "opengrep", "semgrep", or "mock"
	SecurityScore int    // 0-100 score based on severity-weighted findings
}

// SecurityScoreWeights defines point deductions per severity level
var SecurityScoreWeights = map[string]int{
	"critical": 25, // -25 points per critical finding
	"high":     15, // -15 points per high finding
	"medium":   5,  // -5 points per medium finding
	"low":      1,  // -1 point per low finding
	"info":     0,  // info findings don't affect score
}

// CalculateSecurityScore computes a 0-100 security score based on findings
// 100 = perfect (no issues), 0 = critical security concerns
func CalculateSecurityScore(critical, high, medium, low int) int {
	score := 100
	score -= critical * SecurityScoreWeights["critical"]
	score -= high * SecurityScoreWeights["high"]
	score -= medium * SecurityScoreWeights["medium"]
	score -= low * SecurityScoreWeights["low"]

	if score < 0 {
		score = 0
	}
	return score
}

// ScoreGrade returns a letter grade for the security score
func ScoreGrade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	default:
		return "F"
	}
}

// Finding represents a single security finding
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Severity    string   `json:"severity"`
	Message     string   `json:"message"`
	Path        string   `json:"path"`
	StartLine   int      `json:"start_line"`
	EndLine     int      `json:"end_line"`
	StartCol    int      `json:"start_col"`
	EndCol      int      `json:"end_col"`
	Snippet     string   `json:"snippet"`
	Category    string   `json:"category"`
	Confidence  string   `json:"confidence"`
	References  []string `json:"references"`
}

// SARIFOutput represents the SARIF output format from opengrep
type SARIFOutput struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name            string `json:"name"`
				SemanticVersion string `json:"semanticVersion"`
				Rules           []struct {
					ID               string `json:"id"`
					Name             string `json:"name"`
					ShortDescription struct {
						Text string `json:"text"`
					} `json:"shortDescription"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
					Properties struct {
						Precision string   `json:"precision"`
						Tags      []string `json:"tags"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID  string `json:"ruleId"`
			Level   string `json:"level"`
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine   int `json:"startLine"`
						EndLine     int `json:"endLine"`
						StartColumn int `json:"startColumn"`
						EndColumn   int `json:"endColumn"`
						Snippet     struct {
							Text string `json:"text"`
						} `json:"snippet"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

// Scan performs a security scan on the given path
func (s *Scanner) Scan(ctx context.Context, repoPath string, progressFn ProgressFunc) (*Result, error) {
	startTime := time.Now()

	// Count files first for progress reporting
	totalFiles, err := countFiles(repoPath)
	if err != nil {
		totalFiles = 0 // Continue even if we can't count
	}

	// Build opengrep command - requires "scan" subcommand
	// Use --sarif for SARIF output format (not --json which is semgrep native format)
	args := []string{
		"scan",
		"--sarif",
	}

	if s.rulesPath != "" {
		args = append(args, "--config", s.rulesPath)
	} else {
		// Use auto config to detect language and apply relevant rules
		args = append(args, "--config", "auto")
	}

	args = append(args, repoPath)

	// Create context with timeout
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	// Set QT_QPA_PLATFORM=offscreen to prevent Qt display errors on headless servers
	cmd.Env = append(os.Environ(), "QT_QPA_PLATFORM=offscreen")
	log.Printf("[scanner] Running: %s %s", s.binaryPath, strings.Join(args, " "))

	// Capture stdout for JSON output
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	// Capture stderr for progress
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		// If opengrep is not installed, return an error - don't silently mock
		if strings.Contains(err.Error(), "executable file not found") {
			return nil, fmt.Errorf("opengrep/semgrep not found: %s is not installed or not in PATH", s.binaryPath)
		}
		return nil, fmt.Errorf("failed to start scanner: %w", err)
	}

	// Read stderr for progress updates
	go func() {
		scanner := bufio.NewScanner(stderr)
		scannedFiles := 0
		for scanner.Scan() {
			line := scanner.Text()
			// Parse progress from opengrep stderr output
			if strings.Contains(line, "Scanning") || strings.Contains(line, "scanning") {
				scannedFiles++
				if progressFn != nil && totalFiles > 0 {
					progressFn(Progress{
						FilesScanned: scannedFiles,
						FilesTotal:   totalFiles,
						Percent:      (scannedFiles * 100) / totalFiles,
					})
				}
			}
		}
	}()

	// Read JSON output
	var jsonOutput strings.Builder
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB buffer
	for scanner.Scan() {
		jsonOutput.WriteString(scanner.Text())
	}

	// Wait for command to complete
	err = cmd.Wait()
	if err != nil {
		// opengrep returns non-zero when findings are present, which is expected
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// Exit code 1 means findings were found, not an error
				err = nil
			}
		}
	}

	if err != nil && ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("scan timed out after %v", s.timeout)
	}

	// Parse SARIF output
	log.Printf("[scanner] Raw output length: %d bytes", len(jsonOutput.String()))
	if len(jsonOutput.String()) < 500 {
		log.Printf("[scanner] Raw output: %s", jsonOutput.String())
	} else {
		log.Printf("[scanner] Raw output (first 500 chars): %s", jsonOutput.String()[:500])
	}

	result, err := parseSARIFOutput(jsonOutput.String(), totalFiles, startTime)
	if err != nil {
		log.Printf("[scanner] SARIF parse error: %v", err)
		// If parsing fails, return basic result with empty findings
		return &Result{
			FilesScanned: totalFiles,
			Duration:     time.Since(startTime),
			FindingsJSON: `[]`,
			ScannerUsed:  s.binaryPath,
		}, nil
	}

	result.ScannerUsed = s.binaryPath
	log.Printf("[scanner] Completed: %d findings (%d critical, %d high, %d medium, %d low) in %v",
		len(result.Findings), result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount, result.Duration)
	return result, nil
}

// mockScan returns mock results when opengrep is not available (for testing)
func (s *Scanner) mockScan(repoPath string, totalFiles int, startTime time.Time) (*Result, error) {
	// Simulate scanning progress
	return &Result{
		Findings:      []Finding{},
		CriticalCount: 0,
		HighCount:     0,
		MediumCount:   0,
		LowCount:      0,
		InfoCount:     0,
		FilesScanned:  totalFiles,
		Duration:      time.Since(startTime),
		FindingsJSON:  `[]`,
	}, nil
}

// parseSARIFOutput parses SARIF JSON output from opengrep
func parseSARIFOutput(jsonStr string, totalFiles int, startTime time.Time) (*Result, error) {
	if jsonStr == "" {
		return &Result{
			FilesScanned: totalFiles,
			Duration:     time.Since(startTime),
			FindingsJSON: `[]`,
		}, nil
	}

	var sarif SARIFOutput
	if err := json.Unmarshal([]byte(jsonStr), &sarif); err != nil {
		return nil, fmt.Errorf("failed to parse SARIF output: %w", err)
	}

	result := &Result{
		Findings:     []Finding{},
		FilesScanned: totalFiles,
		Duration:     time.Since(startTime),
	}

	// Build rule map for severity lookup
	ruleMap := make(map[string]string)
	if len(sarif.Runs) > 0 {
		for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
			ruleMap[rule.ID] = rule.DefaultConfiguration.Level
		}
	}

	// Process results
	for _, run := range sarif.Runs {
		for _, r := range run.Results {
			severity := r.Level
			if severity == "" {
				severity = ruleMap[r.RuleID]
			}

			finding := Finding{
				RuleID:   r.RuleID,
				Severity: normalizeSeverity(severity),
				Message:  r.Message.Text,
			}

			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				finding.Path = loc.ArtifactLocation.URI
				finding.StartLine = loc.Region.StartLine
				finding.EndLine = loc.Region.EndLine
				finding.StartCol = loc.Region.StartColumn
				finding.EndCol = loc.Region.EndColumn
				finding.Snippet = loc.Region.Snippet.Text
			}

			result.Findings = append(result.Findings, finding)

			// Count by severity
			switch finding.Severity {
			case "critical":
				result.CriticalCount++
			case "high":
				result.HighCount++
			case "medium":
				result.MediumCount++
			case "low":
				result.LowCount++
			default:
				result.InfoCount++
			}
		}
	}

	// Serialize findings to JSON for storage (not raw SARIF)
	findingsBytes, err := json.Marshal(result.Findings)
	if err != nil {
		result.FindingsJSON = `[]`
	} else {
		result.FindingsJSON = string(findingsBytes)
	}

	// Calculate security score
	result.SecurityScore = CalculateSecurityScore(
		result.CriticalCount,
		result.HighCount,
		result.MediumCount,
		result.LowCount,
	)

	return result, nil
}

// normalizeSeverity normalizes severity strings
func normalizeSeverity(s string) string {
	s = strings.ToLower(s)
	switch s {
	case "error", "critical":
		return "critical"
	case "warning", "high":
		return "high"
	case "note", "medium":
		return "medium"
	case "info", "low":
		return "low"
	default:
		return "info"
	}
}

// countFiles counts the number of scannable files in a directory
func countFiles(path string) (int, error) {
	count := 0
	err := filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil // Skip errors
		}
		if info.IsDir() {
			// Skip common non-code directories
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == "__pycache__" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		// Count files with common code extensions
		ext := strings.ToLower(filepath.Ext(p))
		codeExts := map[string]bool{
			".go": true, ".py": true, ".js": true, ".ts": true, ".jsx": true, ".tsx": true,
			".java": true, ".kt": true, ".scala": true, ".rb": true, ".php": true,
			".c": true, ".cpp": true, ".h": true, ".hpp": true, ".cs": true,
			".rs": true, ".swift": true, ".m": true, ".mm": true,
			".yaml": true, ".yml": true, ".json": true, ".xml": true,
			".sh": true, ".bash": true, ".zsh": true, ".ps1": true,
			".sql": true, ".html": true, ".css": true, ".scss": true,
		}
		if codeExts[ext] {
			count++
		}
		return nil
	})
	return count, err
}
