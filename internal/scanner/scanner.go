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
	scanLevel  ScanLevel
}

// ScanLevel defines the depth/thoroughness of scanning
type ScanLevel string

const (
	ScanLevelQuick     ScanLevel = "quick"     // Fast scan, critical issues only
	ScanLevelNormal    ScanLevel = "normal"    // Standard scan, all severities
	ScanLevelThorough  ScanLevel = "thorough"  // Deep scan, maximum analysis
)

// Config holds scanner configuration
type Config struct {
	BinaryPath string
	RulesPath  string
	Timeout    time.Duration
	ScanLevel  ScanLevel
}

// DefaultConfig returns default scanner configuration
func DefaultConfig() Config {
	return Config{
		BinaryPath: "opengrep",           // Assumes opengrep is in PATH
		RulesPath:  "",                   // Use default rules
		Timeout:    180 * time.Second,    // 3 minutes - increased for large repos
		ScanLevel:  ScanLevelNormal,
	}
}

// New creates a new scanner instance
func New(cfg Config) *Scanner {
	if cfg.Timeout == 0 {
		cfg.Timeout = 180 * time.Second
	}
	if cfg.ScanLevel == "" {
		cfg.ScanLevel = ScanLevelNormal
	}
	return &Scanner{
		binaryPath: cfg.BinaryPath,
		rulesPath:  cfg.RulesPath,
		timeout:    cfg.Timeout,
		scanLevel:  cfg.ScanLevel,
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
	Findings         []Finding
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	FilesScanned     int
	Duration         time.Duration
	FindingsJSON     string    // JSON array of Finding structs (not raw SARIF)
	ScannerUsed      string    // "opengrep", "semgrep", or "mock"
	SecurityScore    int       // 0-100 score based on severity-weighted findings
	ScanLevel        ScanLevel // Scan level used
	CachedFileCount  int       // Number of files reused from cache
	ScannedFileCount int       // Number of files actually scanned
	IsPartial        bool      // True if scan timed out with partial results
	PartialReason    string    // Why partial: "timeout", "cancelled", etc.
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

// buildScanArgs builds opengrep arguments based on scan level
func (s *Scanner) buildScanArgs(repoPath string) []string {
	args := []string{
		"scan",
		"--sarif",
	}

	// Add level-specific performance flags
	switch s.scanLevel {
	case ScanLevelQuick:
		// Fast scan: critical only, aggressive timeouts, smaller files, more parallelism
		args = append(args, "--severity", "ERROR")
		args = append(args, "--timeout", "2")
		args = append(args, "--max-target-bytes", "500000") // 500KB max
		args = append(args, "--jobs", "16")
		args = append(args, "--timeout-threshold", "1") // Skip file after 1 timeout

	case ScanLevelThorough:
		// Deep scan: all severities, longer timeouts, larger files, less parallelism
		args = append(args, "--timeout", "30")
		args = append(args, "--max-target-bytes", "5000000") // 5MB max
		args = append(args, "--jobs", "8")
		args = append(args, "--timeout-threshold", "5")

	default: // ScanLevelNormal
		// Balanced scan: all severities, standard timeouts
		args = append(args, "--timeout", "5")
		args = append(args, "--max-target-bytes", "1000000") // 1MB max
		args = append(args, "--jobs", "12")
		args = append(args, "--timeout-threshold", "3")
	}

	// Add config
	if s.rulesPath != "" {
		args = append(args, "--config", s.rulesPath)
	} else {
		args = append(args, "--config", "auto")
	}

	// Exclude common bloat
	args = append(args, "--exclude", "node_modules")
	args = append(args, "--exclude", "vendor")
	args = append(args, "--exclude", "*.min.js")
	args = append(args, "--exclude", "*.bundle.js")

	args = append(args, repoPath)
	return args
}

// Scan performs a security scan on the given path
func (s *Scanner) Scan(ctx context.Context, repoPath string, progressFn ProgressFunc) (*Result, error) {
	startTime := time.Now()

	// Count files first for progress reporting
	totalFiles, err := countFiles(repoPath)
	if err != nil {
		totalFiles = 0 // Continue even if we can't count
	}

	// Build opengrep command args based on scan level
	args := s.buildScanArgs(repoPath)

	// Create context with timeout (adjust based on scan level)
	timeout := s.timeout
	switch s.scanLevel {
	case ScanLevelQuick:
		timeout = 30 * time.Second
	case ScanLevelThorough:
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Validate repository path exists before attempting scan
	if stat, err := os.Stat(repoPath); err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("repository path does not exist: %s (this indicates a cache directory issue)", repoPath)
		}
		return nil, fmt.Errorf("cannot access repository path %s: %w", repoPath, err)
	} else if !stat.IsDir() {
		return nil, fmt.Errorf("repository path is not a directory: %s", repoPath)
	}

	cmd := exec.CommandContext(ctx, s.binaryPath, args...)
	// Set QT_QPA_PLATFORM=offscreen to prevent Qt display errors on headless servers
	cmd.Env = append(os.Environ(), "QT_QPA_PLATFORM=offscreen")
	log.Printf("[scanner] Running (%s): %s %s", s.scanLevel, s.binaryPath, strings.Join(args, " "))
	log.Printf("[scanner] Repository path: %s", repoPath)

	// Log cache directory for config auto downloads and ensure it exists
	if cacheDir, err := os.UserCacheDir(); err == nil {
		log.Printf("[scanner] User cache dir: %s", cacheDir)
		semgrepCache := filepath.Join(cacheDir, "semgrep")
		if stat, err := os.Stat(semgrepCache); err == nil {
			log.Printf("[scanner] Semgrep cache exists: %s (readable: %t)", semgrepCache, stat.IsDir())
		} else if os.IsNotExist(err) {
			// Create semgrep cache directory with proper permissions
			log.Printf("[scanner] Semgrep cache missing, creating: %s", semgrepCache)
			if err := os.MkdirAll(semgrepCache, 0755); err != nil {
				log.Printf("[scanner] Warning: failed to create semgrep cache: %v", err)
			} else {
				log.Printf("[scanner] Semgrep cache created successfully")
			}
		} else {
			log.Printf("[scanner] Warning: semgrep cache stat error: %v", err)
		}
	} else {
		log.Printf("[scanner] Warning: cannot determine user cache dir: %v", err)
	}

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

	// Read stderr for progress updates and error messages
	var stderrOutput strings.Builder
	stderrDone := make(chan struct{})
	go func() {
		defer close(stderrDone)
		stderrScanner := bufio.NewScanner(stderr)
		scannedFiles := 0
		for stderrScanner.Scan() {
			line := stderrScanner.Text()
			stderrOutput.WriteString(line)
			stderrOutput.WriteString("\n")
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
	stdoutScanner := bufio.NewScanner(stdout)
	stdoutScanner.Buffer(make([]byte, 1024*1024), 10*1024*1024) // 10MB buffer
	for stdoutScanner.Scan() {
		jsonOutput.WriteString(stdoutScanner.Text())
	}

	// Wait for command to complete
	err = cmd.Wait()

	// Wait for stderr goroutine to finish collecting output
	<-stderrDone

	// Log stderr output for debugging (especially important when stdout is empty)
	stderrStr := strings.TrimSpace(stderrOutput.String())
	stdoutStr := strings.TrimSpace(jsonOutput.String())
	if stderrStr != "" {
		log.Printf("[scanner] Stderr output: %s", stderrStr)
	}
	// Also log stdout if it's not SARIF JSON (likely an error message)
	if stdoutStr != "" && !strings.HasPrefix(stdoutStr, "{") {
		log.Printf("[scanner] Stdout (non-JSON): %s", stdoutStr)
	}

	// Check for timeout/cancellation first, before checking exit codes
	if err != nil && ctx.Err() == context.DeadlineExceeded {
		// Try to salvage partial results from what was scanned before timeout
		log.Printf("[scanner] Scan timed out after %v, attempting to parse partial results...", s.timeout)

		if len(jsonOutput.String()) > 0 {
			partialResult, parseErr := parseSARIFOutput(jsonOutput.String(), totalFiles, startTime)
			if parseErr == nil && len(partialResult.Findings) > 0 {
				// We got partial results! Return them with warning
				partialResult.ScannerUsed = s.binaryPath
				partialResult.ScanLevel = s.scanLevel
				partialResult.IsPartial = true
				partialResult.PartialReason = fmt.Sprintf("timeout after %v", s.timeout)
				log.Printf("[scanner] Partial results recovered: %d findings from %d files (timeout)",
					len(partialResult.Findings), partialResult.FilesScanned)
				return partialResult, nil
			}
		}

		// No partial results available, return timeout error
		return nil, fmt.Errorf("scan timed out after %v", s.timeout)
	}

	if err != nil {
		// opengrep returns non-zero when findings are present, which is expected
		if exitErr, ok := err.(*exec.ExitError); ok {
			if exitErr.ExitCode() == 1 {
				// Exit code 1 means findings were found, not an error
				err = nil
			} else if exitErr.ExitCode() == -1 {
				// Exit code -1 typically means killed by signal (could be timeout or OOM)
				return nil, fmt.Errorf("scanner was terminated (exit code -1). This may indicate timeout, out of memory, or a crash. Stderr: %s", stderrStr)
			} else if exitErr.ExitCode() == 2 {
				// Exit code 2 indicates configuration/rules error
				// Combine stderr and stdout for error message (config errors may go to either)
				errorMsg := stderrStr
				if stdoutStr != "" && !strings.HasPrefix(stdoutStr, "{") {
					if errorMsg != "" {
						errorMsg = fmt.Sprintf("Stderr: %s; Stdout: %s", errorMsg, stdoutStr)
					} else {
						errorMsg = stdoutStr
					}
				}
				if errorMsg == "" {
					errorMsg = "No error output captured. Common causes: network failure downloading rules (--config auto), permission issues accessing cache directory, or invalid configuration. Check logs above for cache directory info."
				}
				log.Printf("[scanner] Configuration error (exit code 2): %s", errorMsg)
				return nil, fmt.Errorf("scanner configuration error (exit code 2): %s", errorMsg)
			} else {
				// Include stderr and exit code in error for debugging
				log.Printf("[scanner] Failed with exit code %d: %s", exitErr.ExitCode(), stderrStr)
				return nil, fmt.Errorf("scanner failed with exit code %d: %s", exitErr.ExitCode(), stderrStr)
			}
		}
	}

	// Parse SARIF output
	log.Printf("[scanner] Raw output length: %d bytes", len(jsonOutput.String()))
	if len(jsonOutput.String()) == 0 {
		log.Printf("[scanner] WARNING: Scanner produced no output. This may indicate:")
		log.Printf("[scanner]   - No rules were loaded (check --config setting)")
		log.Printf("[scanner]   - Network issues preventing rule download (if using 'auto' config)")
		log.Printf("[scanner]   - Repository has no scannable files")
	} else if len(jsonOutput.String()) < 500 {
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
	result.ScanLevel = s.scanLevel
	log.Printf("[scanner] Completed (%s): %d findings (%d critical, %d high, %d medium, %d low) in %v",
		s.scanLevel, len(result.Findings), result.CriticalCount, result.HighCount, result.MediumCount, result.LowCount, result.Duration)
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
