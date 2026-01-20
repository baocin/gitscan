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
	binaryPath   string
	rulesPath    string
	timeout      time.Duration
	scanLevel    ScanLevel
	infoLeakOnly bool // Filter to only info-leak findings
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
	BinaryPath   string
	RulesPath    string
	Timeout      time.Duration
	ScanLevel    ScanLevel
	InfoLeakOnly bool // Only report info-leak findings (credential theft)
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
		binaryPath:   cfg.BinaryPath,
		rulesPath:    cfg.RulesPath,
		timeout:      cfg.Timeout,
		scanLevel:    cfg.ScanLevel,
		infoLeakOnly: cfg.InfoLeakOnly,
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

// IsInfoLeakOnly returns whether scanner is in info-leak-only mode
func (s *Scanner) IsInfoLeakOnly() bool {
	return s.infoLeakOnly
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
	InfoLeakCount    int       // Credential/secret leaks (highest priority)
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

// RunRiskWeights defines risk points added per severity level
var RunRiskWeights = map[string]int{
	"info-leak": 50, // +50 risk per info leak (immediate danger to cloner)
	"critical":  20, // +20 risk per critical finding
	"high":      10, // +10 risk per high finding
	"medium":    3,  // +3 risk per medium finding
	"low":       1,  // +1 risk per low finding
	"info":      0,  // info findings don't affect risk
}

// CalculateRunRisk computes a 0-100 run risk score based on findings
// 0 = safe to run, 100 = extremely dangerous to execute
func CalculateRunRisk(infoLeak, critical, high, medium, low int) int {
	risk := 0
	risk += infoLeak * RunRiskWeights["info-leak"]
	risk += critical * RunRiskWeights["critical"]
	risk += high * RunRiskWeights["high"]
	risk += medium * RunRiskWeights["medium"]
	risk += low * RunRiskWeights["low"]

	if risk > 100 {
		risk = 100
	}
	return risk
}

// RiskGrade returns a letter grade for the run risk score
func RiskGrade(risk int) string {
	switch {
	case risk == 0:
		return "A" // Safe
	case risk <= 10:
		return "B" // Low risk
	case risk <= 30:
		return "C" // Medium risk
	case risk <= 60:
		return "D" // High risk
	default:
		return "F" // Dangerous - do not run
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
	IsInfoLeak  bool     `json:"is_info_leak"` // True if this is credential theft/auto-exec detection
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
		"--disable-version-check", // Prevent permission errors on version cache file
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
			partialResult, parseErr := parseSARIFOutput(jsonOutput.String(), repoPath, totalFiles, startTime, s.infoLeakOnly)
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
				// BUT if we have valid SARIF output, the scan actually succeeded
				// (exit code 2 may be from cleanup/version check failures)
				if stdoutStr != "" && strings.HasPrefix(stdoutStr, "{") {
					// We have JSON output, try to parse it
					if _, parseErr := parseSARIFOutput(stdoutStr, repoPath, totalFiles, startTime, s.infoLeakOnly); parseErr == nil {
						// Valid SARIF! Scan succeeded despite exit code 2
						log.Printf("[scanner] Exit code 2 but valid SARIF output present, treating as success")
						err = nil // Clear the error, proceed with normal parsing
					} else {
						// Invalid SARIF, this is a real error
						log.Printf("[scanner] Exit code 2 with invalid SARIF output: %v", parseErr)
						return nil, fmt.Errorf("scanner configuration error (exit code 2): invalid SARIF output: %w", parseErr)
					}
				} else {
					// No JSON output, this is a real configuration error
					errorMsg := stderrStr
					if stdoutStr != "" {
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
				}
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

	result, err := parseSARIFOutput(jsonOutput.String(), repoPath, totalFiles, startTime, s.infoLeakOnly)
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
func parseSARIFOutput(jsonStr string, repoPath string, totalFiles int, startTime time.Time, infoLeakOnly bool) (*Result, error) {
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
				RuleID:     r.RuleID,
				Severity:   normalizeSeverity(severity, r.RuleID),
				Message:    r.Message.Text,
				IsInfoLeak: classifyAsInfoLeak(r.RuleID),
			}

			if len(r.Locations) > 0 {
				loc := r.Locations[0].PhysicalLocation
				// Strip repository path prefix to show relative paths
				finding.Path = strings.TrimPrefix(loc.ArtifactLocation.URI, repoPath+"/")
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

			// Track info-leak findings separately
			if finding.IsInfoLeak {
				result.InfoLeakCount++
			}
		}
	}

	// Filter to info-leak findings only if in info-leak-only mode
	if infoLeakOnly {
		filteredFindings := []Finding{}
		for _, finding := range result.Findings {
			if finding.IsInfoLeak {
				filteredFindings = append(filteredFindings, finding)
			}
		}
		result.Findings = filteredFindings

		// Recalculate severity counts for info-leak findings only
		result.CriticalCount = 0
		result.HighCount = 0
		result.MediumCount = 0
		result.LowCount = 0
		result.InfoCount = 0
		result.InfoLeakCount = 0

		for _, finding := range result.Findings {
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
			if finding.IsInfoLeak {
				result.InfoLeakCount++
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

	// Calculate run risk score
	result.SecurityScore = CalculateRunRisk(
		result.InfoLeakCount,
		result.CriticalCount,
		result.HighCount,
		result.MediumCount,
		result.LowCount,
	)

	return result, nil
}

// classifyAsInfoLeak checks if a rule ID indicates data exfiltration/info stealing
// from the perspective of the person cloning and running the code
func classifyAsInfoLeak(ruleID string) bool {
	ruleIDLower := strings.ToLower(ruleID)

	// Pattern matching for data exfiltration / info stealing from cloner
	leakPatterns := []string{
		// SSH/credentials theft
		"ssh-key", "reads-ssh", "steal-ssh", "exfiltrate-ssh",
		"reads-credentials", "steal-credentials", "credential-theft",
		"steals-ssh",

		// Environment/config theft
		"reads-env", "environment-var", "steal-env", "exfiltrate-env",
		"reads-config", "steal-config", "env-var-access",

		// AWS/cloud credentials
		"aws-credential", "reads-aws", "steal-aws", "exfiltrate-aws",
		"cloud-credential", "gcp-credential", "azure-credential",
		"reads-cloud",

		// Browser data
		"browser-cookie", "browser-credential", "steal-cookie",
		"reads-browser", "chrome-password", "firefox-password",
		"cookie-theft", "browser-data",

		// System access
		"shell-history", "bash-history", "clipboard-access",
		"keylog", "keystroke", "input-capture", "reads-clipboard",
		"history-file",

		// Cryptocurrency
		"crypto-wallet", "bitcoin-wallet", "ethereum-wallet",
		"metamask", "wallet-theft", "cryptocurrency",

		// Network exfiltration
		"data-exfiltration", "exfiltrate-data", "suspicious-upload",
		"unauthorized-network", "phone-home", "suspicious-request",
		"data-theft", "steals-data",

		// File system access to private data
		"reads-private-key", "steal-file", "unauthorized-read",
		"reads-home", "access-private", "file-theft",

		// Package manager install hooks (supply chain attacks)
		"install-hook", "postinstall", "preinstall", "setup-py",
		"malicious-npm", "malicious-setup", "npm-hook", "python-hook",

		// NPM/PyPI credential theft
		"npmrc", "npm-token", "pypi-token", "env-file",

		// Auto-execution mechanisms (git hooks, makefiles, etc.)
		"auto-exec", "git-hook", "malicious-git", "git-submodule",
		"malicious-makefile", "makefile-network", "makefile-credential",
		"dangerous-readme", "install-script", "build-script",
		"git-filter", "gitattributes",

		// Multi-language build system auto-execution
		"rust-build", "build-rs", "cargo-build",
		"maven-exec", "pom-xml", "ant-run",
		"gradle-exec", "gradle-init", "gradle-task",
		"cmake-execute", "cmake-download", "cmakelists",
		"dockerfile-onbuild", "docker-compose", "docker-add",

		// Additional language ecosystems
		"composer-scripts", "composer-post", "php-composer",
		"gemspec", "rakefile", "bundler",
		"msbuild", "nuget", "csproj", "dotnet-build",

		// CI/CD auto-execution
		"github-actions", "gitlab-ci", "travis-ci", "circle-ci",
		"workflow", "pipeline",

		// Git hook managers
		"precommit", "pre-commit", "lefthook", "husky",
	}

	for _, pattern := range leakPatterns {
		if strings.Contains(ruleIDLower, pattern) {
			return true
		}
	}

	return false
}

// normalizeSeverity normalizes severity strings to standard levels
func normalizeSeverity(s string, ruleID string) string {
	// Normalize severity string (don't override for info-leak)
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
