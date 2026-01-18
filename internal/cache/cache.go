package cache

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/baocin/gitscan/internal/db"
	"github.com/baocin/gitscan/internal/license"
)

// Error types for better error handling
var (
	ErrRepoNotFound     = errors.New("repository not found")
	ErrRepoPrivate      = errors.New("repository is private or requires authentication")
	ErrNetworkError     = errors.New("network error - could not connect to host")
	ErrInvalidURL       = errors.New("invalid repository URL")
	ErrCloneTimeout     = errors.New("clone timed out")
	ErrRepoTooLarge     = errors.New("repository is too large")
	ErrRateLimited      = errors.New("rate limited by host")
)

// RepoError wraps an error with additional context
type RepoError struct {
	Type    error  // One of the Err* sentinel errors
	Message string // Human-friendly message
	Details string // Technical details (e.g., git output)
}

func (e *RepoError) Error() string {
	return e.Message
}

func (e *RepoError) Unwrap() error {
	return e.Type
}

// classifyCloneError analyzes git clone output and returns a classified error
func classifyCloneError(output string, originalErr error, repoURL string, timeout time.Duration) error {
	outputLower := strings.ToLower(output)

	// Check for common error patterns (order matters - more specific patterns first)

	// Check rate limiting first (before network errors, as both can contain "unable to access")
	if strings.Contains(outputLower, "rate limit") ||
		strings.Contains(outputLower, "too many requests") ||
		strings.Contains(outputLower, "429") {
		return &RepoError{
			Type:    ErrRateLimited,
			Message: "The host is rate limiting requests. Please wait a moment and try again.",
			Details: output,
		}
	}

	// Check for repo not found
	if strings.Contains(outputLower, "repository not found") ||
		strings.Contains(outputLower, "could not be found") ||
		strings.Contains(outputLower, "not found") && strings.Contains(outputLower, "fatal") {
		return &RepoError{
			Type:    ErrRepoNotFound,
			Message: "Repository not found. Please check that the URL is correct and the repository exists.",
			Details: output,
		}
	}

	// Check for authentication/permission issues
	if strings.Contains(outputLower, "authentication failed") ||
		strings.Contains(outputLower, "could not read username") ||
		strings.Contains(outputLower, "could not read password") ||
		strings.Contains(outputLower, "403") ||
		strings.Contains(outputLower, "permission denied") {
		return &RepoError{
			Type:    ErrRepoPrivate,
			Message: "This repository is private or requires authentication. git.vet can only scan public repositories.",
			Details: output,
		}
	}

	// Check for invalid URL
	if strings.Contains(outputLower, "invalid") && strings.Contains(outputLower, "url") {
		return &RepoError{
			Type:    ErrInvalidURL,
			Message: "Invalid repository URL format. Use: git clone https://git.vet/github.com/owner/repo",
			Details: output,
		}
	}

	// Check for network errors (last, as it's the most generic)
	if strings.Contains(outputLower, "could not resolve host") ||
		strings.Contains(outputLower, "connection refused") ||
		strings.Contains(outputLower, "network is unreachable") ||
		strings.Contains(outputLower, "connection timed out") ||
		strings.Contains(outputLower, "unable to access") {
		return &RepoError{
			Type:    ErrNetworkError,
			Message: "Could not connect to the repository host. Please verify the URL and try again.",
			Details: output,
		}
	}

	// Default error message
	return &RepoError{
		Type:    originalErr,
		Message: fmt.Sprintf("Failed to clone repository: %s", firstLine(output)),
		Details: output,
	}
}

// firstLine returns the first non-empty line of output
func firstLine(output string) string {
	lines := strings.Split(strings.TrimSpace(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			// Remove common git prefixes for cleaner output
			line = strings.TrimPrefix(line, "fatal: ")
			line = strings.TrimPrefix(line, "error: ")
			line = strings.TrimPrefix(line, "remote: ")
			return line
		}
	}
	return "unknown error"
}

// RepoCache manages cached repository clones
type RepoCache struct {
	db       *db.DB
	cacheDir string
	mu       sync.RWMutex

	// Configuration
	maxRepoSize   int64         // Maximum repo size in bytes
	staleAfter    time.Duration // Re-fetch repos older than this
	cloneTimeout  time.Duration
	fetchTimeout  time.Duration
}

// Config holds cache configuration
type Config struct {
	CacheDir     string
	MaxRepoSize  int64
	StaleAfter   time.Duration
	CloneTimeout time.Duration
	FetchTimeout time.Duration
}

// DefaultConfig returns default cache configuration
func DefaultConfig() Config {
	// Use home directory based temp dir if possible
	cacheDir := "/tmp/gitvettmpdir"
	if home, err := os.UserHomeDir(); err == nil {
		cacheDir = filepath.Join(home, "gitvettmpdir")
	}

	return Config{
		CacheDir:     cacheDir,
		MaxRepoSize:  500 * 1024 * 1024, // 500MB
		StaleAfter:   1 * time.Hour,
		CloneTimeout: 120 * time.Second,
		FetchTimeout: 60 * time.Second,
	}
}

// CachedRepo represents a cached repository
type CachedRepo struct {
	ID            int64
	URL           string
	LocalPath     string
	LastCommitSHA string
	FileCount     int
	License       string // License type (e.g., "MIT", "Apache-2.0")
}

// ProgressFunc is a callback for progress updates
type ProgressFunc func(message string)

// New creates a new repo cache
func New(database *db.DB, cfg Config) (*RepoCache, error) {
	// Ensure cache directory exists
	if err := os.MkdirAll(cfg.CacheDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create cache directory: %w", err)
	}

	return &RepoCache{
		db:           database,
		cacheDir:     cfg.CacheDir,
		maxRepoSize:  cfg.MaxRepoSize,
		staleAfter:   cfg.StaleAfter,
		cloneTimeout: cfg.CloneTimeout,
		fetchTimeout: cfg.FetchTimeout,
	}, nil
}

// FetchRepo fetches or updates a repository, returning cache info
// repoPath is the unique identifier (e.g., "github.com/user/repo")
// cloneURL is the full git clone URL (e.g., "https://github.com/user/repo.git")
func (c *RepoCache) FetchRepo(ctx context.Context, repoPath, cloneURL string, progressFn ProgressFunc) (*CachedRepo, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	repoURL := cloneURL

	// Check if we have this repo cached
	dbRepo, err := c.db.GetRepoByURL(repoPath)
	if err != nil {
		return nil, fmt.Errorf("database error: %w", err)
	}

	if dbRepo != nil {
		// Check if cache is fresh
		if time.Since(dbRepo.LastFetchedAt) < c.staleAfter {
			// Verify the directory actually exists before returning cached version
			if _, err := os.Stat(dbRepo.LocalPath); err != nil {
				if os.IsNotExist(err) {
					log.Printf("[cache] Cached repo directory missing for %s, re-cloning", repoPath)
					// Directory doesn't exist, need to update (will trigger re-clone)
					if progressFn != nil {
						progressFn("Cached directory missing, re-cloning...")
					}
					return c.updateRepo(ctx, dbRepo, progressFn)
				}
				// Other stat errors (permissions, etc.) - log but try to use anyway
				log.Printf("[cache] Warning: stat error for %s: %v", dbRepo.LocalPath, err)
			}

			// Return cached version
			if progressFn != nil {
				progressFn("Using cached repository")
			}
			// Detect license
			licenseType := ""
			if licInfo := license.Detect(dbRepo.LocalPath); licInfo != nil {
				licenseType = licInfo.Type
			}
			return &CachedRepo{
				ID:            dbRepo.ID,
				URL:           dbRepo.URL,
				LocalPath:     dbRepo.LocalPath,
				LastCommitSHA: dbRepo.LastCommitSHA,
				FileCount:     dbRepo.FileCount,
				License:       licenseType,
			}, nil
		}

		// Update existing cache
		if progressFn != nil {
			progressFn("Updating cached repository...")
		}
		return c.updateRepo(ctx, dbRepo, progressFn)
	}

	// Clone new repository
	if progressFn != nil {
		progressFn("Cloning repository...")
	}
	return c.cloneRepo(ctx, repoPath, repoURL, progressFn)
}

// cloneRepo clones a new repository
func (c *RepoCache) cloneRepo(ctx context.Context, repoPath, repoURL string, progressFn ProgressFunc) (*CachedRepo, error) {
	// Create local path
	localPath := filepath.Join(c.cacheDir, sanitizePath(repoPath))

	// Remove any existing directory
	os.RemoveAll(localPath)

	// Clone with shallow depth
	ctx, cancel := context.WithTimeout(ctx, c.cloneTimeout)
	defer cancel()

	log.Printf("[cache] Cloning %s (timeout: %v)", repoPath, c.cloneTimeout)
	cloneStart := time.Now()

	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"--no-tags",
		repoURL,
		localPath,
	)

	output, err := cmd.CombinedOutput()
	cloneDuration := time.Since(cloneStart)

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[cache] Clone timeout for %s after %v (git output: %s)", repoPath, cloneDuration, truncateOutput(string(output), 200))
			return nil, &RepoError{
				Type:    ErrCloneTimeout,
				Message: fmt.Sprintf("Clone timed out after %v. The repository may be too large or the connection is slow.", c.cloneTimeout),
				Details: string(output),
			}
		}
		log.Printf("[cache] Clone failed for %s after %v: %v (git output: %s)", repoPath, cloneDuration, err, truncateOutput(string(output), 200))
		return nil, classifyCloneError(string(output), err, repoURL, c.cloneTimeout)
	}

	// Make repo read-only immediately for security (prevents malicious code execution)
	if err := makeReadOnly(localPath); err != nil {
		// Log but don't fail - this is a defense-in-depth measure
		// The scan can still proceed even if we can't lock down permissions
		fmt.Fprintf(os.Stderr, "Warning: failed to set read-only permissions on %s: %v\n", localPath, err)
	}

	// Get commit SHA
	commitSHA, err := c.getHeadCommit(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit SHA: %w", err)
	}

	// Get repo stats
	sizeBytes, fileCount := c.getRepoStats(localPath)

	// Log successful clone with stats
	sizeMB := float64(sizeBytes) / (1024 * 1024)
	log.Printf("[cache] Clone succeeded for %s: %d files, %.2f MB in %v", repoPath, fileCount, sizeMB, cloneDuration)

	// Check size limit
	if sizeBytes > c.maxRepoSize {
		os.RemoveAll(localPath)
		return nil, fmt.Errorf("repository too large: %d bytes (max: %d)", sizeBytes, c.maxRepoSize)
	}

	// Save to database
	dbRepo, err := c.db.CreateRepo(repoPath, localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to save repo: %w", err)
	}

	if err := c.db.UpdateRepoFetched(dbRepo.ID, commitSHA, sizeBytes, fileCount); err != nil {
		return nil, fmt.Errorf("failed to update repo: %w", err)
	}

	if progressFn != nil {
		progressFn(fmt.Sprintf("Cloned %d files", fileCount))
	}

	// Detect license and save to database
	licenseType := ""
	if licInfo := license.Detect(localPath); licInfo != nil {
		licenseType = licInfo.Type
		c.db.UpdateRepoLicense(dbRepo.ID, licenseType)
	}

	return &CachedRepo{
		ID:            dbRepo.ID,
		URL:           repoPath,
		LocalPath:     localPath,
		LastCommitSHA: commitSHA,
		FileCount:     fileCount,
		License:       licenseType,
	}, nil
}

// updateRepo updates an existing cached repository
func (c *RepoCache) updateRepo(ctx context.Context, dbRepo *db.Repo, progressFn ProgressFunc) (*CachedRepo, error) {
	// Check if local path exists
	if _, err := os.Stat(dbRepo.LocalPath); os.IsNotExist(err) {
		// Re-clone if missing - dbRepo.URL contains full path like "github.com/user/repo"
		repoURL := fmt.Sprintf("https://%s.git", dbRepo.URL)
		return c.cloneRepo(ctx, dbRepo.URL, repoURL, progressFn)
	}

	// Make repo writable temporarily for git operations
	if err := makeWritable(dbRepo.LocalPath); err != nil {
		return nil, fmt.Errorf("failed to make repo writable: %w", err)
	}

	// Fetch updates
	log.Printf("[cache] Fetching updates for %s (timeout: %v)", dbRepo.URL, c.fetchTimeout)
	fetchStart := time.Now()

	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", dbRepo.LocalPath, "fetch", "--depth", "1", "origin")
	if output, err := cmd.CombinedOutput(); err != nil {
		fetchDuration := time.Since(fetchStart)
		if ctx.Err() == context.DeadlineExceeded {
			log.Printf("[cache] Fetch timeout for %s after %v", dbRepo.URL, fetchDuration)
			return nil, fmt.Errorf("fetch timed out after %v", c.fetchTimeout)
		}
		log.Printf("[cache] Fetch failed for %s after %v: %v (git output: %s)", dbRepo.URL, fetchDuration, err, truncateOutput(string(output), 200))
		return nil, fmt.Errorf("fetch failed: %s - %w", string(output), err)
	}

	// Reset to latest
	cmd = exec.CommandContext(ctx, "git", "-C", dbRepo.LocalPath, "reset", "--hard", "origin/HEAD")
	if output, err := cmd.CombinedOutput(); err != nil {
		log.Printf("[cache] Reset failed for %s: %v (git output: %s)", dbRepo.URL, err, truncateOutput(string(output), 200))
		return nil, fmt.Errorf("reset failed: %s - %w", string(output), err)
	}

	fetchDuration := time.Since(fetchStart)
	log.Printf("[cache] Fetch succeeded for %s in %v", dbRepo.URL, fetchDuration)

	// Make repo read-only again after git operations complete
	if err := makeReadOnly(dbRepo.LocalPath); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to set read-only permissions on %s: %v\n", dbRepo.LocalPath, err)
	}

	// Get new commit SHA
	commitSHA, err := c.getHeadCommit(dbRepo.LocalPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit SHA: %w", err)
	}

	// Update stats
	sizeBytes, fileCount := c.getRepoStats(dbRepo.LocalPath)

	// Update database
	if err := c.db.UpdateRepoFetched(dbRepo.ID, commitSHA, sizeBytes, fileCount); err != nil {
		return nil, fmt.Errorf("failed to update repo: %w", err)
	}

	if progressFn != nil {
		progressFn(fmt.Sprintf("Updated to %s", truncate(commitSHA, 8)))
	}

	// Detect license and save to database
	licenseType := ""
	if licInfo := license.Detect(dbRepo.LocalPath); licInfo != nil {
		licenseType = licInfo.Type
		c.db.UpdateRepoLicense(dbRepo.ID, licenseType)
	}

	return &CachedRepo{
		ID:            dbRepo.ID,
		URL:           dbRepo.URL,
		LocalPath:     dbRepo.LocalPath,
		LastCommitSHA: commitSHA,
		FileCount:     fileCount,
		License:       licenseType,
	}, nil
}

// getHeadCommit gets the HEAD commit SHA
func (c *RepoCache) getHeadCommit(repoPath string) (string, error) {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// getRepoStats gets repository size and file count
func (c *RepoCache) getRepoStats(repoPath string) (sizeBytes int64, fileCount int) {
	filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		// Skip .git directory
		if info.IsDir() && info.Name() == ".git" {
			return filepath.SkipDir
		}
		if !info.IsDir() {
			sizeBytes += info.Size()
			fileCount++
		}
		return nil
	})
	return
}

// GetCacheDir returns the cache directory path
func (c *RepoCache) GetCacheDir() string {
	return c.cacheDir
}

// DeleteRepo removes a cached repository from disk
// This should be called after scanning completes (success or failure)
func (c *RepoCache) DeleteRepo(localPath string) error {
	if localPath == "" {
		return nil
	}
	// Safety check: ensure path is within cache dir
	absPath, err := filepath.Abs(localPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}
	absCacheDir, err := filepath.Abs(c.cacheDir)
	if err != nil {
		return fmt.Errorf("failed to get absolute cache dir: %w", err)
	}
	if !strings.HasPrefix(absPath, absCacheDir) {
		return fmt.Errorf("refusing to delete path outside cache directory: %s", localPath)
	}
	return os.RemoveAll(localPath)
}

// Cleanup removes old cached repositories
func (c *RepoCache) Cleanup(maxAge time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// TODO: Query database for repos older than maxAge and remove them
	// For now, this is a placeholder
	return nil
}

// sanitizePath converts a repo path to a safe filesystem path
func sanitizePath(repoPath string) string {
	// Replace / with __
	safe := strings.ReplaceAll(repoPath, "/", "__")
	// Remove any other potentially dangerous characters
	safe = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			return r
		}
		return '_'
	}, safe)
	return safe
}

// truncate truncates a string to the given length
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length]
}

// truncateOutput truncates output and removes newlines for logging
func truncateOutput(s string, maxLen int) string {
	// Replace newlines with spaces for single-line logging
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.TrimSpace(s)
	if len(s) > maxLen {
		return s[:maxLen] + "..."
	}
	return s
}

// makeReadOnly recursively sets read-only permissions on a directory tree
// Directories: 0555 (r-x, allows traversal but no writes)
// Files: 0444 (r--, read-only, not executable)
// This prevents malicious code from executing or modifying itself
func makeReadOnly(path string) error {
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(p, 0555)
		}
		return os.Chmod(p, 0444)
	})
}

// makeWritable recursively sets writable permissions on a directory tree
// Used temporarily for git operations (fetch/reset) that need write access
// Directories: 0755 (rwx)
// Files: 0644 (rw-)
func makeWritable(path string) error {
	return filepath.Walk(path, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(p, 0755)
		}
		return os.Chmod(p, 0644)
	})
}
