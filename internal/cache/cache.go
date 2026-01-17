package cache

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/baocin/gitscan/internal/db"
)

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
			// Return cached version
			if progressFn != nil {
				progressFn("Using cached repository")
			}
			return &CachedRepo{
				ID:            dbRepo.ID,
				URL:           dbRepo.URL,
				LocalPath:     dbRepo.LocalPath,
				LastCommitSHA: dbRepo.LastCommitSHA,
				FileCount:     dbRepo.FileCount,
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

	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"--no-tags",
		repoURL,
		localPath,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("clone timed out after %v", c.cloneTimeout)
		}
		return nil, fmt.Errorf("clone failed: %s - %w", string(output), err)
	}

	// Get commit SHA
	commitSHA, err := c.getHeadCommit(localPath)
	if err != nil {
		return nil, fmt.Errorf("failed to get commit SHA: %w", err)
	}

	// Get repo stats
	sizeBytes, fileCount := c.getRepoStats(localPath)

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

	return &CachedRepo{
		ID:            dbRepo.ID,
		URL:           repoPath,
		LocalPath:     localPath,
		LastCommitSHA: commitSHA,
		FileCount:     fileCount,
	}, nil
}

// updateRepo updates an existing cached repository
func (c *RepoCache) updateRepo(ctx context.Context, dbRepo *db.Repo, progressFn ProgressFunc) (*CachedRepo, error) {
	// Check if local path exists
	if _, err := os.Stat(dbRepo.LocalPath); os.IsNotExist(err) {
		// Re-clone if missing
		repoURL := fmt.Sprintf("https://github.com/%s.git", dbRepo.URL)
		return c.cloneRepo(ctx, dbRepo.URL, repoURL, progressFn)
	}

	// Fetch updates
	ctx, cancel := context.WithTimeout(ctx, c.fetchTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", "-C", dbRepo.LocalPath, "fetch", "--depth", "1", "origin")
	if output, err := cmd.CombinedOutput(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("fetch timed out after %v", c.fetchTimeout)
		}
		return nil, fmt.Errorf("fetch failed: %s - %w", string(output), err)
	}

	// Reset to latest
	cmd = exec.CommandContext(ctx, "git", "-C", dbRepo.LocalPath, "reset", "--hard", "origin/HEAD")
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("reset failed: %s - %w", string(output), err)
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

	return &CachedRepo{
		ID:            dbRepo.ID,
		URL:           dbRepo.URL,
		LocalPath:     dbRepo.LocalPath,
		LastCommitSHA: commitSHA,
		FileCount:     fileCount,
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
