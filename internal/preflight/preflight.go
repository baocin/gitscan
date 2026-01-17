package preflight

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"syscall"
	"time"
)

// RepoInfo contains pre-clone repository metadata
type RepoInfo struct {
	Owner       string
	Name        string
	FullName    string
	SizeKB      int64  // Size in KB (from GitHub API)
	SizeBytes   int64  // Estimated size in bytes
	IsPrivate   bool
	DefaultRef  string
	Description string
	Error       error
}

// Config holds preflight check configuration
type Config struct {
	GitHubToken      string        // Optional GitHub token for API calls
	MaxRepoSizeKB    int64         // Maximum allowed repo size in KB (default: 500MB = 512000KB)
	MinFreeDiskBytes int64         // Minimum free disk space required (default: 1GB)
	HTTPTimeout      time.Duration // Timeout for API calls
}

// DefaultConfig returns default preflight configuration
func DefaultConfig() Config {
	return Config{
		MaxRepoSizeKB:    512000,           // 500MB
		MinFreeDiskBytes: 1 << 30,          // 1GB
		HTTPTimeout:      10 * time.Second,
	}
}

// Checker performs preflight checks before cloning
type Checker struct {
	config     Config
	httpClient *http.Client
}

// NewChecker creates a new preflight checker
func NewChecker(config Config) *Checker {
	return &Checker{
		config: config,
		httpClient: &http.Client{
			Timeout: config.HTTPTimeout,
		},
	}
}

// CheckRepo performs preflight checks on a repository
func (c *Checker) CheckRepo(ctx context.Context, repoPath string) (*RepoInfo, error) {
	// Parse owner/repo from path
	parts := strings.SplitN(repoPath, "/", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid repository path: %s", repoPath)
	}

	info := &RepoInfo{
		Owner:    parts[0],
		Name:     parts[1],
		FullName: repoPath,
	}

	// Fetch repo metadata from GitHub API
	if err := c.fetchGitHubMetadata(ctx, info); err != nil {
		// Non-fatal: we can still try to clone
		info.Error = err
	}

	return info, nil
}

// fetchGitHubMetadata fetches repository metadata from GitHub API
func (c *Checker) fetchGitHubMetadata(ctx context.Context, info *RepoInfo) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", info.Owner, info.Name)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "gitscan/1.0")

	if c.config.GitHubToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.config.GitHubToken)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		// Could be private or non-existent
		info.IsPrivate = true // Assume private if 404 without auth
		return nil
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("GitHub API returned status %d", resp.StatusCode)
	}

	var ghRepo struct {
		Size          int64  `json:"size"` // KB
		Private       bool   `json:"private"`
		DefaultBranch string `json:"default_branch"`
		Description   string `json:"description"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&ghRepo); err != nil {
		return err
	}

	info.SizeKB = ghRepo.Size
	info.SizeBytes = ghRepo.Size * 1024
	info.IsPrivate = ghRepo.Private
	info.DefaultRef = ghRepo.DefaultBranch
	info.Description = ghRepo.Description

	return nil
}

// CheckDiskSpace checks if there's enough free disk space
func (c *Checker) CheckDiskSpace(path string) (available int64, ok bool, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, false, err
	}

	available = int64(stat.Bavail) * int64(stat.Bsize)
	ok = available >= c.config.MinFreeDiskBytes

	return available, ok, nil
}

// CheckRepoSize checks if repo size is within limits
func (c *Checker) CheckRepoSize(info *RepoInfo) (ok bool, reason string) {
	if info.SizeKB == 0 {
		// Unknown size, allow with warning
		return true, ""
	}

	if info.SizeKB > c.config.MaxRepoSizeKB {
		sizeMB := info.SizeKB / 1024
		maxMB := c.config.MaxRepoSizeKB / 1024
		return false, fmt.Sprintf("Repository too large (%dMB > %dMB limit)", sizeMB, maxMB)
	}

	return true, ""
}

// FormatSize formats bytes as human-readable string
func FormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1fGB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1fMB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1fKB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%dB", bytes)
	}
}
