package preflight

import (
	"fmt"
	"strings"
	"syscall"
)

// RepoInfo contains pre-clone repository metadata
type RepoInfo struct {
	Host     string // github.com, gitlab.com, bitbucket.org
	Owner    string
	Name     string
	FullName string // host/owner/repo
	RepoPath string // owner/repo (for backward compat)
}

// Config holds preflight check configuration
type Config struct {
	MaxTransferBytes int64 // Maximum bytes to transfer during clone (default: 500MB)
	MinFreeDiskBytes int64 // Minimum free disk space required (default: 1GB)
}

// DefaultConfig returns default preflight configuration
func DefaultConfig() Config {
	return Config{
		MaxTransferBytes: 500 * 1024 * 1024, // 500MB
		MinFreeDiskBytes: 1 << 30,           // 1GB
	}
}

// Checker performs preflight checks before cloning
type Checker struct {
	config Config
}

// NewChecker creates a new preflight checker
func NewChecker(config Config) *Checker {
	return &Checker{
		config: config,
	}
}

// ParseRepoInfo parses repository info from path components
func (c *Checker) ParseRepoInfo(host, owner, repo string) *RepoInfo {
	return &RepoInfo{
		Host:     host,
		Owner:    owner,
		Name:     repo,
		FullName: fmt.Sprintf("%s/%s/%s", host, owner, repo),
		RepoPath: fmt.Sprintf("%s/%s", owner, repo),
	}
}

// ParseRepoPath parses a full path like "github.com/owner/repo" into RepoInfo
func (c *Checker) ParseRepoPath(fullPath string) (*RepoInfo, error) {
	parts := strings.SplitN(fullPath, "/", 3)
	if len(parts) < 3 {
		return nil, fmt.Errorf("invalid repository path: %s (expected host/owner/repo)", fullPath)
	}
	return c.ParseRepoInfo(parts[0], parts[1], parts[2]), nil
}

// GetMaxTransferBytes returns the configured maximum transfer size
func (c *Checker) GetMaxTransferBytes() int64 {
	return c.config.MaxTransferBytes
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
