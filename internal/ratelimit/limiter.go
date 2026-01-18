package ratelimit

import (
	"fmt"
	"time"

	"github.com/baocin/gitscan/internal/db"
)

// Limiter handles rate limiting based on IP and SSH key
type Limiter struct {
	db *db.DB

	// Per-IP limits
	ipPerMinute int
	ipPerHour   int

	// Per-SSH key limits
	sshPerMinute int

	// Per-IP per-repo limits
	ipRepoPerMinute int
}

// Config holds rate limiter configuration
type Config struct {
	IPPerMinute     int
	IPPerHour       int
	SSHPerMinute    int
	IPRepoPerMinute int
}

// DefaultConfig returns default rate limiter configuration
func DefaultConfig() Config {
	return Config{
		IPPerMinute:     30,
		IPPerHour:       200,
		SSHPerMinute:    60,
		IPRepoPerMinute: 10,
	}
}

// New creates a new rate limiter
func New(database *db.DB, cfg Config) *Limiter {
	return &Limiter{
		db:              database,
		ipPerMinute:     cfg.IPPerMinute,
		ipPerHour:       cfg.IPPerHour,
		sshPerMinute:    cfg.SSHPerMinute,
		ipRepoPerMinute: cfg.IPRepoPerMinute,
	}
}

// Allow checks if a request should be allowed
// Returns (allowed, message) where message explains the denial if not allowed
func (l *Limiter) Allow(ip, repoURL string) (bool, string) {
	return l.AllowWithSSH(ip, "", repoURL)
}

// IsIPBanned checks if an IP is currently banned
func (l *Limiter) IsIPBanned(ip string) (bool, string) {
	banned, reason, err := l.db.IsIPBanned(ip)
	if err != nil {
		return false, ""
	}
	return banned, reason
}

// AllowWithSSH checks if a request should be allowed, considering SSH key
func (l *Limiter) AllowWithSSH(ip, sshFingerprint, repoURL string) (bool, string) {
	// Check per-IP per-minute limit
	count, err := l.db.CountRecentRequestsByIP(ip, time.Minute)
	if err == nil && count >= l.ipPerMinute {
		return false, fmt.Sprintf("Rate limit exceeded: %d requests per minute (limit: %d)", count, l.ipPerMinute)
	}

	// Check per-IP per-hour limit
	count, err = l.db.CountRecentRequestsByIP(ip, time.Hour)
	if err == nil && count >= l.ipPerHour {
		return false, fmt.Sprintf("Rate limit exceeded: %d requests per hour (limit: %d)", count, l.ipPerHour)
	}

	// Check per-IP per-repo limit
	count, err = l.db.CountRecentRequestsByIPAndRepo(ip, repoURL, time.Minute)
	if err == nil && count >= l.ipRepoPerMinute {
		return false, fmt.Sprintf("Rate limit exceeded for this repository: %d requests per minute (limit: %d)", count, l.ipRepoPerMinute)
	}

	// Check SSH key limit if provided
	if sshFingerprint != "" {
		count, err = l.db.CountRecentRequestsBySSHKey(sshFingerprint, time.Minute)
		if err == nil && count >= l.sshPerMinute {
			return false, fmt.Sprintf("Rate limit exceeded for SSH key: %d requests per minute (limit: %d)", count, l.sshPerMinute)
		}
	}

	return true, ""
}

// RemainingRequests returns the remaining requests for an IP
func (l *Limiter) RemainingRequests(ip string) (perMinute, perHour int) {
	countMinute, _ := l.db.CountRecentRequestsByIP(ip, time.Minute)
	countHour, _ := l.db.CountRecentRequestsByIP(ip, time.Hour)

	perMinute = l.ipPerMinute - countMinute
	if perMinute < 0 {
		perMinute = 0
	}

	perHour = l.ipPerHour - countHour
	if perHour < 0 {
		perHour = 0
	}

	return
}

// ResetTime returns when the rate limit will reset for an IP
func (l *Limiter) ResetTime(ip string) time.Time {
	// Simple approximation: reset in 1 minute
	return time.Now().Add(time.Minute)
}
