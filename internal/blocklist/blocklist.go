package blocklist

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/baocin/gitscan/internal/db"
)

// Manager manages threat intelligence blocklists
type Manager struct {
	db             *db.DB
	fetcher        *Fetcher
	sources        []Source
	updateInterval time.Duration

	// In-memory cache for fast lookups
	mu     sync.RWMutex
	cidrs  map[SourceType][]*net.IPNet
	ipMap  map[string]BlocklistMatch // Quick lookup for exact IPs
	loaded bool
}

// BlocklistMatch represents a blocklist match
type BlocklistMatch struct {
	IP     string
	Source SourceType
	Reason string
}

// Config holds blocklist manager configuration
type Config struct {
	Enabled        bool
	UpdateInterval time.Duration
	FetchTimeout   time.Duration
	Sources        []Source
}

// DefaultConfig returns default blocklist configuration
func DefaultConfig() Config {
	return Config{
		Enabled:        true,
		UpdateInterval: 12 * time.Hour,
		FetchTimeout:   30 * time.Second,
		Sources:        DefaultSources(),
	}
}

// New creates a new blocklist manager
func New(database *db.DB, config Config) *Manager {
	return &Manager{
		db:             database,
		fetcher:        NewFetcher(config.FetchTimeout),
		sources:        config.Sources,
		updateInterval: config.UpdateInterval,
		cidrs:          make(map[SourceType][]*net.IPNet),
		ipMap:          make(map[string]BlocklistMatch),
	}
}

// IsBlocked checks if an IP is blocklisted
// Returns (blocked, source, reason)
func (m *Manager) IsBlocked(ip string) (bool, string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Quick exact match lookup
	if match, ok := m.ipMap[ip]; ok {
		return true, string(match.Source), match.Reason
	}

	// Parse IP for CIDR matching
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false, "", ""
	}

	// Check all CIDR blocks
	for sourceType, cidrs := range m.cidrs {
		for _, cidr := range cidrs {
			if cidr.Contains(parsedIP) {
				return true, string(sourceType), fmt.Sprintf("Blocklisted by %s", sourceType)
			}
		}
	}

	return false, "", ""
}

// LoadFromDatabase loads blocklist entries from the database into memory
func (m *Manager) LoadFromDatabase(ctx context.Context) error {
	entries, err := m.db.GetAllBlocklistEntries()
	if err != nil {
		return fmt.Errorf("failed to load blocklist from database: %w", err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Clear existing data
	m.cidrs = make(map[SourceType][]*net.IPNet)
	m.ipMap = make(map[string]BlocklistMatch)

	// Build in-memory cache
	for _, entry := range entries {
		source := SourceType(entry.Source)

		// Parse as CIDR
		_, ipnet, err := net.ParseCIDR(entry.IP)
		if err != nil {
			// Try as plain IP
			parsedIP := net.ParseIP(entry.IP)
			if parsedIP != nil {
				// Store as exact match
				m.ipMap[entry.IP] = BlocklistMatch{
					IP:     entry.IP,
					Source: source,
					Reason: entry.Reason,
				}
			}
			continue
		}

		// Store CIDR
		m.cidrs[source] = append(m.cidrs[source], ipnet)
	}

	m.loaded = true
	log.Printf("[blocklist] Loaded %d entries from database (%d CIDRs, %d exact IPs)",
		len(entries), m.countCIDRs(), len(m.ipMap))

	return nil
}

// UpdateFeeds fetches and updates all enabled blocklist sources
func (m *Manager) UpdateFeeds(ctx context.Context) error {
	enabledSources := EnabledSources(m.sources)
	if len(enabledSources) == 0 {
		return nil
	}

	log.Printf("[blocklist] Updating %d blocklist sources...", len(enabledSources))

	// Fetch all sources concurrently
	results := m.fetcher.FetchAll(ctx, enabledSources)

	// Process results
	totalEntries := 0
	errors := 0

	for sourceType, result := range results {
		if result.Error != nil {
			log.Printf("[blocklist] Failed to fetch %s: %v", sourceType, result.Error)
			errors++
			continue
		}

		// Convert entries to database format
		dbEntries := make([]db.BlocklistEntry, len(result.Entries))
		for i, entry := range result.Entries {
			dbEntries[i] = db.BlocklistEntry{
				IP:     entry.IP,
				Source: string(entry.Source),
				Reason: entry.Reason,
			}
		}

		// Store entries in database
		if err := m.db.UpdateBlocklistEntries(string(sourceType), dbEntries); err != nil {
			log.Printf("[blocklist] Failed to store %s entries: %v", sourceType, err)
			errors++
			continue
		}

		totalEntries += len(result.Entries)
		log.Printf("[blocklist] Updated %s: %d entries", sourceType, len(result.Entries))
	}

	// Reload from database
	if err := m.LoadFromDatabase(ctx); err != nil {
		return fmt.Errorf("failed to reload after update: %w", err)
	}

	if errors > 0 {
		return fmt.Errorf("failed to update %d/%d sources", errors, len(enabledSources))
	}

	log.Printf("[blocklist] Update complete: %d total entries", totalEntries)
	return nil
}

// StartAutoUpdates starts automatic periodic updates
func (m *Manager) StartAutoUpdates(ctx context.Context) {
	// Initial update
	if err := m.UpdateFeeds(ctx); err != nil {
		log.Printf("[blocklist] Initial update failed: %v", err)
	}

	// Periodic updates
	ticker := time.NewTicker(m.updateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := m.UpdateFeeds(ctx); err != nil {
				log.Printf("[blocklist] Periodic update failed: %v", err)
			}
		case <-ctx.Done():
			log.Printf("[blocklist] Auto-update stopped")
			return
		}
	}
}

// Stats returns blocklist statistics
type Stats struct {
	TotalEntries   int
	TotalCIDRs     int
	TotalExactIPs  int
	SourceCounts   map[string]int
	LastUpdateTime time.Time
	Loaded         bool
}

// GetStats returns current blocklist statistics
func (m *Manager) GetStats() Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	sourceCounts := make(map[string]int)
	for sourceType, cidrs := range m.cidrs {
		sourceCounts[string(sourceType)] = len(cidrs)
	}

	return Stats{
		TotalEntries:  m.countCIDRs() + len(m.ipMap),
		TotalCIDRs:    m.countCIDRs(),
		TotalExactIPs: len(m.ipMap),
		SourceCounts:  sourceCounts,
		Loaded:        m.loaded,
	}
}

// countCIDRs counts total CIDR blocks across all sources
func (m *Manager) countCIDRs() int {
	count := 0
	for _, cidrs := range m.cidrs {
		count += len(cidrs)
	}
	return count
}

// IsLoaded returns whether the blocklist has been loaded
func (m *Manager) IsLoaded() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.loaded
}
