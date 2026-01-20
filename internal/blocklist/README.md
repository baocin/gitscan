# Blocklist Package

Reusable threat intelligence blocklist library for blocking malicious IPs based on community threat feeds.

## Features

- **Multiple Threat Sources**: Spamhaus DROP/EDROP, Feodo Tracker, abuse.ch URLhaus
- **Auto-updating**: Periodic background updates with configurable intervals
- **CIDR Support**: Handles both individual IPs and CIDR ranges
- **Fast Lookups**: In-memory cache with database persistence
- **Format Agnostic**: Supports multiple blocklist formats (plain IP, CIDR, Spamhaus, CSV)

## Quick Start

```go
import "github.com/baocin/gitscan/internal/blocklist"

// Create manager with default config
cfg := blocklist.DefaultConfig()
manager := blocklist.New(database, cfg)

// Load from database
ctx := context.Background()
manager.LoadFromDatabase(ctx)

// Start auto-updates in background
go manager.StartAutoUpdates(ctx)

// Check if an IP is blocked
blocked, source, reason := manager.IsBlocked("1.2.3.4")
if blocked {
    log.Printf("IP blocked by %s: %s", source, reason)
}
```

## Configuration

```go
type Config struct {
    Enabled        bool          // Enable/disable blocklist
    UpdateInterval time.Duration // How often to update feeds
    FetchTimeout   time.Duration // HTTP timeout for fetching
    Sources        []Source      // List of threat feeds
}
```

### Default Configuration

- **Enabled**: true
- **Update Interval**: 12 hours
- **Fetch Timeout**: 30 seconds
- **Sources**: Spamhaus DROP, Spamhaus EDROP, Feodo Tracker, URLhaus

## Threat Intelligence Sources

### 1. Spamhaus DROP (Don't Route Or Peer)
- **URL**: https://www.spamhaus.org/drop/drop.txt
- **Type**: CIDR blocks of known hostile networks
- **Count**: ~1,400 CIDR ranges
- **Update**: Daily
- **Format**: Spamhaus custom format

### 2. Feodo Tracker
- **URL**: https://feodotracker.abuse.ch/downloads/ipblocklist.txt
- **Type**: Botnet C&C server IPs (Dridex, TrickBot, QakBot, Emotet, BazarLoader)
- **Count**: ~6 IPs (active botnets only)
- **Update**: Every 6 hours
- **Format**: Plain IP list

### 3. Emerging Threats Compromised IPs
- **URL**: https://rules.emergingthreats.net/blockrules/compromised-ips.txt
- **Type**: Known compromised/infected hosts
- **Count**: ~500 IPs
- **Update**: Every 12 hours
- **Format**: Plain IP list

### 4. CI Army Bad Guys
- **URL**: https://cinsscore.com/list/ci-badguys.txt
- **Type**: Collective Intelligence Network Security malicious IPs
- **Count**: ~15,000 IPs
- **Update**: Every 12 hours
- **Format**: Plain IP list

## Architecture

### Package Structure

```
internal/blocklist/
├── blocklist.go       # Main API and manager
├── fetcher.go         # HTTP fetching with retry logic
├── parser.go          # Parse various blocklist formats
├── sources.go         # Threat feed definitions
├── blocklist_test.go  # Unit tests
└── README.md          # This file
```

### Data Flow

1. **Fetch**: Download blocklists from threat feeds (HTTP)
2. **Parse**: Convert different formats into unified Entry structure
3. **Store**: Save to database for persistence
4. **Load**: Build in-memory cache from database
5. **Check**: Fast in-memory lookup for IP matching

## API Reference

### Manager

```go
type Manager struct { }

// Create new manager
func New(db *db.DB, config Config) *Manager

// Check if IP is blocked
func (m *Manager) IsBlocked(ip string) (blocked bool, source string, reason string)

// Load entries from database into memory
func (m *Manager) LoadFromDatabase(ctx context.Context) error

// Update all enabled feeds
func (m *Manager) UpdateFeeds(ctx context.Context) error

// Start automatic periodic updates
func (m *Manager) StartAutoUpdates(ctx context.Context)

// Get statistics
func (m *Manager) GetStats() Stats
```

### Entry

```go
type Entry struct {
    IP     string        // IP address or CIDR (e.g., "1.2.3.4/32" or "10.0.0.0/8")
    CIDR   *net.IPNet    // Parsed CIDR block
    Reason string        // Why this IP/range is blocked
    Source SourceType    // Which feed it came from
}
```

### Stats

```go
type Stats struct {
    TotalEntries   int            // Total IPs + CIDRs
    TotalCIDRs     int            // Number of CIDR blocks
    TotalExactIPs  int            // Number of exact IP matches
    SourceCounts   map[string]int // Entries per source
    Loaded         bool           // Whether data is loaded
}
```

## Database Schema

```sql
CREATE TABLE blocklist_ips (
    ip TEXT NOT NULL,
    source TEXT NOT NULL,
    reason TEXT,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (ip, source)
);
```

## Performance

- **In-memory cache**: O(1) for exact IP matches, O(n) for CIDR checks
- **Database storage**: Persistent across restarts
- **Concurrent fetching**: All sources fetched in parallel
- **Total entries**: ~16,900 (1,400 CIDRs + 15,500 IPs)
- **Download size**: ~500KB total per update
- **Typical load time**: < 150ms for ~16,900 entries
- **Memory usage**: ~3-5MB

## Example Integration

```go
// In middleware
func securityMiddleware(blocklistMgr *blocklist.Manager) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIP(r)

        // Check blocklist
        if blocked, source, reason := blocklistMgr.IsBlocked(clientIP); blocked {
            log.Printf("[BLOCKLIST] Rejected %s from %s: %s", clientIP, source, reason)
            http.Error(w, "Forbidden", http.StatusForbidden)
            return
        }

        // Continue...
    })
}
```

## Command Line Flags

When using with `gitscan-server`:

```bash
# Enable blocklist (default: true)
--enable-blocklist=true

# Update interval in hours (default: 12)
--blocklist-update-hours=12
```

## Adding Custom Sources

```go
customSource := blocklist.Source{
    Type:           "custom-feed",
    Name:           "My Custom Feed",
    URL:            "https://example.com/blocklist.txt",
    Format:         blocklist.FormatPlainIP,
    Description:    "Custom threat feed",
    UpdateInterval: 6 * time.Hour,
    Enabled:        true,
}

cfg := blocklist.DefaultConfig()
cfg.Sources = append(cfg.Sources, customSource)
```

## Testing

```bash
go test ./internal/blocklist/...
```

## License

Same as parent project.

## Contributing

This is a defensive security tool. Only threat intelligence sources and security improvements are accepted. No offensive capabilities.
