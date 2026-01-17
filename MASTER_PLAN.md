# GitScan Master Plan

> **Zero-install security scanning for git repositories via protocol-level integration**

## Overview

GitScan is a security scanning tool that works with standard `git clone` commands - no installation required on the client. Users simply replace the git host with git.vet and include the original host in the path:

```bash
# Instead of:
git clone https://github.com/user/repo

# Use:
git clone https://git.vet/github.com/user/repo
```

Instead of cloning, they receive a security scan report displayed directly in their terminal.

---

## Core Concept: Git Protocol Sideband Abuse

### The Insight

Git's smart HTTP protocol includes a **sideband channel** for sending progress messages to the client. These appear as `remote: ...` lines during clone operations. By controlling the git server, we can:

1. Accept the clone request
2. Perform security scanning server-side
3. Stream scan progress via sideband messages
4. Display the final report
5. Intentionally fail the clone (report-only mode) OR complete it (scan + clone mode)

### Why This Works

- **Zero install**: Works with any standard git client
- **Universal**: macOS, Linux, Windows - anywhere git runs
- **No new commands**: Familiar `git clone` syntax
- **Streaming output**: Real-time progress during slow scans

### Limitations

- Server cannot detect client terminal capabilities (colors, width)
- Scanning happens server-side (privacy trade-off for convenience)
- Rate limiting required to prevent abuse

---

## User Experience

### Standard Flow (Report Only)

```
$ git clone https://git.vet/github.com/facebook/react
Cloning into 'react'...
remote:
remote: ⠋ [gitscan] Fetching repository...
remote: ⠙ [gitscan] Fetched. 142MB, 4,521 files
remote: ⠹ [gitscan] Scanning with opengrep...
remote: ⠸ [gitscan] Progress: 1,204 / 4,521 files (26%)
remote: ⠼ [gitscan] Progress: 3,102 / 4,521 files (68%)
remote: ✓ [gitscan] Scan complete!
remote:
remote: ╔══════════════════════════════════════════════════════════════════╗
remote: ║  GITSCAN SECURITY REPORT                                         ║
remote: ║  Repository: facebook/react                                      ║
remote: ║  Commit: a1b2c3d4e5f6                                            ║
remote: ║  Scanned: 4,521 files in 3.2s                                    ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  ✗ 0 Critical   ⚠ 2 High   ◆ 14 Medium   ○ 23 Low               ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║                                                                  ║
remote: ║  HIGH: Potential ReDoS vulnerability                             ║
remote: ║  └─ packages/react-dom/src/shared/sanitizeURL.js:42              ║
remote: ║                                                                  ║
remote: ║  HIGH: Unsafe innerHTML assignment                               ║
remote: ║  └─ fixtures/dom/src/components/Editor.js:156                    ║
remote: ║                                                                  ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  Full report: https://git.vet/r/fb-react-a1b2c3               ║
remote: ║  To clone: git clone https://github.com/facebook/react           ║
remote: ╚══════════════════════════════════════════════════════════════════╝
remote:
fatal: Could not read from remote repository.
```

### URL Variants

| URL Pattern | Behavior |
|-------------|----------|
| `git.vet/github.com/user/repo` | Scan and report (fail clone) |
| `git.vet/clone/github.com/user/repo` | Scan, report, then complete clone |
| `git.vet/plain/github.com/user/repo` | Report without box-drawing/unicode |
| `git.vet/json/github.com/user/repo` | Output raw JSON report |

### Supported Git Hosts

| Host | Path Format |
|------|-------------|
| GitHub | `git.vet/github.com/owner/repo` |
| GitLab | `git.vet/gitlab.com/owner/repo` |
| Bitbucket | `git.vet/bitbucket.org/owner/repo` |

---

## Advanced Features

### Client Disconnect Detection (Ctrl+C)

When a user presses Ctrl+C during a scan, the HTTP connection closes. We detect this via Go's `context.Done()` and immediately abort processing to save compute:

```go
select {
case <-ctx.Done():
    return // Client disconnected, abort
default:
    // Continue processing
}
```

This check is performed:
- Before starting preflight checks
- During repository fetch
- During scan execution
- Between each major step

### Private Repository Warning

When a private repo is detected (user provides authentication), we show a 10-second countdown warning:

```
$ git clone https://git.vet/github.com/user/private-repo
Cloning into 'private-repo'...
remote:
remote: ╔══════════════════════════════════════════════════════════════════╗
remote: ║  ⚠  PRIVATE REPOSITORY DETECTED                                  ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  Your private repository code will be analyzed on our servers.   ║
remote: ║  Code is deleted immediately after scanning.                     ║
remote: ║                                                                  ║
remote: ║  Press Ctrl+C now to cancel if you do not consent.               ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  Skip this delay: https://git.vet/pricing                     ║
remote: ╚══════════════════════════════════════════════════════════════════╝
remote:
remote: Starting scan in 10 seconds... (Ctrl+C to cancel)
remote: Starting scan in 9 seconds... (Ctrl+C to cancel)
...
```

- Paid users skip this delay
- Detects auth via `Authorization` header or URL credentials

### Preflight Checks

Before/during cloning, we perform resource checks:

1. **Disk Space**: Verify server has sufficient free space
2. **Data Transfer Limit**: Monitor clone progress, abort if >500MB transferred
3. **Rate Limits**: Check request quotas

**Why no API-based size check?**
- GitHub, GitLab, Bitbucket all have different APIs
- Unauthenticated API rate limits are very low (60 req/hour for GitHub)
- API-reported sizes are often inaccurate (doesn't include LFS, may be stale)

**Transfer-based limiting is better:**
```go
// Monitor git clone output and abort if too large
cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", repoURL, localPath)
// Wrap stdout/stderr to count bytes transferred
// Abort if threshold exceeded
```

This approach works universally across all git hosts without requiring API keys.

### Queue Management

Separate processing queues for public vs private repos:

| Queue | Concurrent Slots | Priority |
|-------|------------------|----------|
| Public (free) | 10 | Low |
| Private (free) | 3 | Normal |
| Paid tier | Dedicated | High |

This prevents free private repo scans from blocking public scans.

### Shallow Clone Optimization

Server always uses shallow clone to minimize disk and bandwidth:

```bash
git clone --depth 1 --single-branch --no-tags <repo>
```

This typically reduces clone time by 80-95% for repos with long history.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              gitscan server (Go)                                │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐    ┌────────────────────────────┐│
│  │  Git Smart HTTP  │    │   Repo Fetcher   │    │      Scanner Engine        ││
│  │     Handler      │───▶│                  │───▶│                            ││
│  │                  │    │ • Shallow clone  │    │  • Opengrep (LGPL 2.1)     ││
│  │ • Parse URL      │    │   (--depth=1)    │    │  • Custom rules            ││
│  │ • Rate limiting  │    │ • Full clone for │    │  • SARIF output            ││
│  │ • Sideband write │    │   historical     │    │                            ││
│  │ • Request logging│    │ • Disk cache     │    │                            ││
│  └──────────────────┘    └──────────────────┘    └────────────────────────────┘│
│          │                        │                          │                  │
│          │                        │                          │                  │
│          ▼                        ▼                          ▼                  │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                            SQLite Database                                │  │
│  │                                                                           │  │
│  │  repos          │  scans              │  requests                         │  │
│  │  ────────────── │  ─────────────────  │  ──────────────────────────────   │  │
│  │  id             │  id                 │  id                               │  │
│  │  url            │  repo_id            │  ip                               │  │
│  │  local_path     │  commit_sha         │  ssh_key_fingerprint              │  │
│  │  last_commit    │  results_json       │  user_agent                       │  │
│  │  last_fetched   │  critical_count     │  repo_url                         │  │
│  │  size_bytes     │  high_count         │  scan_id                          │  │
│  │  file_count     │  medium_count       │  response_time_ms                 │  │
│  │                 │  low_count          │  created_at                       │  │
│  │                 │  scan_duration_ms   │                                   │  │
│  │                 │  created_at         │                                   │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Component Responsibilities

#### Git Smart HTTP Handler
- Implements git smart HTTP protocol (just enough to accept connections)
- Parses incoming URLs to extract `owner/repo`
- Writes progress and results via sideband channel (band 2)
- Terminates connection appropriately based on mode

#### Repo Fetcher
- Clones repositories from GitHub (shallow by default: `--depth=1`)
- Caches repos on disk to avoid re-fetching
- Updates cached repos with `git fetch` when stale
- Tracks specific commits requested by clients

#### Scanner Engine
- Wraps opengrep binary for static analysis
- Streams progress back to handler
- Supports custom rule sets
- Outputs in SARIF format for consistency

#### SQLite Database
- Caches scan results per (repo, commit) pair
- Tracks all requests for rate limiting and analytics
- Stores repo metadata and cache state

---

## Database Schema

```sql
-- Cached repositories
CREATE TABLE repos (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,              -- github.com/user/repo
    local_path TEXT NOT NULL,              -- /var/cache/gitscan/repos/...
    default_branch TEXT,                   -- main, master, etc.
    last_commit_sha TEXT,
    last_fetched_at DATETIME,
    size_bytes INTEGER,
    file_count INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Scan results (cached per commit)
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repos(id),
    commit_sha TEXT NOT NULL,
    results_json TEXT NOT NULL,            -- Full opengrep SARIF output
    summary_json TEXT,                     -- Condensed findings
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    files_scanned INTEGER,
    scan_duration_ms INTEGER,
    opengrep_version TEXT,
    rules_version TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repo_id, commit_sha)
);

-- Request tracking (rate limiting + analytics)
CREATE TABLE requests (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    ssh_key_fingerprint TEXT,              -- Available for SSH connections
    user_agent TEXT,
    repo_url TEXT NOT NULL,
    commit_sha TEXT,
    request_mode TEXT,                     -- 'scan', 'clone', 'json', 'plain'
    scan_id INTEGER REFERENCES scans(id),  -- NULL if rate limited or error
    cache_hit BOOLEAN DEFAULT FALSE,
    response_time_ms INTEGER,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_repos_url ON repos(url);
CREATE INDEX idx_scans_repo_commit ON scans(repo_id, commit_sha);
CREATE INDEX idx_requests_ip_time ON requests(ip, created_at);
CREATE INDEX idx_requests_ssh_time ON requests(ssh_key_fingerprint, created_at)
    WHERE ssh_key_fingerprint IS NOT NULL;
CREATE INDEX idx_requests_repo_time ON requests(repo_url, created_at);
```

---

## Rate Limiting Strategy

### Identification Methods

| Connection Type | Identifier | Reliability |
|-----------------|------------|-------------|
| HTTPS (public repos) | IP address | Low (NAT, VPNs) |
| HTTPS (private repos) | Username/token | High |
| SSH | Public key fingerprint | High |

### Default Limits

| Scope | Limit | Window |
|-------|-------|--------|
| Per IP | 30 requests | 1 minute |
| Per IP | 200 requests | 1 hour |
| Per SSH key | 60 requests | 1 minute |
| Per (IP, repo) | 10 requests | 1 minute |

### Implementation

```sql
-- Check if IP is rate limited (per-minute)
SELECT COUNT(*) as cnt FROM requests
WHERE ip = ? AND created_at > datetime('now', '-1 minute');

-- Check if specific repo is being hammered by IP
SELECT COUNT(*) as cnt FROM requests
WHERE ip = ? AND repo_url = ? AND created_at > datetime('now', '-1 minute');
```

When rate limited, return a friendly sideband message:

```
remote:
remote: ⚠ [gitscan] Rate limit exceeded
remote:
remote: You've made too many requests. Please wait a moment.
remote: If you need higher limits, visit: https://git.vet/pricing
remote:
fatal: Could not read from remote repository.
```

---

## Scanner: Opengrep

### Why Opengrep

- **License**: LGPL 2.1 (engine AND rules) - safe for commercial SaaS use
- **Compatibility**: Drop-in replacement for semgrep
- **Community**: Backed by Aikido, Amplify, Orca, and others
- **Performance**: Fast enough for real-time scanning

References:
- https://www.opengrep.dev/
- https://github.com/opengrep/opengrep

### Integration Approach

```go
// scanner/opengrep.go

type Scanner struct {
    binaryPath   string
    rulesPath    string
    timeout      time.Duration
    progressChan chan Progress
}

type Progress struct {
    FilesScanned int
    FilesTotal   int
    Percent      int
}

type Results struct {
    Findings     []Finding
    CriticalCount int
    HighCount     int
    MediumCount   int
    LowCount      int
    Duration      time.Duration
}

func (s *Scanner) Scan(ctx context.Context, repoPath string) (*Results, error) {
    cmd := exec.CommandContext(ctx, s.binaryPath,
        "--config", s.rulesPath,
        "--json",
        "--metrics", "off",
        repoPath,
    )
    // ... parse output, stream progress
}
```

### Rule Categories

| Category | Description |
|----------|-------------|
| security | Vulnerabilities, injection, auth issues |
| secrets | API keys, passwords, tokens |
| crypto | Weak algorithms, hardcoded keys |
| injection | SQL, command, XSS, template injection |

---

## Streaming Progress

The git sideband protocol allows real-time streaming of messages. This is critical for large repos where scanning may take 10+ seconds.

### Sideband Protocol

```
Packet format: 4-byte hex length + 1-byte channel + payload

Channels:
  1 = pack data (actual git objects)
  2 = progress (displayed as "remote: ...")
  3 = error (displayed as "remote: ..." to stderr)
```

### Go Implementation

```go
// githttp/sideband.go

type SidebandWriter struct {
    w io.Writer
}

func (s *SidebandWriter) WriteProgress(msg string) error {
    return s.writeBand(2, msg+"\n")
}

func (s *SidebandWriter) WriteError(msg string) error {
    return s.writeBand(3, msg+"\n")
}

func (s *SidebandWriter) writeBand(band byte, data string) error {
    // pkt-line format: 4 hex digits length + band byte + data
    length := len(data) + 5 // 4 bytes length + 1 byte band
    pkt := fmt.Sprintf("%04x%c%s", length, band, data)
    _, err := s.w.Write([]byte(pkt))
    return err
}

// Flush packet (0000) signals end of stream
func (s *SidebandWriter) Flush() error {
    _, err := s.w.Write([]byte("0000"))
    return err
}
```

### Progress Animation

Since we can't detect terminal capabilities, we use universally-supported characters:

```go
var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

func (h *Handler) showProgress(sb *SidebandWriter, scanner *Scanner) {
    ticker := time.NewTicker(100 * time.Millisecond)
    frame := 0

    for {
        select {
        case progress := <-scanner.Progress():
            sb.WriteProgress(fmt.Sprintf("%s [gitscan] Scanning: %d/%d files (%d%%)",
                spinnerFrames[frame%len(spinnerFrames)],
                progress.Done, progress.Total, progress.Percent))
            frame++
        case <-ticker.C:
            // Keep spinner alive even without progress updates
            frame++
        case <-scanner.Done():
            return
        }
    }
}
```

---

## Terminal Output Formatting

### Character Sets

**Unicode mode (default):**
```
╔══════════════════════════════════════════════════════════════╗
║  GITSCAN SECURITY REPORT                                     ║
╠══════════════════════════════════════════════════════════════╣
║  ✗ 2 Critical   ⚠ 5 High   ◆ 12 Medium   ○ 23 Low           ║
╚══════════════════════════════════════════════════════════════╝
```

**Plain mode (`/plain/` URL):**
```
================================================================
  GITSCAN SECURITY REPORT
================================================================
  [X] 2 Critical   [!] 5 High   [*] 12 Medium   [-] 23 Low
================================================================
```

### Colors

ANSI colors are sent regardless of terminal (most support them):

```go
const (
    Reset   = "\033[0m"
    Red     = "\033[31m"
    Yellow  = "\033[33m"
    Green   = "\033[32m"
    Blue    = "\033[34m"
    Bold    = "\033[1m"
)

// Example usage
fmt.Sprintf("%s%s✗ 2 Critical%s", Bold, Red, Reset)
```

For `/plain/` mode, colors are stripped.

---

## Build & Test Strategy

### Multi-Stage Docker Build

The build process uses a two-phase approach:

1. **Builder Container**: Compiles Go binary, caches opengrep rules, runs unit tests
2. **Git Version Test Containers**: Use the built binary to verify compatibility across git versions

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 1: Builder (runs on every build)                                     │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  FROM golang:1.22 AS builder                                          │  │
│  │  • Download dependencies (cached layer)                               │  │
│  │  • Build Go binary                                                    │  │
│  │  • Run unit tests (go test ./...)                                     │  │
│  │  • Output: /gitscan binary                                            │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  FROM opengrep AS rules-cache                                         │  │
│  │  • Pull opengrep image (cached layer)                                 │  │
│  │  • Extract rules to /rules (cached layer)                             │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ artifacts: binary + rules
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 2: Git Version Test Matrix (runs in parallel)                        │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐        │
│  │ git 2.17    │  │ git 2.25    │  │ git 2.34    │  │ git 2.43    │  ...   │
│  │ (ubuntu     │  │ (ubuntu     │  │ (ubuntu     │  │ (ubuntu     │        │
│  │  18.04)     │  │  20.04)     │  │  22.04)     │  │  24.04)     │        │
│  ├─────────────┤  ├─────────────┤  ├─────────────┤  ├─────────────┤        │
│  │ COPY binary │  │ COPY binary │  │ COPY binary │  │ COPY binary │        │
│  │ COPY rules  │  │ COPY rules  │  │ COPY rules  │  │ COPY rules  │        │
│  │ RUN tests   │  │ RUN tests   │  │ RUN tests   │  │ RUN tests   │        │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘        │
│                                                                             │
│  Tests verify:                                                              │
│  • Server starts successfully                                               │
│  • git clone receives sideband messages                                     │
│  • Report formatting displays correctly                                     │
│  • Connection terminates as expected                                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ all tests pass
┌─────────────────────────────────────────────────────────────────────────────┐
│  STAGE 3: Production Image                                                  │
│  ┌───────────────────────────────────────────────────────────────────────┐  │
│  │  FROM alpine:latest                                                   │  │
│  │  COPY --from=builder /gitscan /usr/local/bin/                         │  │
│  │  COPY --from=rules-cache /rules /etc/gitscan/rules/                   │  │
│  │  COPY --from=opengrep /usr/local/bin/opengrep /usr/local/bin/         │  │
│  │  → Minimal production image (~50MB)                                   │  │
│  └───────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Git Version Test Matrix

| Git Version | Base Image | Source | Priority |
|-------------|------------|--------|----------|
| 2.17.x | ubuntu:18.04 | Ubuntu 18.04 LTS | High |
| 2.25.x | ubuntu:20.04 | Ubuntu 20.04 LTS | High |
| 2.34.x | ubuntu:22.04 | Ubuntu 22.04 LTS | High |
| 2.39.x | alpine + git | macOS Xcode CLT equivalent | High |
| 2.43.x | ubuntu:24.04 | Ubuntu 24.04 LTS | High |
| 2.52.x | alpine + git@edge | Latest release | Medium |

### Dockerfile Structure

```dockerfile
# docker/Dockerfile

# ============================================================================
# Stage 1: Build the Go binary
# ============================================================================
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -o /gitscan ./cmd/gitscan-server
RUN go test ./...

# ============================================================================
# Stage 2: Cache opengrep and rules
# ============================================================================
FROM ghcr.io/opengrep/opengrep:latest AS opengrep-cache

# Rules are already in the image at /rules or similar
# We just use this stage to copy from later

# ============================================================================
# Stage 3: Production image
# ============================================================================
FROM alpine:latest AS production

RUN apk add --no-cache git ca-certificates

COPY --from=builder /gitscan /usr/local/bin/gitscan
COPY --from=opengrep-cache /usr/local/bin/opengrep /usr/local/bin/opengrep
# COPY --from=opengrep-cache /rules /etc/gitscan/rules

EXPOSE 8080 8443
ENTRYPOINT ["/usr/local/bin/gitscan"]
```

### Git Version Test Container Template

```dockerfile
# docker/git-test/Dockerfile.template
# Built with: --build-arg GIT_IMAGE=ubuntu:22.04

ARG GIT_IMAGE=ubuntu:22.04
FROM ${GIT_IMAGE} AS git-test

# Install git (method varies by base image)
RUN apt-get update && apt-get install -y git curl || \
    apk add --no-cache git curl

# Copy built artifacts from builder
COPY --from=builder /gitscan /usr/local/bin/gitscan
COPY --from=opengrep-cache /usr/local/bin/opengrep /usr/local/bin/opengrep

# Copy test script
COPY test/git-compat-test.sh /test.sh
RUN chmod +x /test.sh

# Run tests at build time
RUN /test.sh
```

### docker-compose.test.yml

```yaml
version: '3.8'

services:
  # Builder service - compiles and runs unit tests
  builder:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: builder
    volumes:
      - build-artifacts:/artifacts
    command: >
      sh -c "cp /gitscan /artifacts/ && echo 'Build complete'"

  # Git version test services - run in parallel
  test-git-2.17:
    build:
      context: .
      dockerfile: docker/git-test/Dockerfile
      args:
        GIT_IMAGE: ubuntu:18.04
    depends_on:
      - builder
    network_mode: "service:gitscan-server"

  test-git-2.25:
    build:
      context: .
      dockerfile: docker/git-test/Dockerfile
      args:
        GIT_IMAGE: ubuntu:20.04
    depends_on:
      - builder

  test-git-2.34:
    build:
      context: .
      dockerfile: docker/git-test/Dockerfile
      args:
        GIT_IMAGE: ubuntu:22.04
    depends_on:
      - builder

  test-git-2.43:
    build:
      context: .
      dockerfile: docker/git-test/Dockerfile
      args:
        GIT_IMAGE: ubuntu:24.04
    depends_on:
      - builder

  test-git-latest:
    build:
      context: .
      dockerfile: docker/git-test/Dockerfile
      args:
        GIT_IMAGE: alpine:edge
    depends_on:
      - builder

  # Server for integration tests
  gitscan-server:
    build:
      context: .
      dockerfile: docker/Dockerfile
      target: production
    depends_on:
      - builder
    ports:
      - "8080:8080"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 5s
      timeout: 3s
      retries: 3

volumes:
  build-artifacts:
```

### Build Commands

```bash
# Full build with all tests (CI/CD)
docker compose -f docker-compose.test.yml build

# Build only (skip git version tests for local dev)
docker build --target production -t gitscan:latest .

# Run specific git version test
docker compose -f docker-compose.test.yml build test-git-2.43

# Run all tests in parallel
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit
```

---

## Project Structure

```
gitscan/
├── cmd/
│   └── gitscan-server/
│       └── main.go                 # Entry point
├── internal/
│   ├── githttp/
│   │   ├── handler.go              # HTTP handler for git requests
│   │   ├── sideband.go             # Sideband message writer
│   │   ├── protocol.go             # Git protocol parsing
│   │   └── report.go               # Report formatting
│   ├── scanner/
│   │   ├── opengrep.go             # Opengrep wrapper
│   │   ├── progress.go             # Progress tracking
│   │   └── rules/                  # Custom rule definitions
│   │       └── default.yaml
│   ├── cache/
│   │   ├── repo.go                 # Repository fetching/caching
│   │   └── manager.go              # Cache eviction, cleanup
│   ├── db/
│   │   ├── db.go                   # SQLite connection
│   │   ├── schema.sql              # Schema definitions
│   │   ├── repos.go                # Repo queries
│   │   ├── scans.go                # Scan queries
│   │   └── requests.go             # Request logging/rate limit queries
│   └── ratelimit/
│       └── limiter.go              # Rate limiting logic
├── docker/
│   ├── Dockerfile                  # Production image
│   ├── Dockerfile.dev              # Development image
│   └── git-versions/               # Test containers
│       ├── git-2.17.Dockerfile
│       ├── git-2.25.Dockerfile
│       ├── git-2.34.Dockerfile
│       ├── git-2.39.Dockerfile
│       ├── git-2.43.Dockerfile
│       └── git-2.52.Dockerfile
├── test/
│   ├── git-compat.sh               # Git version compatibility tests
│   ├── integration_test.go         # Integration tests
│   └── fixtures/                   # Test repositories
├── scripts/
│   ├── build.sh                    # Build script
│   └── deploy.sh                   # Hetzner deployment
├── docker-compose.yml              # Local development
├── go.mod
├── go.sum
├── MASTER_PLAN.md                  # This document
└── README.md
```

---

## Deployment: Hetzner

### Server Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 vCPU | 4 vCPU |
| RAM | 4 GB | 8 GB |
| Disk | 100 GB SSD | 250 GB SSD |
| Network | 1 Gbps | 1 Gbps |

### Recommended Hetzner Products

- **CPX31** (4 vCPU, 8 GB RAM, 160 GB) - ~€15/month
- **Storage Box** for repo cache overflow - optional

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Hetzner Cloud                           │
│  ┌───────────────────────────────────────────────────────┐ │
│  │                    CPX31 VM                            │ │
│  │  ┌─────────────────────────────────────────────────┐  │ │
│  │  │              Docker Compose                      │  │ │
│  │  │  ┌─────────────────┐  ┌─────────────────────┐   │  │ │
│  │  │  │  gitscan-server │  │     opengrep        │   │  │ │
│  │  │  │    (Go app)     │──│    (scanner)        │   │  │ │
│  │  │  └─────────────────┘  └─────────────────────┘   │  │ │
│  │  │           │                                      │  │ │
│  │  │           ▼                                      │  │ │
│  │  │  ┌─────────────────────────────────────────┐    │  │ │
│  │  │  │            Volumes                       │    │  │ │
│  │  │  │  /data/sqlite   - Database               │    │  │ │
│  │  │  │  /data/repos    - Cached repositories    │    │  │ │
│  │  │  └─────────────────────────────────────────┘    │  │ │
│  │  └─────────────────────────────────────────────────┘  │ │
│  └───────────────────────────────────────────────────────┘ │
│                            │                                │
│                    Hetzner Firewall                        │
│                    - Allow 443 (HTTPS)                     │
│                    - Allow 22 (SSH from admin IP)          │
└─────────────────────────────────────────────────────────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   Cloudflare    │
                    │   (DNS + CDN)   │
                    │                 │
                    │ git.vet → Hetzner IP
                    └─────────────────┘
```

### docker-compose.yml

```yaml
version: '3.8'

services:
  gitscan:
    build: .
    ports:
      - "443:8443"
      - "80:8080"   # Redirect to HTTPS
    volumes:
      - ./data/sqlite:/data/sqlite
      - ./data/repos:/data/repos
      - ./certs:/certs:ro
    environment:
      - GITSCAN_DB_PATH=/data/sqlite/gitscan.db
      - GITSCAN_REPO_CACHE_PATH=/data/repos
      - GITSCAN_TLS_CERT=/certs/cert.pem
      - GITSCAN_TLS_KEY=/certs/key.pem
    restart: unless-stopped

  opengrep:
    image: ghcr.io/opengrep/opengrep:latest
    volumes:
      - ./data/repos:/repos:ro
      - ./rules:/rules:ro
```

---

## Security Considerations

### Input Validation

- Sanitize repository URLs (prevent path traversal, injection)
- Validate URL format: `^[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+$`
- Reject URLs with suspicious patterns

### Resource Limits

- Maximum repo size: 500 MB (configurable)
- Maximum files to scan: 100,000
- Scan timeout: 60 seconds
- Clone timeout: 120 seconds

### Isolation

- Each scan runs in isolated temp directory
- Consider gVisor/Firecracker for repo cloning (defense in depth)
- Opengrep runs with limited permissions

### Network

- TLS required for all connections
- No outbound network from scanner container
- Firewall: only 443 exposed

---

## Future Enhancements

### Phase 2
- [ ] Private repository support (GitHub App OAuth)
- [ ] GitLab and Bitbucket support
- [ ] Custom rule upload via web UI
- [ ] Webhook notifications

### Phase 3
- [ ] PR comment integration (gitscan as GitHub Action)
- [ ] Historical trend tracking
- [ ] Organization dashboards
- [ ] API for CI/CD integration

### Phase 4
- [ ] Self-hosted option (Docker image)
- [ ] IDE extensions (VS Code, JetBrains)
- [ ] Dependency scanning (SCA)
- [ ] License compliance checking

---

## Open Questions

1. **Pricing**: Free tier limits? Paid tiers for higher rate limits?
2. **Private repos**: OAuth flow complexity - worth it for v1?
3. **Clone mode**: Should we support actually completing the clone after scan?

---

## References

- [Git Protocol Documentation](https://git-scm.com/docs/protocol-v2)
- [Git Smart HTTP Protocol](https://www.git-scm.com/docs/http-protocol)
- [Opengrep](https://www.opengrep.dev/)
- [Semgrep Licensing Changes](https://semgrep.dev/blog/2024/important-updates-to-semgrep-oss/)
- [Opengrep Fork Announcement](https://www.infoq.com/news/2025/02/semgrep-forked-opengrep/)
