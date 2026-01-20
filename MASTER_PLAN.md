# git.vet Master Plan

> **Zero-install security scanning for git repositories via protocol-level integration**

## Overview

git.vet is a security scanning tool that works with standard `git clone` commands - no installation required on the client. Users simply replace the git host with git.vet and include the original host in the path:

```bash
# Instead of:
git clone https://github.com/user/repo

# Use:
git clone https://git.vet/github.com/user/repo
```

Instead of cloning, they receive a security scan report displayed directly in their terminal.

### Core Philosophy: Credential Theft Detection First

**The primary question git.vet answers: "Will this tool steal my local credentials?"**

Unlike traditional vulnerability scanners that prioritize CVEs and code quality issues, git.vet is built around a paranoid security model focused on **local credential theft detection**. When evaluating any repository, the hierarchy of concerns is:

1. **🚨 CRITICAL - Credential Theft Behaviors** (highest priority)
   - Reading `.aws/credentials`, `.aws/config`
   - Accessing `~/.ssh/` directory (private keys, known_hosts)
   - Exfiltrating `.env` files or environment variables
   - Stealing browser cookies/sessions
   - Reading password managers or keychains
   - POST requests with sensitive local file contents

2. **🔴 HIGH - Malicious Code Patterns**
   - Encoded/obfuscated payloads (base64 decoded exec)
   - Network exfiltration to hardcoded IPs/domains
   - Process injection or persistence mechanisms
   - Suspicious curl/wget piped to shell

3. **🟠 MEDIUM - Traditional Vulnerabilities**
   - CVEs in dependencies
   - SQL injection, XSS, command injection
   - Insecure cryptography

4. **🟡 LOW - Code Quality Issues**
   - Deprecated APIs
   - Missing input validation
   - Code smells

This inverted priority model reflects the real-world threat: users clone repos to run locally, and the biggest risk is immediate credential exfiltration—not theoretical vulnerabilities that require specific conditions to exploit.

### Current Implementation Status

| Feature | Status | Location |
|---------|--------|----------|
| Git Smart HTTP Protocol | ✅ Done | `internal/githttp/` |
| Opengrep/Semgrep Integration | ✅ Done | `internal/scanner/` |
| SARIF Output Parsing | ✅ Done | `internal/scanner/scanner.go` |
| Terminal Report (Sideband) | ✅ Done | `internal/githttp/handler.go` (80-char width, critical-first sorting) |
| Web Report Page | ✅ Done | `web/templates/report.html` (critical-first sorting) |
| QR Code Generation | ✅ Done | `internal/githttp/qrcode.go` (High recovery, full blocks) |
| License Detection | ✅ Done | `internal/license/license.go` |
| Rate Limiting | ✅ Done | `internal/ratelimit/limiter.go` |
| Repository Caching | ✅ Done | `internal/cache/cache.go` |
| SQLite Database | ✅ Done | `internal/db/` |
| Docker Image | ✅ Done | `docker/Dockerfile` |
| Unit Tests | ✅ Done | `*_test.go` files |
| GitHub Actions CI | ✅ Done | `.github/workflows/test.yml` |
| Marketing Homepage | ✅ Done | `web/templates/index.html` |
| Pricing Page | ✅ Done | `web/templates/pricing.html` |
| Security Score (0-100) | ✅ Done | `internal/scanner/scanner.go` |
| Invalid Repo Error Handling | ✅ Done | `internal/cache/cache.go`, `internal/githttp/handler.go` |

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
$ git clone https://git.vet/github.com/baocin/known-malicious-repo
Cloning into 'known-malicious-repo'...
remote:
remote: [git.vet] Running preflight checks...
remote: [git.vet] Preflight OK
remote: ⠋ [git.vet] Fetching from github.com...
remote: ✓ [git.vet] Repository fetched
remote: ⠙ [git.vet] Scanning for vulnerabilities...
remote: ✓ [git.vet] Scan complete!
remote:
remote: ╔══════════════════════════════════════════════════════════════════╗
remote: ║ ⚠ RUN RISK: 100/100 (F) - DO NOT RUN THIS CODE                  ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║ 🚨 26 Critical    ⚠ 0 High    ℹ 4 Medium    - 0 Low              ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║                                                                  ║
remote: ║  CRITICAL: Malicious npm postinstall hook                        ║
remote: ║  └─ package.json:7                                               ║
remote: ║                                                                  ║
remote: ║  CRITICAL: Shell script accessing SSH private keys               ║
remote: ║  └─ scripts/steal_ssh.sh:10                                      ║
remote: ║                                                                  ║
remote: ║  CRITICAL: Python script exfiltrating environment variables      ║
remote: ║  └─ setup.py:52                                                  ║
remote: ║                                                                  ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  Full report: https://git.vet/r/54615e9b                         ║
remote: ║                                                                  ║
remote: ║          [Scannable QR code displays here]                       ║
remote: ║         Scan QR to view full web report                          ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  To clone: git clone https://github.com/baocin/known-malicious-repo ║
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
| Gitea | `git.vet/gitea.example.com/owner/repo` |
| Self-hosted GitLab | `git.vet/gitlab.company.com/owner/repo` |

### SSH Protocol Support

git.vet supports both HTTPS and SSH access:

```bash
# HTTPS (default)
git clone https://git.vet/github.com/user/repo

# SSH
git clone ssh://git.vet/github.com/user/repo
```

**Implementation Status:**
- [ ] **TODO: Verify SSH connectivity is working** - User reported `ssh://git.vet/github.com/WebGoat/WebGoat` times out on port 22
- [ ] SSH server implementation (`internal/gitssh/`)
- [ ] SSH key fingerprint extraction for rate limiting
- [ ] SSH sideband message support

**SSH Server Architecture:**
```go
// internal/gitssh/server.go
type SSHServer struct {
    config   *ssh.ServerConfig
    handler  *githttp.Handler  // Reuse HTTP handler logic
}

// SSH connections use the same scan pipeline as HTTPS
func (s *SSHServer) HandleGitUploadPack(session ssh.Session) {
    // Extract repo from command: git-upload-pack '/github.com/user/repo'
    // Route through same handler as HTTP
}
```

### Repository Deduplication (SSH vs HTTPS)

The same repository accessed via different protocols should share cache and scan results:

```
ssh://git.vet/github.com/user/repo   ─┐
                                      ├──▶ Canonical: github.com/user/repo
https://git.vet/github.com/user/repo ─┘
```

**Normalization Rules:**
1. Strip protocol prefix (`https://`, `ssh://`, `git://`)
2. Strip `git.vet/` prefix
3. Remove trailing `.git` suffix
4. Lowercase the host portion
5. Normalize path separators

```go
// internal/cache/normalize.go
func NormalizeRepoURL(rawURL string) string {
    // "ssh://git.vet/github.com/User/Repo.git" → "github.com/user/repo"
    // "https://git.vet/GITHUB.COM/User/Repo"  → "github.com/user/repo"

    url = strings.TrimPrefix(url, "ssh://")
    url = strings.TrimPrefix(url, "https://")
    url = strings.TrimPrefix(url, "git://")
    url = strings.TrimPrefix(url, "git.vet/")
    url = strings.TrimSuffix(url, ".git")

    parts := strings.SplitN(url, "/", 2)
    if len(parts) == 2 {
        return strings.ToLower(parts[0]) + "/" + parts[1]
    }
    return url
}
```

**Database Impact:**
- `repos.url` stores the **canonical** normalized URL
- `requests.repo_url` stores the **original** URL for debugging
- Cache lookups use normalized URL for hits across protocols

### Branch and Tag Support

Users should be able to scan specific branches or tags:

| Pattern | Example |
|---------|---------|
| Branch | `git.vet/github.com/user/repo@develop` |
| Tag | `git.vet/github.com/user/repo@v1.2.3` |
| Commit SHA | `git.vet/github.com/user/repo@abc123def` |

**Implementation Notes:**

Different git hosts use different URL formats for branches/tags:

| Host | Clone URL Format |
|------|------------------|
| GitHub | `git clone -b <ref> https://github.com/user/repo` |
| GitLab | `git clone -b <ref> https://gitlab.com/user/repo` |
| Bitbucket | `git clone -b <ref> https://bitbucket.org/user/repo` |
| Gitea | `git clone -b <ref> https://gitea.example.com/user/repo` |

All major git hosts support the `-b` flag for specifying branches/tags, so we can use a unified approach:

```go
// Parse ref from URL: repo@ref
ref := "main" // default
if strings.Contains(repoPath, "@") {
    parts := strings.SplitN(repoPath, "@", 2)
    repoPath = parts[0]
    ref = parts[1]
}

// Clone with specific ref
cmd := exec.CommandContext(ctx, "git", "clone",
    "--depth", "1",
    "--single-branch",
    "-b", ref,
    repoURL,
    localPath,
)
```

**Testing Required:**
- [ ] GitHub branches and tags
- [ ] GitLab branches and tags
- [ ] Bitbucket branches and tags
- [ ] Gitea branches and tags
- [ ] Self-hosted GitLab instances
- [x] Invalid ref handling (graceful error) - `internal/cache/cache.go`

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
remote: ⚠ [git.vet] Rate limit exceeded
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

## Package Manager Vulnerability Scanning

### Detected Package Managers

git.vet detects and scans dependencies from multiple package manager ecosystems:

| Package Manager | Detection Files | Audit Command | Notes |
|-----------------|-----------------|---------------|-------|
| **npm** | `package.json`, `package-lock.json` | `npm audit --json` | Most common |
| **yarn** | `yarn.lock` | `yarn audit --json` | v1 and v2+ support |
| **pnpm** | `pnpm-lock.yaml` | `pnpm audit --json` | Strict lockfile |
| **bun** | `bun.lockb` | `bun audit` (planned) | Binary lockfile |
| **pip** | `requirements.txt`, `Pipfile.lock` | `pip-audit --json` | Python |
| **cargo** | `Cargo.toml`, `Cargo.lock` | `cargo audit --json` | Rust |
| **go** | `go.mod`, `go.sum` | `govulncheck -json` | Go modules |
| **composer** | `composer.json`, `composer.lock` | `composer audit --format=json` | PHP |
| **bundler** | `Gemfile`, `Gemfile.lock` | `bundle audit --format=json` | Ruby |
| **maven** | `pom.xml` | OWASP dependency-check | Java |
| **gradle** | `build.gradle`, `build.gradle.kts` | OWASP dependency-check | Java/Kotlin |

### Scan Priority Order

When multiple package managers are detected, scan in this order (most critical first):

1. **Runtime dependencies** (package.json, requirements.txt, go.mod)
2. **Lockfiles** (package-lock.json, yarn.lock, Cargo.lock)
3. **Development dependencies** (marked separately in output)

### Integration Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Package Vulnerability Pipeline                    │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Detect package managers          2. Run native audit tools      │
│     ├─ Scan for lockfiles               ├─ npm audit --json        │
│     ├─ Check for manifest files         ├─ yarn audit --json       │
│     └─ Identify ecosystems              └─ pip-audit --json        │
│                                                                     │
│                            ↓                                        │
│  3. Normalize vulnerabilities        4. Merge with SAST findings   │
│     ├─ Map to common severity           ├─ Deduplicate             │
│     ├─ Extract CVE IDs                  ├─ Cross-reference         │
│     └─ Get fix versions                 └─ Generate report         │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Example Output

```
remote: ╔══════════════════════════════════════════════════════════════════╗
remote: ║  DEPENDENCY VULNERABILITIES (npm)                                ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║  HIGH: lodash@4.17.15 - Prototype Pollution (CVE-2020-8203)     ║
remote: ║  └─ Fix: npm install lodash@4.17.21                             ║
remote: ║                                                                  ║
remote: ║  MEDIUM: axios@0.19.2 - SSRF vulnerability (CVE-2020-28168)     ║
remote: ║  └─ Fix: npm install axios@0.21.1                               ║
remote: ╚══════════════════════════════════════════════════════════════════╝
```

### Notes

- Package vulnerabilities are classified as **MEDIUM** severity by default
- **Credential theft patterns in dependencies are still CRITICAL** (e.g., malicious postinstall scripts)
- Lockfile analysis is preferred over manifest analysis for accuracy

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
            sb.WriteProgress(fmt.Sprintf("%s [git.vet] Scanning: %d/%d files (%d%%)",
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
║  GIT.VET SECURITY REPORT                                     ║
╠══════════════════════════════════════════════════════════════╣
║  ✗ 2 Critical   ⚠ 5 High   ◆ 12 Medium   ○ 23 Low           ║
╚══════════════════════════════════════════════════════════════╝
```

**Plain mode (`/plain/` URL):**
```
================================================================
  GIT.VET SECURITY REPORT
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

### Width Constraints

All terminal output is constrained to **80 characters maximum width** for maximum compatibility across terminals, CI/CD systems, and logging tools:

- Box drawing characters and borders fit within 80 chars
- Finding messages are word-wrapped if needed
- QR codes are sized to fit (2 chars per module with 4-module quiet zones)
- Enforced at `internal/githttp/handler.go:301` via `boxWidth := 80`

This ensures readable output even on minimal terminals, SSH sessions with small windows, and automated build logs.

### Finding Display Order

Findings are sorted by **severity from critical to info** (worst first) to prioritize the most important security issues:

```go
// Severity priority: critical → high → medium → low → info
severityOrder := map[string]int{
    "critical": 0, "error": 0, "high": 1, "warning": 1,
    "medium": 2, "low": 3, "info": 4,
}
```

This applies to both:
- CLI output (terminal sideband messages)
- Web reports (`web/templates/report.html`)

Implementation: `SortFindingsBySeverity()` in `internal/githttp/handler.go`

### QR Code Implementation

QR codes linking to web reports use:

- **Error correction**: High level (30% damage recovery) for reliable scanning
- **Characters**: Full blocks (`██`) and spaces only - maximum terminal compatibility
- **Module size**: 2 characters wide per module (fits 80-char width limit)
- **Rendering**: 1 QR row per terminal line (taller but easier to scan)
- **Quiet zones**: 4 modules on all sides (QR spec compliant)

Implementation: `GenerateScaledQR()` in `internal/githttp/qrcode.go`

Example QR display:
```
remote: ║  Full report: https://git.vet/r/abc123           ║
remote: ║                                                  ║
remote: ║        ██████  ██    ████████    ██████          ║
remote: ║        ██  ██    ██  ██      ██  ██  ██          ║
remote: ║        ██████      ████    ██    ██████          ║
remote: ║         [Additional QR code rows...]             ║
remote: ║          ^ Scan QR to view full report ^         ║
```

---

## Build & Test Strategy

### Unit Tests (Implemented)

Unit tests are located alongside the code they test:

| Package | Test File | Coverage |
|---------|-----------|----------|
| `internal/scanner` | `scanner_test.go` | SARIF parsing, severity normalization, findings JSON |
| `internal/githttp` | `qrcode_test.go` | QR generation, sizing, quiet zones, box fitting |

**Run locally:**
```bash
go test -v -race -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

**GitHub Actions CI** (`.github/workflows/test.yml`):
- Runs on push to `main` and `claude/*` branches
- Runs on PRs to `main`
- Includes race detection and coverage reporting
- Docker tests verify: health, version, homepage, pricing, static assets, git protocol

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

#### Host Validation & SSRF Protection (✅ IMPLEMENTED)

**Default Policy (Strict Mode)**:
- Only allow known git hosts: `github.com`, `gitlab.com`, `bitbucket.org`
- Block all IP addresses (both IPv4 and IPv6)
- Block localhost/loopback addresses (`127.0.0.0/8`, `::1`, `localhost`)
- Block private networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
- Block link-local addresses (`169.254.0.0/16`, `fe80::/10`)
- Block unspecified addresses (`0.0.0.0`, `::`)

**Escape Hatch (Permissive Mode)**:
- Enable with `--allow-custom-hosts` CLI flag
- Allows self-hosted repos (Gitea, GitLab, Gogs, etc.)
- Still blocks all dangerous IPs (localhost, private networks, link-local)
- Allows public IPs for legitimate self-hosted scenarios

**Security Rationale**:
- Prevents SSRF attacks against internal services (port 22, 80, 443, etc.)
- Prevents network scanning of internal infrastructure
- Most users only need GitHub/GitLab/Bitbucket
- Power users can opt-in with explicit flag

**Implementation**:
- `internal/githttp/protocol.go`: `ValidateHost()` function
- `internal/githttp/handler.go`: Validation before any network operations
- `cmd/gitscan-server/main.go`: `--allow-custom-hosts` CLI flag
- Comprehensive tests in `internal/githttp/protocol_test.go`

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

## What Happens After the Report

### Security Score (0-100)

Provide a weighted overall security score:

| Severity | Weight |
|----------|--------|
| Critical | 25 pts per finding (max 100 deduction) |
| High     | 10 pts per finding (max 60 deduction) |
| Medium   | 3 pts per finding (max 30 deduction)  |
| Low      | 1 pt per finding (max 10 deduction)   |

```
Score = max(0, 100 - (critical_penalty + high_penalty + medium_penalty + low_penalty))
```

Display as: `Security Score: 73/100 ⭐⭐⭐☆☆`

### Recommended Alternatives

When a vulnerable package is found:
- Suggest safer alternatives with their security scores
- Show one-liner remediation commands

```
⚠ Found: lodash@3.10.1 (4 High vulnerabilities)
✓ Alternative: lodash@4.17.21 (0 vulnerabilities)
  Fix: npm install lodash@4.17.21

⚠ Found: express@3.x (deprecated, 12 vulnerabilities)
✓ Alternative: express@4.18.2 (0 vulnerabilities)
  Fix: npm install express@4.18.2
```

### Auto-Clone for Clean Repos (Premium)

If no issues are found:
- Option to automatically complete the clone
- No need to re-run with the original URL
- Saves time for frequent scanners

### Misspelled Repo Detection

Detect common typosquatting patterns:
```
⚠ Did you mean github.com/facebook/react?
  You requested: github.com/facebok/react

⚠ This repo name is similar to a popular package.
  Consider verifying you have the correct repository.
```

### Web Report Enhancements

#### Implemented Features

- ✅ **Collapsible Severity Sections** (`web/templates/report.html`, `web/handler.go`) - Findings are grouped by severity level (Critical, High, Medium, Low) in expandable `<details>` sections. Critical and High sections auto-expand if they contain findings; Medium and Low are collapsed by default. Each section displays count badge and severity icon.

- ✅ **Interactive Report Embed** (`web/templates/index.html`) - Homepage iframe preview is clickable to open full report in new tab. Wrapper div includes `onclick` handler with `pointer-events: none` on iframe to prevent interference.

- ✅ **Enhanced Error Pages** (`web/templates/repo_reports.html`) - "No scans found" page features centered layout with icon, helpful instructions, styled command box, and link to docs. Consistent visual design with report pages.

- ✅ **Documentation Portal** (`web/templates/docs.html`, `web/handler.go`) - Comprehensive `/docs` page detailing:
  - All scan modes (default, /clone, /plain, /json)
  - Supported hosts (GitHub, GitLab, Bitbucket)
  - Private repository authentication with consent delay
  - SSH protocol support
  - Web report URLs and patterns
  - API reference (metrics, version endpoints)

- ✅ **Stats Dashboard** (`web/templates/stats.html`, `web/handler.go`) - Unlisted `/stats` page (public but not linked in navigation) with:
  - Auto-refresh every 30 seconds
  - System overview (uptime, total scans, active scans, peak concurrent, cache hit rate)
  - Performance metrics with percentiles (p50, p95, p99 for clone/scan/total times)
  - Top scanned repositories table
  - Largest repository scanned
  - Recent scans across all repos
  - Color-coded metrics (green=good, yellow=warning, red=error)

- ✅ **Unified Navigation** - All templates (`index.html`, `pricing.html`, `docs.html`, `report.html`, `repo_reports.html`) include consistent header with "Docs → Pricing → GitHub" navigation

- ✅ **Marketing Copy Updates** (`web/templates/index.html`) - Removed QR code references from feature descriptions. Focus on web reports without mentioning QR functionality.

#### Planned Features

- Copy-to-clipboard button for clone command
- One-click clone command generation
- Download report as PDF/JSON
- Share report link with custom expiry

#### Technical Implementation Notes

**Collapsible Sections Architecture:**
- Backend (`web/handler.go`): `ReportData` struct includes severity-grouped slices (`CriticalFindings`, `HighFindings`, `MediumFindings`, `LowFindings`)
- Findings parsed from `results_json` are sorted by severity then distributed into respective slices
- Template uses HTML5 `<details>` + `<summary>` elements for native collapsibility
- Auto-expand logic: `{{if gt .CriticalCount 0}}open{{end}}` conditionally adds `open` attribute
- CSS transitions on `.expand-icon` (rotate 180° when expanded)

**Interactive Iframe:**
- Parent div onclick handler: `onclick="window.open('/reports/github.com/WebGoat/WebGoat/latest', '_blank')"`
- Iframe styled with `pointer-events: none` to prevent click interception
- Parent div includes `cursor: pointer` and tooltip title attribute

**Template Function Extensions:**
- Added `divf` template function for float division in stats dashboard (converts int64 to MB, milliseconds to seconds)

---

## Claude Code Integration

### AI-Assisted Security Scanning

git.vet can be integrated as a **Claude Code skill** that intercepts `git clone` commands before cloning repositories. This enables AI-assisted development workflows where:

1. **Automatic Security Checks**: When Claude Code attempts to clone a repository, the skill intercepts the command and routes it through git.vet first
2. **Pre-Clone Vulnerability Awareness**: Claude sees the security scan results before the code is cloned, allowing it to warn users about vulnerabilities
3. **Informed Decision Making**: If critical or high-severity vulnerabilities are found, Claude can:
   - Alert the user about the security risks
   - Suggest safer alternatives or forks
   - Recommend specific security mitigations before proceeding
   - Optionally block the clone if the risk is too high

### Skill Implementation Concept

```bash
# Instead of directly running:
git clone https://github.com/user/repo

# The Claude Code skill would intercept and run:
git clone https://git.vet/github.com/user/repo

# Claude would then see the security report in the terminal output
# and can make informed decisions about whether to proceed
```

### Benefits for AI-Assisted Development

- **Proactive Security**: Security vulnerabilities are surfaced before code enters the development environment
- **Context for AI**: Claude has security context when helping with code from that repository
- **Reduced Attack Surface**: Prevents inadvertent cloning of malicious or vulnerable dependencies
- **Audit Trail**: All scans are logged, providing visibility into what code AI assistants are working with

This integration positions git.vet as a security layer for the emerging AI-assisted development ecosystem.

---

## LLM-TLDR Integration for Semantic Analysis

### Beyond Pattern Matching

While opengrep excels at pattern-based vulnerability detection, [llm-tldr](https://github.com/parcadei/llm-tldr) offers complementary **semantic code analysis** that could detect issues patterns alone cannot find:

- **Authentication Flow Analysis**: Trace JWT validation, session handling, and auth bypass risks across call graphs
- **Code Smells**: Identify architectural issues like circular dependencies, god classes, and dead code
- **Data Flow Vulnerabilities**: Track tainted input through the codebase to find injection points
- **Business Logic Flaws**: Understand control flow to detect authorization gaps and state machine issues

### How llm-tldr Works

llm-tldr uses a five-layer analysis architecture:
1. **AST Parsing**: Extract function/class structure
2. **Call Graph Analysis**: Map function relationships and dependencies
3. **Control Flow Graphs**: Understand execution paths and complexity
4. **Data Flow Graphs**: Track value propagation through code
5. **Program Dependence Graphs**: Line-level impact analysis

It achieves ~95% token savings by extracting only relevant structural information, making large codebases accessible to LLMs within context limits.

### Integration Concept

```
┌─────────────────────────────────────────────────────────────┐
│                     git.vet Analysis Pipeline                │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  1. Opengrep Scan          2. llm-tldr Analysis             │
│     ├─ SAST patterns          ├─ Call graph extraction      │
│     ├─ Secret detection       ├─ Data flow tracking         │
│     └─ Known CVEs             └─ Semantic embeddings        │
│                                                             │
│                    ↓                                        │
│         ┌─────────────────────────┐                        │
│         │  Combined Intelligence  │                        │
│         │  ─────────────────────  │                        │
│         │  • Pattern matches      │                        │
│         │  • Semantic context     │                        │
│         │  • Flow-based risks     │                        │
│         └─────────────────────────┘                        │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

### Potential Use Cases

| Issue Type | Opengrep | llm-tldr | Combined |
|------------|----------|----------|----------|
| Hardcoded secrets | Yes | - | Yes |
| SQL injection | Yes | Better context | Enhanced |
| Auth bypass | Limited | Yes (flow analysis) | Enhanced |
| Dead code | - | Yes | Yes |
| Circular deps | - | Yes | Yes |
| Taint tracking | Limited | Yes | Enhanced |

### Implementation Notes

- llm-tldr supports: Python, TypeScript, JavaScript, Go, Rust, Java, C, C++, Ruby, PHP, C#, Kotlin, Scala, Swift, Lua, Elixir
- Background daemon provides ~100ms queries vs 30-second CLI spawns
- 1024-dimensional embeddings via bge-large-en-v1.5 model enable semantic search

This would position git.vet as a comprehensive code intelligence platform, not just a vulnerability scanner.

---

## Future Enhancements

### Phase 1.5 - Credential Theft Detection (PRIORITY)
- [ ] **Implement credential theft detection rules** - Custom opengrep rules for:
  - [ ] `.aws/credentials` and `.aws/config` file access patterns
  - [ ] `~/.ssh/` directory traversal and key reading
  - [ ] `.env` file exfiltration patterns
  - [ ] Browser cookie/session stealing
  - [ ] Keychain/password manager access
  - [ ] Base64-encoded credential exfiltration
- [ ] **Severity override system** - Credential theft patterns marked CRITICAL regardless of opengrep default
- [ ] **Network exfiltration detection** - Identify outbound requests with sensitive data

### Phase 1.6 - Package Vulnerability Scanning
- [ ] **Detect package manager config files** (package.json, yarn.lock, pnpm-lock.yaml, bun.lockb)
- [ ] **Run native audit commands** (npm audit, yarn audit, pnpm audit)
- [ ] **Parse and normalize vulnerability output** to common format
- [ ] **Scan postinstall scripts** for malicious behavior (CRITICAL priority)
- [ ] **Support additional ecosystems**: pip-audit, cargo audit, govulncheck

### Phase 1.7 - SSH Protocol Support
- [ ] **TODO: Verify SSH connectivity is working** - Port 22 timeout reported
- [ ] **Implement SSH server** (`internal/gitssh/`)
- [ ] **SSH/HTTPS deduplication** - Canonical URL normalization
- [ ] **SSH key fingerprint rate limiting**

### Phase 2
- [ ] Private repository support (GitHub App OAuth)
- [ ] GitLab and Bitbucket support
- [ ] Custom rule upload via web UI
- [ ] Webhook notifications
- [x] Security score (0-100) with severity weighting - `internal/scanner/scanner.go`

### Phase 3
- [ ] PR comment integration (gitscan as GitHub Action)
- [ ] Historical trend tracking
- [ ] Organization dashboards
- [ ] API for CI/CD integration
- [ ] Alternative package recommendations

### Phase 4
- [x] Self-hosted option (Docker image) - `docker/Dockerfile`
- [ ] IDE extensions (VS Code, JetBrains)
- [ ] Dependency scanning (SCA)
- [x] License compliance checking - `internal/license/license.go`
- [ ] Typosquatting/misspelled repo detection
- [ ] Auto-clone for clean repos (premium feature)

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
