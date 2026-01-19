# git.vet Scripts

Utility scripts for git.vet operations and maintenance.

## Cache Preloader

**`preload-cache.sh`** - Warm up the cache by scanning popular repositories

### Usage

```bash
# Sequential scanning (slower but safer)
./scripts/preload-cache.sh

# Parallel scanning (5 concurrent by default)
./scripts/preload-cache.sh --parallel

# Parallel with custom concurrency
./scripts/preload-cache.sh --parallel --max-concurrent 10

# Use SSH instead of HTTP
./scripts/preload-cache.sh --method ssh

# Test against local/staging server
./scripts/preload-cache.sh --host localhost:8080
```

### Options

- `--parallel` - Run scans in parallel for faster execution
- `--max-concurrent N` - Maximum number of concurrent scans (default: 5)
- `--method http|ssh` - Choose scan method (default: http)
- `--host HOSTNAME` - Specify git.vet hostname (default: git.vet)
- `--help` - Show usage information

### What it does

1. Scans 30+ popular repositories including:
   - OWASP security projects (WebGoat, Juice Shop, etc.)
   - Popular frameworks (React, Django, Rails, etc.)
   - Security tools (TruffleHog, GitLeaks, Trivy, etc.)
   - Common libraries and DevOps tools

2. Populates the server cache with:
   - Cloned repositories
   - Scan results
   - Security findings

3. Improves performance for:
   - Future scans of these repos
   - Scans of similar repositories
   - Demo and testing scenarios

### Requirements

- `git` command
- `bash` 4.0+
- `timeout` command (part of GNU coreutils)
- **Optional**: `parallel` command for better parallel execution
  - Install: `sudo apt-get install parallel` (Ubuntu/Debian)
  - Install: `brew install parallel` (macOS)

### Examples

**Quick cache warmup:**
```bash
./scripts/preload-cache.sh --parallel
```

**Full cache population (slower but more thorough):**
```bash
./scripts/preload-cache.sh
```

**Test local development server:**
```bash
./scripts/preload-cache.sh --host localhost:8080 --parallel --max-concurrent 3
```

### Output

The script provides detailed progress and a summary:

```
╔════════════════════════════════════════════════════════════════╗
║           git.vet Cache Preloader                              ║
╠════════════════════════════════════════════════════════════════╣
║  Host:         git.vet
║  Method:       http
║  Parallel:     true
║  Concurrent:   5
║  Repositories: 30
╚════════════════════════════════════════════════════════════════╝

[INFO] [1/30] Scanning OWASP/WebGoat...
[✓] [1/30] OWASP/WebGoat - Scan completed
...

╔════════════════════════════════════════════════════════════════╗
║                    Preload Summary                             ║
╠════════════════════════════════════════════════════════════════╣
║  Total:        30 repositories
║  Successful:   28
║  Failed:       2
║  Duration:     145 seconds (2.4 minutes)
╚════════════════════════════════════════════════════════════════╝
```

### Notes

- Each scan has a 5-minute timeout to prevent hanging
- Failed scans are logged but don't stop the process
- Temporary clone directories are automatically cleaned up
- The script is safe to run multiple times
- Ideal to run after deploying updates or clearing cache
