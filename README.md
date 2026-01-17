# git.vet

**Zero-install security scanning for git repositories**

git.vet lets you scan any public repository for security issues using just `git clone` - no installation required.

## Usage

Replace your git host with `git.vet` and include the original host in the path:

```bash
# Instead of:
git clone https://github.com/user/repo

# Use:
git clone https://git.vet/github.com/user/repo
```

The scan results appear directly in your terminal.

## Supported Hosts

| Host | Command |
|------|---------|
| GitHub | `git clone https://git.vet/github.com/owner/repo` |
| GitLab | `git clone https://git.vet/gitlab.com/owner/repo` |
| Bitbucket | `git clone https://git.vet/bitbucket.org/owner/repo` |

## Output Modes

| Mode | Command | Description |
|------|---------|-------------|
| Scan (default) | `git.vet/github.com/owner/repo` | Security report only |
| Clone | `git.vet/clone/github.com/owner/repo` | Scan + complete clone |
| Plain | `git.vet/plain/github.com/owner/repo` | No unicode/colors |
| JSON | `git.vet/json/github.com/owner/repo` | Machine-readable output |

## Example

```
$ git clone https://git.vet/github.com/facebook/react
Cloning into 'react'...
remote:
remote: [git.vet] Fetching from github.com (shallow clone)...
remote: [git.vet] Fetched. 4521 files
remote: [git.vet] Scanning with opengrep...
remote: [git.vet] Scan complete!
remote:
remote: +------------------------------------------------------------------+
remote: |  GIT.VET SECURITY REPORT                                         |
remote: |  Repository: github.com/facebook/react                           |
remote: |  Commit: a1b2c3d4                                                |
remote: |  Scanned: 4521 files in 3.2s                                     |
remote: +------------------------------------------------------------------+
remote: |  X 0 Critical   ! 2 High   * 14 Medium   - 23 Low                |
remote: +------------------------------------------------------------------+
remote: |  Full report: https://git.vet/r/a1b2c3d4                         |
remote: |  To clone: git clone https://github.com/facebook/react           |
remote: +------------------------------------------------------------------+
remote:
fatal: Could not read from remote repository.
```

The `fatal` error is expected - git.vet intentionally fails the clone after showing the report (unless using `/clone/` mode).

## How It Works

git.vet implements the git smart HTTP protocol and uses the sideband channel to stream scan progress and results to your terminal. No client installation needed - works anywhere git runs.

1. You request a clone from `git.vet`
2. git.vet fetches the repo (shallow clone for speed)
3. Scans with [opengrep](https://github.com/opengrep/opengrep) (LGPL 2.1)
4. Streams results via git protocol sideband messages
5. Intentionally fails the clone (or completes it in `/clone/` mode)

## Private Repositories

Private repos are supported but require a 10-second consent delay:

```bash
git clone https://username:token@git.vet/github.com/private/repo
```

Your code is deleted immediately after scanning.

## Self-Hosting

```bash
docker run -p 8080:8080 ghcr.io/baocin/gitscan:latest
```

See [MASTER_PLAN.md](MASTER_PLAN.md) for detailed architecture documentation.

## Development

```bash
# Build
go build -o git-vet-server ./cmd/gitscan-server

# Run
./git-vet-server -listen :8080 -db git-vet.db -cache-dir /tmp/git-vet-cache

# Test
go test ./...
```

## License

MIT
