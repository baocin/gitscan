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
remote: ║ Full report: https://git.vet/r/54615e9b                          ║
remote: ║ To clone: git clone https://github.com/baocin/known-malicious-repo ║
remote: ╠══════════════════════════════════════════════════════════════════╣
remote: ║ Questions? gitvet@steele.red • buymeacoffee.com/gitvet           ║
remote: ╚══════════════════════════════════════════════════════════════════╝
remote:
fatal: bad object 54615e9b0b4df9ac4519937f5ccab429cff0a19d
```

The `fatal` error is expected - git.vet shows the security report and then fails the clone to prevent downloading malicious code (unless using `/clone/` mode).

## How It Works

git.vet implements the git smart HTTP protocol and uses the sideband channel to stream scan progress and results to your terminal. No client installation needed - works anywhere git runs.

1. You request a clone from `git.vet`
2. git.vet fetches the repo (shallow clone for speed)
3. Scans with [opengrep](https://github.com/opengrep/opengrep) - fast, flexible static analysis
4. Streams results via git protocol sideband messages
5. Intentionally fails the clone (or completes it in `/clone/` mode)

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
