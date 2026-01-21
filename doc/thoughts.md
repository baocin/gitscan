# Thoughts & Future Ideas

## Extension to `curl | bash` Install Scripts

The same security scanning approach that git.vet uses for repositories could be valuable for detecting malicious code in `curl | bash` style installers.

### The Problem

Many projects use convenience installers like:
```bash
curl -fsSL https://opencode.ai/install | bash
curl -fsSL https://get.docker.com | sh
```

These pose similar security risks to cloning and running untrusted code:
- **Auto-execution**: The script runs immediately with your user privileges
- **Credential theft**: Malicious scripts can steal SSH keys, cloud credentials, browser cookies
- **Data exfiltration**: Can read and upload sensitive files from your system
- **Supply chain attacks**: Compromised CDNs or repositories can serve malicious installers

### How git.vet's Detection Rules Apply

The same patterns we detect in repositories are relevant for install scripts:

1. **Credential Theft Detection**
   - Reading `~/.ssh/` keys
   - Accessing `~/.aws/credentials`
   - Reading browser credential stores
   - Accessing environment variables with secrets

2. **Data Exfiltration**
   - Suspicious network calls (curl/wget to unknown domains)
   - Base64 encoding of sensitive files
   - Uploading data to external servers

3. **Dangerous Operations**
   - Downloading and executing additional scripts
   - Modifying shell rc files (persistence)
   - Adding cron jobs or systemd services
   - Changing file permissions on system directories

### Potential Implementation

**Option 1: Pre-scan proxy**
```bash
curl https://opencode.ai/install | git.vet scan-stdin | bash
```
The scanner analyzes the script before it's piped to bash, blocking execution if dangerous patterns are found.

**Option 2: URL-based scanning**
```bash
git.vet scan-url https://opencode.ai/install
# Shows security report, then:
# "To execute: curl https://opencode.ai/install | bash"
```

**Option 3: Browser extension**
Detect `curl | bash` commands in documentation and show inline security warnings.

### Challenges

1. **Performance**: Scanning must be fast enough not to interrupt the install flow
2. **False positives**: Legitimate installers may need to read environment, make network calls, etc.
3. **Obfuscation**: Malicious scripts can use encoding, compression, or multi-stage downloads
4. **Trust model**: Users running `curl | bash` have already decided to trust the source

### Value Proposition

Even with challenges, showing users **what** a script will do before execution is valuable:
- "This script will read your SSH keys" → user can decide if that's expected
- "This script contacts 3 external domains" → shows full attack surface
- Risk score (0-100) gives quick assessment without reading entire script

### Related Work

- [Curlshield](https://github.com/edneville/curlshield) - Static analysis for shell scripts
- [ShellCheck](https://www.shellcheck.net/) - Shell script linting (not security-focused)
- Browser "Download scanning" - but doesn't analyze script content

### Next Steps

1. Extend opengrep rules to detect shell script patterns (currently focused on git repos)
2. Build CLI tool: `git.vet scan-script <file>` or `git.vet scan-stdin`
3. Test against known-malicious install scripts
4. Consider integration with package managers (homebrew, apt, etc.)
