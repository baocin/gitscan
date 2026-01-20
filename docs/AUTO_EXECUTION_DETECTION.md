# Auto-Execution Detection Rules

## Overview

GitVet now includes comprehensive detection for **auto-execution mechanisms** - code that runs automatically when a repository is cloned, built, or used. These mechanisms can be exploited for supply chain attacks, credential theft, and malicious code execution.

## Detection Coverage

### 26 Rule Files | 78+ Individual Rules | 30 Findings on Test Repo

### Git-Level Auto-Execution

**Files:** `auto-exec-git-hooks.yaml`, `auto-exec-gitattributes.yaml`

- **Git hooks** (`.git/hooks/*`, `.gitmodules`)
  - Detects malicious submodules (CVE-2024-32002, CVE-2025-48384)
  - Detects executable git hooks
- **Git attributes** (`.gitattributes`)
  - Detects filter configurations (CVE-2022-23521)
  - Detects overflow exploits (long lines)

**Severity:** ERROR (hooks), WARNING (attributes)

---

### Build System Auto-Execution

**Files:** `auto-exec-makefile.yaml`, `auto-exec-build-scripts.yaml`

- **Makefiles**
  - Network downloads + execution
  - Credential file access (WARNING - reduced false positives)
  - Suspicious default targets
- **Install scripts** (`install.sh`, `setup.sh`, `build.sh`, `configure`)
  - Curl/wget piped to bash
  - Credential access
  - Sudo privilege escalation

**Severity:** ERROR (network exec), WARNING (credential access)

---

### Language-Specific Auto-Execution

#### JavaScript/Node.js
**File:** `npm-hooks.yaml`

- **package.json lifecycle hooks**
  - `postinstall`, `preinstall`, `install` scripts
  - Auto-executes on `npm install`

**Severity:** ERROR

#### Python
**File:** `python-hooks.yaml`

- **setup.py hooks**
  - Executes arbitrary code on `pip install`
  - Detects cmdclass overrides

**Severity:** ERROR

#### Rust
**File:** `auto-exec-rust-build.yaml` (4 rules)

- **build.rs scripts**
  - Network downloads (reqwest, curl, wget)
  - Credential access
  - Shell command execution
  - Presence detection (INFO)

**Severity:** ERROR (network/creds), WARNING (shell), INFO (present)

#### Java/Maven
**File:** `auto-exec-java-maven.yaml` (5 rules)

- **pom.xml plugins**
  - exec-maven-plugin shell execution
  - maven-antrun-plugin exec tasks
  - GMavenPlus Groovy scripts
  - Custom plugin repositories
  - Hardcoded credentials in POM

**Severity:** ERROR (exec), WARNING (repos/creds)

#### Gradle
**File:** `auto-exec-gradle.yaml` (5 rules)

- **build.gradle scripts**
  - Init scripts (auto-run before every build)
  - Exec tasks
  - Network downloads
  - Untrusted repositories
  - Credential access

**Severity:** ERROR (exec/network), WARNING (repos/creds)

#### C/C++/CMake
**File:** `auto-exec-cmake.yaml` (4 rules)

- **CMakeLists.txt commands**
  - execute_process with network access
  - execute_process with credential access
  - Shell command execution
  - add_custom_command network downloads

**Severity:** ERROR (network), WARNING (shell/creds)

#### PHP
**File:** `auto-exec-php-composer.yaml` (3 rules)

- **composer.json scripts**
  - pre-install-cmd, post-install-cmd hooks
  - Custom package repositories
  - post-autoload-dump scripts

**Severity:** ERROR (shell exec), WARNING (repos)

#### Ruby
**File:** `auto-exec-ruby.yaml` (4 rules)

- **Gemspec/Rakefile**
  - post_install hooks
  - Rakefile network execution
  - Credential access
  - Git-based gem sources

**Severity:** ERROR (exec), WARNING (creds), INFO (git sources)

#### .NET
**File:** `auto-exec-dotnet.yaml` (4 rules)

- **MSBuild projects** (`.csproj`, `.vbproj`)
  - Exec tasks with curl/wget/PowerShell
  - PreBuild/AfterBuild targets
  - NuGet install.ps1 scripts
  - DownloadFile tasks

**Severity:** ERROR (exec/NuGet), WARNING (build targets)

---

### Container Auto-Execution

**File:** `auto-exec-docker.yaml` (6 rules)

- **Dockerfile**
  - ONBUILD triggers (auto-execute in child images)
  - ADD from URLs
  - RUN with curl/wget piped to bash
- **docker-compose.yml**
  - Build from network URLs
  - Volume mounts of sensitive paths (.ssh, .aws, docker.sock)

**Severity:** ERROR (ONBUILD RUN, curl|bash), WARNING (volumes), INFO (ADD URLs)

---

### CI/CD Auto-Execution

**File:** `auto-exec-cicd.yaml` (6 rules)

- **GitHub Actions** (`.github/workflows/*.yml`)
  - Curl piped to bash
  - Third-party actions without version pins
  - Secrets in logs
- **GitLab CI** (`.gitlab-ci.yml`)
  - Curl piped to bash in scripts
- **Travis CI** (`.travis.yml`)
  - Curl piped to bash in hooks
- **CircleCI** (`.circleci/config.yml`)
  - Curl piped to bash

**Severity:** ERROR (curl|bash), WARNING (unpinned actions, secrets)

---

### Git Hook Managers

**File:** `auto-exec-precommit.yaml` (5 rules)

- **pre-commit** (`.pre-commit-config.yaml`)
  - Hooks configuration detection (INFO)
  - Custom repositories (WARNING)
  - System hooks
- **Lefthook** (`lefthook.yml`)
  - Hook detection
- **Husky** (`package.json`)
  - Husky git hooks

**Severity:** WARNING (custom repos), INFO (presence detection)

---

### Social Engineering

**File:** `auto-exec-readme.yaml` (4 rules)

- **README.md instructions**
  - Curl/wget piped to bash
  - Run install scripts
  - npm install (INFO)
  - pip install (INFO)

**Severity:** WARNING (curl|bash, scripts), INFO (npm/pip)

---

## Test Results

### Known Exploitive Project (Test Repository)
- **30 findings** across malicious patterns
- All expected malicious code detected

### WebGoat (Real Open-Source Java Project)
- **4 findings** - all legitimate INFO/WARNING
  - Pre-commit hooks configuration (trusted GitHub repos)
- **No false positives** for build files

### False Positive Mitigation
- Makefile credential access: **WARNING** (not ERROR)
- Makefile confidence: **LOW** (valid for C/C++ projects)
- README npm/pip install: **INFO** (informational only)
- Pre-commit trusted repos: **INFO** (awareness, not blocking)

---

## Severity Guidelines

| Severity | Use Case | Examples |
|----------|----------|----------|
| **ERROR** | Dangerous patterns requiring review | Curl\|bash, network exec, credential theft |
| **WARNING** | Suspicious but potentially legitimate | Makefile creds, custom repos, build hooks |
| **INFO** | Awareness/informational | README instructions, hook presence |

---

## CWE/OWASP Coverage

- **CWE-78**: OS Command Injection
- **CWE-94**: Improper Control of Code Generation
- **CWE-200**: Exposure of Sensitive Information
- **CWE-269**: Improper Privilege Management
- **CWE-494**: Download of Code Without Integrity Check
- **CWE-506**: Embedded Malicious Code
- **CWE-522**: Insufficiently Protected Credentials
- **CWE-532**: Insertion of Sensitive Information into Log File
- **CWE-798**: Use of Hard-coded Credentials
- **CWE-829**: Inclusion of Functionality from Untrusted Control Sphere

**OWASP Top 10 2021:**
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection
- A04: Insecure Design
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Security Logging and Monitoring Failures

---

## Usage

```bash
# Scan a repository for auto-execution risks
gitvet scan /path/to/repo

# Scan specific config files
opengrep scan --config rules/credential-theft /path/to/repo

# Scan with verbose output
opengrep scan --config rules/credential-theft --verbose /path/to/repo
```

---

## References

- [CVE-2024-32002](https://nvd.nist.gov/vuln/detail/CVE-2024-32002) - Git RCE via malicious submodules
- [CVE-2025-48384](https://nvd.nist.gov/vuln/detail/CVE-2025-48384) - Git arbitrary file write
- [CVE-2022-23521](https://nvd.nist.gov/vuln/detail/CVE-2022-23521) - .gitattributes integer overflow
- [CVE-2018-11235](https://nvd.nist.gov/vuln/detail/CVE-2018-11235) - Git submodule RCE

---

## Language Support Summary

| Language/Tool | Rules | Auto-Execution Mechanism |
|---------------|-------|--------------------------|
| JavaScript/Node.js | 3 | package.json lifecycle hooks |
| Python | 3 | setup.py install |
| Rust | 4 | build.rs scripts |
| Java/Maven | 5 | pom.xml plugins |
| Gradle | 5 | build.gradle, init scripts |
| C/C++/CMake | 4 | CMakeLists.txt execute_process |
| PHP | 3 | composer.json scripts |
| Ruby | 4 | gemspec, Rakefile |
| .NET | 4 | MSBuild, NuGet scripts |
| Docker | 6 | ONBUILD, docker-compose |
| Shell | 7 | Makefiles, install scripts |
| Git | 4 | hooks, submodules, attributes |
| CI/CD | 6 | GitHub Actions, GitLab CI, Travis, CircleCI |
| Git Hooks | 5 | pre-commit, Lefthook, Husky |
| README | 4 | Social engineering instructions |

**Total: 67+ rules across 26 files**

---

## Future Enhancements

Potential additions:
- Perl (Makefile.PL, Build.PL)
- Lua (LuaRocks)
- Ansible playbooks
- Terraform providers
- VS Code tasks.json
- IDE project files (.idea, .eclipse)
- Go vendor modifications (low priority - go.sum provides integrity)
