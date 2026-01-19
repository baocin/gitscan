package githttp

import (
	"testing"
)

func TestParseRepoPathFull(t *testing.T) {
	tests := []struct {
		name        string
		urlPath     string
		wantHost    string
		wantOwner   string
		wantRepo    string
		wantMode    string
		wantErr     bool
		errContains string
	}{
		{
			name:      "basic github path",
			urlPath:   "/github.com/WebGoat/WebGoat/info/refs",
			wantHost:  "github.com",
			wantOwner: "WebGoat",
			wantRepo:  "WebGoat",
			wantMode:  "scan",
		},
		{
			name:      "github path with .git suffix",
			urlPath:   "/github.com/facebook/react.git/info/refs",
			wantHost:  "github.com",
			wantOwner: "facebook",
			wantRepo:  "react",
			wantMode:  "scan",
		},
		{
			name:      "github path with mode prefix",
			urlPath:   "/json/github.com/user/repo/info/refs",
			wantHost:  "github.com",
			wantOwner: "user",
			wantRepo:  "repo",
			wantMode:  "json",
		},
		{
			name:      "gitlab path",
			urlPath:   "/gitlab.com/inkscape/inkscape/info/refs",
			wantHost:  "gitlab.com",
			wantOwner: "inkscape",
			wantRepo:  "inkscape",
			wantMode:  "scan",
		},
		{
			name:      "bitbucket path",
			urlPath:   "/bitbucket.org/atlassian/python-bitbucket/info/refs",
			wantHost:  "bitbucket.org",
			wantOwner: "atlassian",
			wantRepo:  "python-bitbucket",
			wantMode:  "scan",
		},
		{
			name:      "clone mode prefix",
			urlPath:   "/clone/github.com/owner/repo/git-upload-pack",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantMode:  "clone",
		},
		{
			name:      "plain mode prefix",
			urlPath:   "/plain/github.com/owner/repo/info/refs",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantMode:  "plain",
		},
		// Bug fix: duplicate github.com URL - auto-correct
		{
			name:      "duplicate github.com in path - should auto-correct",
			urlPath:   "/github.com/github.com/WebGoat/WebGoat/info/refs",
			wantHost:  "github.com",
			wantOwner: "WebGoat",
			wantRepo:  "WebGoat",
			wantMode:  "scan",
		},
		{
			name:      "duplicate gitlab.com in path - should auto-correct",
			urlPath:   "/gitlab.com/gitlab.com/owner/repo/info/refs",
			wantHost:  "gitlab.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantMode:  "scan",
		},
		// Bug fix: user pastes full URL with https://
		{
			name:      "full URL with https:// pasted",
			urlPath:   "/https:/github.com/owner/repo/info/refs",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantMode:  "scan",
		},
		{
			name:      "full URL with http:// pasted",
			urlPath:   "/http:/github.com/owner/repo/info/refs",
			wantHost:  "github.com",
			wantOwner: "owner",
			wantRepo:  "repo",
			wantMode:  "scan",
		},
		// Error cases
		{
			name:        "unsupported host",
			urlPath:     "/sourcehut.org/user/repo/info/refs",
			wantErr:     true,
			errContains: "unsupported git host",
		},
		{
			name:        "missing components",
			urlPath:     "/github.com/user/info/refs",
			wantErr:     true,
			errContains: "need host/owner/repo format",
		},
		{
			name:        "only host",
			urlPath:     "/github.com/info/refs",
			wantErr:     true,
			errContains: "need host/owner/repo format",
		},
		{
			name:        "duplicate host with missing repo",
			urlPath:     "/github.com/github.com/owner/info/refs",
			wantErr:     true,
			errContains: "duplicate host detected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRepoPathFull() expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("ParseRepoPathFull() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("ParseRepoPathFull() unexpected error: %v", err)
				return
			}

			if parsed.Host != tt.wantHost {
				t.Errorf("ParseRepoPathFull() Host = %q, want %q", parsed.Host, tt.wantHost)
			}
			if parsed.Owner != tt.wantOwner {
				t.Errorf("ParseRepoPathFull() Owner = %q, want %q", parsed.Owner, tt.wantOwner)
			}
			if parsed.Repo != tt.wantRepo {
				t.Errorf("ParseRepoPathFull() Repo = %q, want %q", parsed.Repo, tt.wantRepo)
			}
			if parsed.Mode != tt.wantMode {
				t.Errorf("ParseRepoPathFull() Mode = %q, want %q", parsed.Mode, tt.wantMode)
			}

			// Verify FullPath is correctly constructed
			expectedFullPath := parsed.Host + "/" + parsed.Owner + "/" + parsed.Repo
			if parsed.FullPath != expectedFullPath {
				t.Errorf("ParseRepoPathFull() FullPath = %q, want %q", parsed.FullPath, expectedFullPath)
			}

			// Verify RepoPath is correctly constructed
			expectedRepoPath := parsed.Owner + "/" + parsed.Repo
			if parsed.RepoPath != expectedRepoPath {
				t.Errorf("ParseRepoPathFull() RepoPath = %q, want %q", parsed.RepoPath, expectedRepoPath)
			}
		})
	}
}

func TestGetCloneURL(t *testing.T) {
	tests := []struct {
		name    string
		urlPath string
		wantURL string
	}{
		{
			name:    "github repo",
			urlPath: "/github.com/WebGoat/WebGoat/info/refs",
			wantURL: "https://github.com/WebGoat/WebGoat.git",
		},
		{
			name:    "gitlab repo",
			urlPath: "/gitlab.com/inkscape/inkscape/info/refs",
			wantURL: "https://gitlab.com/inkscape/inkscape.git",
		},
		{
			name:    "repo with hyphen",
			urlPath: "/github.com/facebook/create-react-app/info/refs",
			wantURL: "https://github.com/facebook/create-react-app.git",
		},
		{
			name:    "repo with dots",
			urlPath: "/github.com/user/repo.js/info/refs",
			wantURL: "https://github.com/user/repo.js.git",
		},
		{
			name:    "duplicate github.com auto-corrected",
			urlPath: "/github.com/github.com/WebGoat/WebGoat/info/refs",
			wantURL: "https://github.com/WebGoat/WebGoat.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)
			if err != nil {
				t.Fatalf("ParseRepoPathFull() failed: %v", err)
			}

			gotURL := parsed.GetCloneURL()
			if gotURL != tt.wantURL {
				t.Errorf("GetCloneURL() = %q, want %q", gotURL, tt.wantURL)
			}
		})
	}
}

func TestGetAPIURL(t *testing.T) {
	tests := []struct {
		name    string
		urlPath string
		wantAPI string
	}{
		{
			name:    "github api url",
			urlPath: "/github.com/facebook/react/info/refs",
			wantAPI: "https://api.github.com/repos/facebook/react",
		},
		{
			name:    "gitlab api url",
			urlPath: "/gitlab.com/inkscape/inkscape/info/refs",
			wantAPI: "https://gitlab.com/api/v4/projects/inkscape%2Finkscape",
		},
		{
			name:    "bitbucket api url",
			urlPath: "/bitbucket.org/atlassian/python-bitbucket/info/refs",
			wantAPI: "https://api.bitbucket.org/2.0/repositories/atlassian/python-bitbucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)
			if err != nil {
				t.Fatalf("ParseRepoPathFull() failed: %v", err)
			}

			gotAPI := parsed.GetAPIURL()
			if gotAPI != tt.wantAPI {
				t.Errorf("GetAPIURL() = %q, want %q", gotAPI, tt.wantAPI)
			}
		})
	}
}

func TestParseRepoPath(t *testing.T) {
	// Test the simpler ParseRepoPath wrapper
	mode, repoPath, err := ParseRepoPath("/github.com/user/repo/info/refs")
	if err != nil {
		t.Fatalf("ParseRepoPath() failed: %v", err)
	}
	if mode != "scan" {
		t.Errorf("ParseRepoPath() mode = %q, want %q", mode, "scan")
	}
	if repoPath != "user/repo" {
		t.Errorf("ParseRepoPath() repoPath = %q, want %q", repoPath, "user/repo")
	}
}

// contains checks if substr is in s
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestValidateHost tests the host validation function
func TestValidateHost(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		allowCustomHosts bool
		wantErr          bool
		errContains      string
	}{
		// Known hosts (should always pass)
		{
			name:             "github.com allowed (strict mode)",
			host:             "github.com",
			allowCustomHosts: false,
			wantErr:          false,
		},
		{
			name:             "gitlab.com allowed (strict mode)",
			host:             "gitlab.com",
			allowCustomHosts: false,
			wantErr:          false,
		},
		{
			name:             "bitbucket.org allowed (strict mode)",
			host:             "bitbucket.org",
			allowCustomHosts: false,
			wantErr:          false,
		},

		// Custom hosts (strict vs permissive)
		{
			name:             "custom host blocked (strict mode)",
			host:             "git.example.com",
			allowCustomHosts: false,
			wantErr:          true,
			errContains:      "unsupported git host",
		},
		{
			name:             "custom host allowed (permissive mode)",
			host:             "git.example.com",
			allowCustomHosts: true,
			wantErr:          false,
		},
		{
			name:             "self-hosted gitea blocked (strict mode)",
			host:             "gitea.company.com",
			allowCustomHosts: false,
			wantErr:          true,
			errContains:      "Use --allow-custom-hosts",
		},
		{
			name:             "self-hosted gitea allowed (permissive mode)",
			host:             "gitea.company.com",
			allowCustomHosts: true,
			wantErr:          false,
		},

		// Localhost / loopback (always blocked)
		{
			name:             "localhost blocked (strict mode)",
			host:             "localhost",
			allowCustomHosts: false,
			wantErr:          true,
			errContains:      "loopback",
		},
		{
			name:             "localhost blocked (permissive mode)",
			host:             "localhost",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "loopback",
		},
		{
			name:             "127.0.0.1 blocked (strict mode)",
			host:             "127.0.0.1",
			allowCustomHosts: false,
			wantErr:          true,
			errContains:      "loopback",
		},
		{
			name:             "127.0.0.1 blocked (permissive mode)",
			host:             "127.0.0.1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "loopback",
		},
		{
			name:             "127.1.2.3 blocked (loopback range)",
			host:             "127.1.2.3",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "loopback",
		},
		{
			name:             "::1 blocked (IPv6 loopback)",
			host:             "::1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "loopback",
		},

		// Private networks (always blocked)
		{
			name:             "10.0.0.1 blocked (private)",
			host:             "10.0.0.1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "private network",
		},
		{
			name:             "172.16.0.1 blocked (private)",
			host:             "172.16.0.1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "private network",
		},
		{
			name:             "192.168.1.1 blocked (private)",
			host:             "192.168.1.1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "private network",
		},
		{
			name:             "fc00::1 blocked (IPv6 private)",
			host:             "fc00::1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "private network",
		},

		// Link-local (always blocked)
		{
			name:             "169.254.1.1 blocked (link-local)",
			host:             "169.254.1.1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "link-local",
		},
		{
			name:             "fe80::1 blocked (IPv6 link-local)",
			host:             "fe80::1",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "link-local",
		},

		// Public IPs (should work in permissive mode)
		{
			name:             "8.8.8.8 blocked (strict mode - is IP)",
			host:             "8.8.8.8",
			allowCustomHosts: false,
			wantErr:          true,
			errContains:      "IP addresses are not allowed",
		},
		{
			name:             "8.8.8.8 allowed (permissive mode - public IP)",
			host:             "8.8.8.8",
			allowCustomHosts: true,
			wantErr:          false,
		},
		{
			name:             "1.1.1.1 allowed (permissive mode - public IP)",
			host:             "1.1.1.1",
			allowCustomHosts: true,
			wantErr:          false,
		},

		// Unspecified addresses (always blocked)
		{
			name:             "0.0.0.0 blocked",
			host:             "0.0.0.0",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "unspecified",
		},
		{
			name:             ":: blocked (IPv6 unspecified)",
			host:             "::",
			allowCustomHosts: true,
			wantErr:          true,
			errContains:      "unspecified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := HostValidationConfig{
				AllowCustomHosts: tt.allowCustomHosts,
			}
			err := ValidateHost(tt.host, config)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ValidateHost() expected error, got nil")
					return
				}
				if tt.errContains != "" && !contains(err.Error(), tt.errContains) {
					t.Errorf("ValidateHost() error = %q, should contain %q", err.Error(), tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("ValidateHost() unexpected error: %v", err)
				}
			}
		})
	}
}

// TestIsIPAddress tests IP address detection
func TestIsIPAddress(t *testing.T) {
	tests := []struct {
		input  string
		wantIP bool
	}{
		{"github.com", false},
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"fe80::1", true},
		{"2001:4860:4860::8888", true},
		{"not-an-ip", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := isIPAddress(tt.input)
			if result != tt.wantIP {
				t.Errorf("isIPAddress(%q) = %v, want %v", tt.input, result, tt.wantIP)
			}
		})
	}
}

// TestIsDangerousIP tests dangerous IP detection
func TestIsDangerousIP(t *testing.T) {
	tests := []struct {
		ip             string
		wantDangerous  bool
		reasonContains string
	}{
		{"127.0.0.1", true, "loopback"},
		{"localhost", false, ""}, // localhost resolves but ParseIP("localhost") returns nil
		{"::1", true, "loopback"},
		{"10.0.0.1", true, "private"},
		{"172.16.0.1", true, "private"},
		{"192.168.1.1", true, "private"},
		{"169.254.1.1", true, "link-local"},
		{"fe80::1", true, "link-local"},
		{"0.0.0.0", true, "unspecified"},
		{"::", true, "unspecified"},
		{"8.8.8.8", false, ""},
		{"1.1.1.1", false, ""},
		{"2001:4860:4860::8888", false, ""}, // Google Public DNS IPv6
		{"github.com", false, ""},           // Not an IP
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			isDangerous, reason := isDangerousIP(tt.ip)
			if isDangerous != tt.wantDangerous {
				t.Errorf("isDangerousIP(%q) = %v, want %v", tt.ip, isDangerous, tt.wantDangerous)
			}
			if tt.wantDangerous && !contains(reason, tt.reasonContains) {
				t.Errorf("isDangerousIP(%q) reason = %q, should contain %q", tt.ip, reason, tt.reasonContains)
			}
		})
	}
}
