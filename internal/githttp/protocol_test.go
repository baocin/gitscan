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

// TestSSHProtocolParsing tests parsing of SSH protocol prefixes in URL paths
func TestSSHProtocolParsing(t *testing.T) {
	tests := []struct {
		name         string
		urlPath      string
		wantHost     string
		wantOwner    string
		wantRepo     string
		wantMode     string
		wantProtocol CloneProtocol
		wantErr      bool
	}{
		{
			name:         "ssh prefix alone",
			urlPath:      "/ssh/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "scan",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "ssh prefix with mode (ssh/json)",
			urlPath:      "/ssh/json/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "json",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "ssh prefix with clone mode (ssh/clone)",
			urlPath:      "/ssh/clone/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "clone",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "mode before ssh (clone/ssh)",
			urlPath:      "/clone/ssh/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "clone",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "json/ssh combo",
			urlPath:      "/json/ssh/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "json",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "plain/ssh combo",
			urlPath:      "/plain/ssh/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "plain",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "https by default (no ssh prefix)",
			urlPath:      "/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "scan",
			wantProtocol: ProtocolHTTPS,
		},
		{
			name:         "https with mode prefix",
			urlPath:      "/json/github.com/user/repo/info/refs",
			wantHost:     "github.com",
			wantOwner:    "user",
			wantRepo:     "repo",
			wantMode:     "json",
			wantProtocol: ProtocolHTTPS,
		},
		{
			name:         "ssh with gitlab",
			urlPath:      "/ssh/gitlab.com/org/project/info/refs",
			wantHost:     "gitlab.com",
			wantOwner:    "org",
			wantRepo:     "project",
			wantMode:     "scan",
			wantProtocol: ProtocolSSH,
		},
		{
			name:         "ssh with bitbucket",
			urlPath:      "/ssh/bitbucket.org/team/repo/info/refs",
			wantHost:     "bitbucket.org",
			wantOwner:    "team",
			wantRepo:     "repo",
			wantMode:     "scan",
			wantProtocol: ProtocolSSH,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRepoPathFull() expected error, got nil")
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
			if parsed.Protocol != tt.wantProtocol {
				t.Errorf("ParseRepoPathFull() Protocol = %q, want %q", parsed.Protocol, tt.wantProtocol)
			}
		})
	}
}

// TestGetSSHCloneURL tests SSH clone URL generation
func TestGetSSHCloneURL(t *testing.T) {
	tests := []struct {
		name        string
		urlPath     string
		wantSSHURL  string
		wantHTTPURL string
	}{
		{
			name:        "github repo",
			urlPath:     "/ssh/github.com/user/repo/info/refs",
			wantSSHURL:  "git@github.com:user/repo.git",
			wantHTTPURL: "https://github.com/user/repo.git",
		},
		{
			name:        "gitlab repo",
			urlPath:     "/ssh/gitlab.com/org/project/info/refs",
			wantSSHURL:  "git@gitlab.com:org/project.git",
			wantHTTPURL: "https://gitlab.com/org/project.git",
		},
		{
			name:        "bitbucket repo",
			urlPath:     "/ssh/bitbucket.org/team/repo/info/refs",
			wantSSHURL:  "git@bitbucket.org:team/repo.git",
			wantHTTPURL: "https://bitbucket.org/team/repo.git",
		},
		{
			name:        "repo with hyphen",
			urlPath:     "/ssh/github.com/facebook/create-react-app/info/refs",
			wantSSHURL:  "git@github.com:facebook/create-react-app.git",
			wantHTTPURL: "https://github.com/facebook/create-react-app.git",
		},
		{
			name:        "repo with dots",
			urlPath:     "/ssh/github.com/user/repo.js/info/refs",
			wantSSHURL:  "git@github.com:user/repo.js.git",
			wantHTTPURL: "https://github.com/user/repo.js.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)
			if err != nil {
				t.Fatalf("ParseRepoPathFull() failed: %v", err)
			}

			gotSSH := parsed.GetSSHCloneURL()
			if gotSSH != tt.wantSSHURL {
				t.Errorf("GetSSHCloneURL() = %q, want %q", gotSSH, tt.wantSSHURL)
			}

			gotHTTPS := parsed.GetHTTPSCloneURL()
			if gotHTTPS != tt.wantHTTPURL {
				t.Errorf("GetHTTPSCloneURL() = %q, want %q", gotHTTPS, tt.wantHTTPURL)
			}

			// Verify GetCloneURL returns SSH URL when protocol is SSH
			gotClone := parsed.GetCloneURL()
			if gotClone != tt.wantSSHURL {
				t.Errorf("GetCloneURL() with SSH protocol = %q, want %q", gotClone, tt.wantSSHURL)
			}
		})
	}
}

// TestGetCloneURLProtocolSelection tests that GetCloneURL respects the protocol setting
func TestGetCloneURLProtocolSelection(t *testing.T) {
	tests := []struct {
		name    string
		urlPath string
		wantURL string
	}{
		{
			name:    "default protocol (HTTPS)",
			urlPath: "/github.com/user/repo/info/refs",
			wantURL: "https://github.com/user/repo.git",
		},
		{
			name:    "explicit SSH protocol",
			urlPath: "/ssh/github.com/user/repo/info/refs",
			wantURL: "git@github.com:user/repo.git",
		},
		{
			name:    "SSH with mode prefix",
			urlPath: "/clone/ssh/github.com/user/repo/info/refs",
			wantURL: "git@github.com:user/repo.git",
		},
		{
			name:    "mode only (HTTPS)",
			urlPath: "/clone/github.com/user/repo/info/refs",
			wantURL: "https://github.com/user/repo.git",
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
