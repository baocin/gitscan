package githttp

import (
	"testing"
)

func TestParseRepoPathFull(t *testing.T) {
	tests := []struct {
		name         string
		urlPath      string
		wantMode     string
		wantHost     string
		wantOwner    string
		wantRepo     string
		wantFullPath string
		wantCloneURL string
		wantErr      bool
	}{
		{
			name:         "github standard",
			urlPath:      "/github.com/semgrep/semgrep/info/refs",
			wantMode:     "scan",
			wantHost:     "github.com",
			wantOwner:    "semgrep",
			wantRepo:     "semgrep",
			wantFullPath: "github.com/semgrep/semgrep",
			wantCloneURL: "https://github.com/semgrep/semgrep.git",
			wantErr:      false,
		},
		{
			name:         "github with .git suffix",
			urlPath:      "/github.com/WebGoat/WebGoat.git/info/refs",
			wantMode:     "scan",
			wantHost:     "github.com",
			wantOwner:    "WebGoat",
			wantRepo:     "WebGoat",
			wantFullPath: "github.com/WebGoat/WebGoat",
			wantCloneURL: "https://github.com/WebGoat/WebGoat.git",
			wantErr:      false,
		},
		{
			name:         "github upload-pack",
			urlPath:      "/github.com/owner/repo/git-upload-pack",
			wantMode:     "scan",
			wantHost:     "github.com",
			wantOwner:    "owner",
			wantRepo:     "repo",
			wantFullPath: "github.com/owner/repo",
			wantCloneURL: "https://github.com/owner/repo.git",
			wantErr:      false,
		},
		{
			name:         "with mode prefix",
			urlPath:      "/json/github.com/facebook/react/info/refs",
			wantMode:     "json",
			wantHost:     "github.com",
			wantOwner:    "facebook",
			wantRepo:     "react",
			wantFullPath: "github.com/facebook/react",
			wantCloneURL: "https://github.com/facebook/react.git",
			wantErr:      false,
		},
		{
			name:         "gitlab",
			urlPath:      "/gitlab.com/inkscape/inkscape/info/refs",
			wantMode:     "scan",
			wantHost:     "gitlab.com",
			wantOwner:    "inkscape",
			wantRepo:     "inkscape",
			wantFullPath: "gitlab.com/inkscape/inkscape",
			wantCloneURL: "https://gitlab.com/inkscape/inkscape.git",
			wantErr:      false,
		},
		{
			name:         "bitbucket",
			urlPath:      "/bitbucket.org/atlassian/python-bitbucket/info/refs",
			wantMode:     "scan",
			wantHost:     "bitbucket.org",
			wantOwner:    "atlassian",
			wantRepo:     "python-bitbucket",
			wantFullPath: "bitbucket.org/atlassian/python-bitbucket",
			wantCloneURL: "https://bitbucket.org/atlassian/python-bitbucket.git",
			wantErr:      false,
		},
		{
			name:    "unsupported host",
			urlPath: "/sourceforge.net/project/repo/info/refs",
			wantErr: true,
		},
		{
			name:    "missing repo",
			urlPath: "/github.com/owner/info/refs",
			wantErr: true,
		},
		{
			name:    "missing owner and repo",
			urlPath: "/github.com/info/refs",
			wantErr: true,
		},
		{
			name:    "empty path",
			urlPath: "/",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)

			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseRepoPathFull(%q) expected error, got nil", tt.urlPath)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseRepoPathFull(%q) unexpected error: %v", tt.urlPath, err)
			}

			if parsed.Mode != tt.wantMode {
				t.Errorf("Mode = %q, want %q", parsed.Mode, tt.wantMode)
			}
			if parsed.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", parsed.Host, tt.wantHost)
			}
			if parsed.Owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", parsed.Owner, tt.wantOwner)
			}
			if parsed.Repo != tt.wantRepo {
				t.Errorf("Repo = %q, want %q", parsed.Repo, tt.wantRepo)
			}
			if parsed.FullPath != tt.wantFullPath {
				t.Errorf("FullPath = %q, want %q", parsed.FullPath, tt.wantFullPath)
			}

			cloneURL := parsed.GetCloneURL()
			if cloneURL != tt.wantCloneURL {
				t.Errorf("GetCloneURL() = %q, want %q", cloneURL, tt.wantCloneURL)
			}
		})
	}
}

func TestGetCloneURLDoesNotDuplicateHost(t *testing.T) {
	// This test specifically verifies that the clone URL doesn't contain the host twice
	// Bug report: https://github.com/github.com/semgrep/semgrep.git/ was being produced
	// instead of https://github.com/semgrep/semgrep.git

	paths := []string{
		"/github.com/semgrep/semgrep/info/refs",
		"/github.com/WebGoat/WebGoat/info/refs",
		"/github.com/OWASP/NodeGoat/info/refs",
	}

	for _, path := range paths {
		parsed, err := ParseRepoPathFull(path)
		if err != nil {
			t.Fatalf("ParseRepoPathFull(%q) error: %v", path, err)
		}

		cloneURL := parsed.GetCloneURL()

		// The clone URL should NOT contain the host twice
		// A bug would produce: https://github.com/github.com/owner/repo.git
		if containsDuplicateHost(cloneURL, parsed.Host) {
			t.Errorf("GetCloneURL() = %q contains duplicate host %q", cloneURL, parsed.Host)
		}

		// Verify the URL structure is correct
		expectedPrefix := "https://" + parsed.Host + "/"
		if len(cloneURL) < len(expectedPrefix) {
			t.Errorf("GetCloneURL() = %q is too short", cloneURL)
			continue
		}

		afterHost := cloneURL[len(expectedPrefix):]
		// After the host, we should have owner/repo.git, NOT host/owner/repo.git
		if afterHost[:len(parsed.Host)] == parsed.Host {
			t.Errorf("GetCloneURL() = %q has host duplicated after prefix", cloneURL)
		}
	}
}

func containsDuplicateHost(url, host string) bool {
	// Count occurrences of host in URL
	count := 0
	for i := 0; i <= len(url)-len(host); i++ {
		if url[i:i+len(host)] == host {
			count++
		}
	}
	return count > 1
}

func TestGetAPIURL(t *testing.T) {
	tests := []struct {
		name       string
		urlPath    string
		wantAPIURL string
	}{
		{
			name:       "github",
			urlPath:    "/github.com/facebook/react/info/refs",
			wantAPIURL: "https://api.github.com/repos/facebook/react",
		},
		{
			name:       "gitlab",
			urlPath:    "/gitlab.com/inkscape/inkscape/info/refs",
			wantAPIURL: "https://gitlab.com/api/v4/projects/inkscape%2Finkscape",
		},
		{
			name:       "bitbucket",
			urlPath:    "/bitbucket.org/atlassian/python-bitbucket/info/refs",
			wantAPIURL: "https://api.bitbucket.org/2.0/repositories/atlassian/python-bitbucket",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := ParseRepoPathFull(tt.urlPath)
			if err != nil {
				t.Fatalf("ParseRepoPathFull error: %v", err)
			}

			apiURL := parsed.GetAPIURL()
			if apiURL != tt.wantAPIURL {
				t.Errorf("GetAPIURL() = %q, want %q", apiURL, tt.wantAPIURL)
			}
		})
	}
}

func TestParseRepoPath(t *testing.T) {
	// Test the simplified ParseRepoPath function
	mode, repoPath, err := ParseRepoPath("/github.com/owner/repo/info/refs")
	if err != nil {
		t.Fatalf("ParseRepoPath error: %v", err)
	}
	if mode != "scan" {
		t.Errorf("mode = %q, want %q", mode, "scan")
	}
	if repoPath != "owner/repo" {
		t.Errorf("repoPath = %q, want %q", repoPath, "owner/repo")
	}
}
