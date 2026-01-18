// Package test contains integration tests for SSH cloning functionality.
package test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSSHCloneGitHubRepo tests cloning a public repo via SSH.
// This test requires:
// - SSH key configured for GitHub
// - Git with SSH support
func TestSSHCloneGitHubRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH integration test in short mode")
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping SSH integration test")
	}

	// Check if SSH agent is running and has keys
	sshAuthSock := os.Getenv("SSH_AUTH_SOCK")
	if sshAuthSock == "" {
		t.Skip("SSH_AUTH_SOCK not set, SSH agent not running - skipping SSH test")
	}

	// Check if we can connect to GitHub via SSH
	// This tests if SSH keys are properly configured
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", "-T", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "git@github.com")
	output, err := cmd.CombinedOutput()
	// GitHub returns exit code 1 with "successfully authenticated" message
	// This is expected behavior - GitHub doesn't allow shell access
	outputStr := string(output)
	if !strings.Contains(strings.ToLower(outputStr), "successfully authenticated") &&
		!strings.Contains(strings.ToLower(outputStr), "you've successfully authenticated") {
		t.Skipf("SSH authentication to GitHub failed, skipping test. Output: %s", outputStr)
	}
	t.Log("SSH authentication to GitHub verified")

	// Create temp directory for cloning
	tmpDir, err := os.MkdirTemp("", "gitscan-ssh-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "gitscan")

	// Clone using SSH URL
	t.Log("Cloning baocin/gitscan via SSH...")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd = exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"git@github.com:baocin/gitscan.git",
		repoDir,
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to clone repo via SSH: %v\nOutput: %s", err, string(output))
	}
	t.Logf("SSH Clone successful: %s", repoDir)

	// Verify the repo was cloned
	if _, err := os.Stat(filepath.Join(repoDir, "go.mod")); os.IsNotExist(err) {
		t.Fatal("go.mod not found in SSH-cloned repo")
	}

	// Get the commit SHA
	cmd = exec.CommandContext(ctx, "git", "-C", repoDir, "rev-parse", "HEAD")
	commitOutput, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get commit SHA: %v", err)
	}
	commitSHA := strings.TrimSpace(string(commitOutput))
	t.Logf("Commit SHA: %s", commitSHA)

	// Count files
	fileCount := 0
	err = filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.Contains(path, "/.git/") {
			fileCount++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to count files: %v", err)
	}
	t.Logf("File count: %d", fileCount)

	if fileCount < 10 {
		t.Errorf("Expected at least 10 files in repo, got %d", fileCount)
	}
}

// TestSSHCloneGitLabRepo tests cloning from GitLab via SSH
func TestSSHCloneGitLabRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SSH integration test in short mode")
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping SSH integration test")
	}

	// Check if SSH agent is running
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set, skipping SSH test")
	}

	// Check GitLab SSH authentication
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ssh", "-T", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "git@gitlab.com")
	output, err := cmd.CombinedOutput()
	outputStr := string(output)
	if !strings.Contains(strings.ToLower(outputStr), "welcome") &&
		!strings.Contains(strings.ToLower(outputStr), "authenticated") {
		t.Skipf("SSH authentication to GitLab failed, skipping test. Output: %s", outputStr)
	}
	t.Log("SSH authentication to GitLab verified")

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "gitscan-gitlab-ssh-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "inkscape")

	// Clone using SSH URL - inkscape is a public GitLab repo
	t.Log("Cloning inkscape/inkscape via SSH...")
	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cmd = exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"git@gitlab.com:inkscape/inkscape.git",
		repoDir,
	)
	output, err = cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to clone repo via SSH: %v\nOutput: %s", err, string(output))
	}
	t.Logf("SSH Clone successful: %s", repoDir)

	// Verify the repo was cloned
	if _, err := os.Stat(repoDir); os.IsNotExist(err) {
		t.Fatal("Repository directory not found after SSH clone")
	}
}

// TestSSHURLFormat tests that the SSH URL format is correct for various hosts
func TestSSHURLFormat(t *testing.T) {
	tests := []struct {
		name        string
		host        string
		owner       string
		repo        string
		expectedURL string
	}{
		{
			name:        "GitHub SSH URL",
			host:        "github.com",
			owner:       "facebook",
			repo:        "react",
			expectedURL: "git@github.com:facebook/react.git",
		},
		{
			name:        "GitLab SSH URL",
			host:        "gitlab.com",
			owner:       "inkscape",
			repo:        "inkscape",
			expectedURL: "git@gitlab.com:inkscape/inkscape.git",
		},
		{
			name:        "Bitbucket SSH URL",
			host:        "bitbucket.org",
			owner:       "atlassian",
			repo:        "python-bitbucket",
			expectedURL: "git@bitbucket.org:atlassian/python-bitbucket.git",
		},
		{
			name:        "Repo with hyphens",
			host:        "github.com",
			owner:       "facebook",
			repo:        "create-react-app",
			expectedURL: "git@github.com:facebook/create-react-app.git",
		},
		{
			name:        "Repo with numbers",
			host:        "github.com",
			owner:       "user123",
			repo:        "project456",
			expectedURL: "git@github.com:user123/project456.git",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build SSH URL manually using the same format
			sshURL := "git@" + tt.host + ":" + tt.owner + "/" + tt.repo + ".git"
			if sshURL != tt.expectedURL {
				t.Errorf("SSH URL = %q, want %q", sshURL, tt.expectedURL)
			}
		})
	}
}

// TestCompareSSHAndHTTPSCloneResults tests that SSH and HTTPS clones produce identical results
func TestCompareSSHAndHTTPSCloneResults(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping comparison integration test in short mode")
	}

	// Check prerequisites
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if os.Getenv("SSH_AUTH_SOCK") == "" {
		t.Skip("SSH_AUTH_SOCK not set")
	}

	// Check GitHub SSH auth
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ssh", "-T", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "git@github.com")
	output, _ := cmd.CombinedOutput()
	if !strings.Contains(strings.ToLower(string(output)), "authenticated") {
		t.Skip("SSH authentication to GitHub not available")
	}

	// Create temp directories
	tmpDir, err := os.MkdirTemp("", "gitscan-compare-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	sshDir := filepath.Join(tmpDir, "ssh-clone")
	httpsDir := filepath.Join(tmpDir, "https-clone")

	// Clone via SSH
	t.Log("Cloning via SSH...")
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cmd = exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"git@github.com:baocin/gitscan.git",
		sshDir,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("SSH clone failed: %v\nOutput: %s", err, string(output))
	}

	// Clone via HTTPS
	t.Log("Cloning via HTTPS...")
	cmd = exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"https://github.com/baocin/gitscan.git",
		httpsDir,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("HTTPS clone failed: %v\nOutput: %s", err, string(output))
	}

	// Compare commit SHAs
	sshSHA := getCommitSHA(t, sshDir)
	httpsSHA := getCommitSHA(t, httpsDir)

	if sshSHA != httpsSHA {
		t.Errorf("Commit SHAs differ: SSH=%s, HTTPS=%s", sshSHA, httpsSHA)
	}
	t.Logf("Both clones have same commit: %s", sshSHA)

	// Compare file counts (excluding .git)
	sshCount := countFiles(t, sshDir)
	httpsCount := countFiles(t, httpsDir)

	if sshCount != httpsCount {
		t.Errorf("File counts differ: SSH=%d, HTTPS=%d", sshCount, httpsCount)
	}
	t.Logf("Both clones have %d files", sshCount)
}

func getCommitSHA(t *testing.T, repoDir string) string {
	cmd := exec.Command("git", "-C", repoDir, "rev-parse", "HEAD")
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Failed to get commit SHA: %v", err)
	}
	return strings.TrimSpace(string(output))
}

func countFiles(t *testing.T, dir string) int {
	count := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.Contains(path, "/.git/") {
			count++
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to count files: %v", err)
	}
	return count
}
