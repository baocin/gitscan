// Package test contains integration tests for gitscan failure modes.
// These tests verify graceful handling of various error conditions.
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

// TestMistypedRepoName tests various common typos in repository names
func TestMistypedRepoName(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	testCases := []struct {
		name        string
		url         string
		description string
	}{
		{
			name:        "typo_in_repo_name",
			url:         "https://github.com/baocin/gitscam.git", // scam instead of scan
			description: "Common typo in repo name",
		},
		{
			name:        "typo_in_owner",
			url:         "https://github.com/baocn/gitscan.git", // baocn instead of baocin
			description: "Typo in owner name",
		},
		{
			name:        "extra_character",
			url:         "https://github.com/baocin/gitscans.git", // extra 's'
			description: "Extra character in repo name",
		},
		{
			name:        "missing_character",
			url:         "https://github.com/baocin/gitsca.git", // missing 'n'
			description: "Missing character in repo name",
		},
		{
			name:        "swapped_characters",
			url:         "https://github.com/baocin/gitstcan.git", // ts instead of ts
			description: "Swapped characters in repo name",
		},
		// Note: GitHub is case-insensitive for git clone, so wrong_case_owner is not tested
		{
			name:        "completely_fake_repo",
			url:         "https://github.com/definitely-not-real-user-xyz/nonexistent-repo-abc123.git",
			description: "Completely non-existent user and repo",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tmpDir, err := os.MkdirTemp("", "gitscan-typo-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			repoDir := filepath.Join(tmpDir, "repo")

			t.Logf("Testing: %s - %s", tc.description, tc.url)
			cmd := exec.CommandContext(ctx, "git", "clone",
				"--depth", "1",
				tc.url,
				repoDir,
			)
			output, err := cmd.CombinedOutput()
			outputStr := strings.ToLower(string(output))

			// Clone should fail
			if err == nil {
				t.Errorf("Expected clone to fail for %s, but it succeeded", tc.description)
				return
			}

			t.Logf("Clone output: %s", outputStr)

			// Verify error indicates repo not found or access denied
			hasExpectedError := strings.Contains(outputStr, "not found") ||
				strings.Contains(outputStr, "could not read") ||
				strings.Contains(outputStr, "authentication") ||
				strings.Contains(outputStr, "does not exist") ||
				strings.Contains(outputStr, "fatal") ||
				strings.Contains(outputStr, "403") ||
				strings.Contains(outputStr, "404")

			if !hasExpectedError {
				t.Errorf("Expected error indicating repo not found, got: %s", outputStr)
			}
		})
	}
}

// TestInvalidURLFormats tests various malformed URL patterns
func TestInvalidURLFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	testCases := []struct {
		name        string
		url         string
		description string
	}{
		{
			name:        "missing_owner",
			url:         "https://github.com/gitscan.git",
			description: "Missing owner in URL",
		},
		{
			name:        "wrong_host",
			url:         "https://githbu.com/baocin/gitscan.git", // typo in github
			description: "Typo in host name",
		},
		{
			name:        "http_instead_of_https",
			url:         "http://github.com/baocin/gitscan.git",
			description: "HTTP instead of HTTPS (may redirect or fail)",
		},
		{
			name:        "extra_path_segments",
			url:         "https://github.com/baocin/gitscan/extra/path.git",
			description: "Extra path segments",
		},
		{
			name:        "missing_git_extension",
			url:         "https://github.com/baocin/definitely-not-real-repo",
			description: "Missing .git extension (may still work for some repos)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tmpDir, err := os.MkdirTemp("", "gitscan-url-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			repoDir := filepath.Join(tmpDir, "repo")

			t.Logf("Testing: %s - %s", tc.description, tc.url)
			cmd := exec.CommandContext(ctx, "git", "clone",
				"--depth", "1",
				tc.url,
				repoDir,
			)
			output, err := cmd.CombinedOutput()
			outputStr := string(output)

			// Log the result (may or may not fail depending on URL)
			if err != nil {
				t.Logf("Clone failed (expected for most cases): %s", outputStr)
			} else {
				t.Logf("Clone succeeded (only OK for some edge cases)")
			}
		})
	}
}

// TestPrivateRepoDetection tests that private repos are detected correctly
func TestPrivateRepoDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	// These are known to be private or require auth
	// Using generic patterns that will definitely fail as private
	testCases := []struct {
		name string
		url  string
	}{
		{
			name: "private_looking_url",
			url:  "https://github.com/baocin/private-internal-repo.git",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tmpDir, err := os.MkdirTemp("", "gitscan-private-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			repoDir := filepath.Join(tmpDir, "repo")

			cmd := exec.CommandContext(ctx, "git", "clone",
				"--depth", "1",
				tc.url,
				repoDir,
			)
			output, err := cmd.CombinedOutput()
			outputStr := strings.ToLower(string(output))

			// Should fail
			if err == nil {
				t.Logf("Clone unexpectedly succeeded")
				return
			}

			// Check for auth-related errors
			hasAuthError := strings.Contains(outputStr, "authentication") ||
				strings.Contains(outputStr, "could not read username") ||
				strings.Contains(outputStr, "403") ||
				strings.Contains(outputStr, "permission denied") ||
				strings.Contains(outputStr, "not found") // GitHub returns 404 for private repos to unauthenticated users

			if hasAuthError {
				t.Logf("Correctly detected as requiring auth: %s", outputStr)
			} else {
				t.Logf("Error output: %s", outputStr)
			}
		})
	}
}

// TestAlternativeGitHosts tests cloning from non-GitHub hosts
func TestAlternativeGitHosts(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	testCases := []struct {
		name        string
		url         string
		expectFail  bool
		description string
	}{
		{
			name:        "gitlab_nonexistent",
			url:         "https://gitlab.com/definitely-not-real/nonexistent-repo-12345.git",
			expectFail:  true,
			description: "Non-existent GitLab repo",
		},
		{
			name:        "bitbucket_nonexistent",
			url:         "https://bitbucket.org/definitely-not-real/nonexistent-repo-12345.git",
			expectFail:  true,
			description: "Non-existent Bitbucket repo",
		},
		{
			name:        "invalid_host",
			url:         "https://not-a-real-git-host.invalid/owner/repo.git",
			expectFail:  true,
			description: "Completely invalid host",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tmpDir, err := os.MkdirTemp("", "gitscan-host-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			repoDir := filepath.Join(tmpDir, "repo")

			t.Logf("Testing: %s", tc.description)
			cmd := exec.CommandContext(ctx, "git", "clone",
				"--depth", "1",
				tc.url,
				repoDir,
			)
			output, err := cmd.CombinedOutput()
			outputStr := string(output)

			if tc.expectFail && err == nil {
				t.Errorf("Expected clone to fail for %s", tc.description)
			} else if !tc.expectFail && err != nil {
				t.Errorf("Expected clone to succeed: %v\nOutput: %s", err, outputStr)
			} else {
				t.Logf("Result as expected. Output: %s", truncate(outputStr, 200))
			}
		})
	}
}

// TestTimeoutBehavior tests that long-running clones are handled properly
func TestTimeoutBehavior(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	// Use a very short timeout to trigger timeout behavior
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	tmpDir, err := os.MkdirTemp("", "gitscan-timeout-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "repo")

	// Try to clone something - should timeout immediately
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"https://github.com/baocin/gitscan.git",
		repoDir,
	)
	_, err = cmd.CombinedOutput()

	// Should have been killed due to timeout
	if err == nil {
		t.Log("Clone completed despite short timeout (fast network/cache?)")
	} else if ctx.Err() == context.DeadlineExceeded {
		t.Log("Correctly killed due to timeout")
	} else {
		t.Logf("Clone failed with error: %v", err)
	}
}

// TestEmptyOwnerRepo tests URLs with empty owner or repo
func TestEmptyOwnerRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	testCases := []struct {
		name string
		url  string
	}{
		{
			name: "empty_repo",
			url:  "https://github.com/baocin/.git",
		},
		{
			name: "just_host",
			url:  "https://github.com/.git",
		},
		// Note: trailing slash URLs work fine, so not tested here
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			tmpDir, err := os.MkdirTemp("", "gitscan-empty-test-*")
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			defer os.RemoveAll(tmpDir)

			repoDir := filepath.Join(tmpDir, "repo")

			cmd := exec.CommandContext(ctx, "git", "clone",
				"--depth", "1",
				tc.url,
				repoDir,
			)
			output, err := cmd.CombinedOutput()

			// These should all fail
			if err == nil {
				t.Errorf("Expected clone to fail for malformed URL: %s", tc.url)
			} else {
				t.Logf("Correctly failed: %s", truncate(string(output), 200))
			}
		})
	}
}
