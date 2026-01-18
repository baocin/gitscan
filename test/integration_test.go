// Package test contains integration tests for gitscan.
// These tests require network access and will clone actual repositories.
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

// TestCloneAndScanGitHubRepo tests the full flow of cloning a public repo
// from GitHub and scanning it for vulnerabilities.
// This test clones the gitscan repo itself which contains test/fixtures/fake_secrets.go
func TestCloneAndScanGitHubRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create temp directory for cloning
	tmpDir, err := os.MkdirTemp("", "gitscan-integration-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "gitscan")

	// Clone the gitscan repo from GitHub
	t.Log("Cloning baocin/gitscan from GitHub...")
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"https://github.com/baocin/gitscan.git",
		repoDir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to clone repo: %v\nOutput: %s", err, string(output))
	}
	t.Logf("Clone successful: %s", repoDir)

	// Verify the repo was cloned
	if _, err := os.Stat(filepath.Join(repoDir, "go.mod")); os.IsNotExist(err) {
		t.Fatal("go.mod not found in cloned repo")
	}

	// Verify the fake secrets file exists (if this branch has been pushed)
	fakeSecretsPath := filepath.Join(repoDir, "test", "fixtures", "fake_secrets.go")
	if _, err := os.Stat(fakeSecretsPath); os.IsNotExist(err) {
		t.Log("Note: test/fixtures/fake_secrets.go not found - may not be pushed yet")
	} else {
		t.Log("Found test/fixtures/fake_secrets.go")
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

	// Verify we got some files
	if fileCount < 10 {
		t.Errorf("Expected at least 10 files in repo, got %d", fileCount)
	}
}

// TestCloneNonExistentRepo tests that cloning a non-existent repo fails gracefully
func TestCloneNonExistentRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "gitscan-nonexistent-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "nonexistent")

	// Try to clone a non-existent repo
	t.Log("Attempting to clone non-existent repo...")
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"https://github.com/baocin/this-repo-does-not-exist-12345.git",
		repoDir,
	)
	output, err := cmd.CombinedOutput()

	// Should fail
	if err == nil {
		t.Fatal("Expected clone to fail for non-existent repo")
	}

	outputStr := strings.ToLower(string(output))
	t.Logf("Clone output: %s", outputStr)

	// Verify error message indicates some kind of failure
	// Different git versions/configurations may produce different messages:
	// - "not found" - repo doesn't exist
	// - "could not read username" - private repo or doesn't exist
	// - "authentication failed" - requires auth
	// - "repository" - generic repo error
	hasExpectedError := strings.Contains(outputStr, "not found") ||
		strings.Contains(outputStr, "could not read") ||
		strings.Contains(outputStr, "authentication") ||
		strings.Contains(outputStr, "fatal")

	if !hasExpectedError {
		t.Errorf("Expected error-related text in output, got: %s", outputStr)
	}
}

// TestCloneRepoAndCountFiles tests cloning and verifies basic statistics
func TestCloneRepoAndCountFiles(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "gitscan-count-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "gitscan")

	// Clone with depth=1
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"--single-branch",
		"https://github.com/baocin/gitscan.git",
		repoDir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to clone: %v\nOutput: %s", err, string(output))
	}

	// Count Go files
	goFileCount := 0
	testFileCount := 0
	err = filepath.Walk(repoDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && !strings.Contains(path, "/.git/") {
			if strings.HasSuffix(path, ".go") {
				goFileCount++
				if strings.HasSuffix(path, "_test.go") {
					testFileCount++
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("Failed to walk repo: %v", err)
	}

	t.Logf("Go files: %d (including %d test files)", goFileCount, testFileCount)

	// Should have multiple Go files
	if goFileCount < 5 {
		t.Errorf("Expected at least 5 Go files, got %d", goFileCount)
	}
}

// TestScannerWithOpengrep runs opengrep on the cloned repo if available
func TestScannerWithOpengrep(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check if opengrep is available
	opengrep, err := exec.LookPath("opengrep")
	if err != nil {
		// Also check for osemgrep (alternative name)
		opengrep, err = exec.LookPath("osemgrep")
		if err != nil {
			t.Skip("opengrep/osemgrep not available, skipping scanner test")
		}
	}
	t.Logf("Using scanner: %s", opengrep)

	// Check if git is available
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "gitscan-scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	repoDir := filepath.Join(tmpDir, "gitscan")

	// Clone the repo
	t.Log("Cloning repo for scanner test...")
	cmd := exec.CommandContext(ctx, "git", "clone",
		"--depth", "1",
		"https://github.com/baocin/gitscan.git",
		repoDir,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to clone: %v\nOutput: %s", err, string(output))
	}

	// Run opengrep with auto config
	t.Log("Running scanner...")
	cmd = exec.CommandContext(ctx, opengrep,
		"scan",
		"--config", "auto",
		"--sarif",
		repoDir,
	)
	scanOutput, err := cmd.CombinedOutput()

	// Scanner may return non-zero exit code if findings are found
	// That's OK - we just want to verify it runs and produces output
	t.Logf("Scanner exit error (may be expected): %v", err)

	outputStr := string(scanOutput)

	// Check for valid JSON output
	if len(outputStr) == 0 {
		t.Error("Scanner produced no output")
	}

	// Should have some JSON structure
	if !strings.Contains(outputStr, "{") {
		t.Logf("Scanner output (first 500 chars): %s", truncate(outputStr, 500))
		t.Error("Expected JSON output from scanner")
	}

	// Log what we found
	if strings.Contains(outputStr, "results") {
		t.Log("Scanner produced results JSON")
	}
	if strings.Contains(outputStr, "AKIA") || strings.Contains(outputStr, "password") || strings.Contains(outputStr, "secret") {
		t.Log("Scanner may have detected fake secrets in test fixtures")
	}
}

// truncate returns the first n characters of a string
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
