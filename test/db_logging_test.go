// Package test contains tests for database logging functionality.
// These tests verify that all scan requests are properly logged to the database.
package test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baocin/gitscan/internal/db"
)

// TestLogRequestCreation tests that LogRequest properly creates database records
func TestLogRequestCreation(t *testing.T) {
	// Create a temporary database
	tmpDir, err := os.MkdirTemp("", "gitscan-db-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	// Create a test request
	req := &db.Request{
		IP:          "192.168.1.1",
		UserAgent:   "test-agent/1.0",
		RepoURL:     "github.com/test/repo",
		CommitSHA:   "abc123def456",
		RequestMode: "scan",
		CacheHit:    false,
		ResponseTimeMS: 1500,
	}

	// Log the request
	err = database.LogRequest(req)
	if err != nil {
		t.Fatalf("LogRequest failed: %v", err)
	}

	// Verify the request was assigned an ID
	if req.ID == 0 {
		t.Error("Request ID was not assigned")
	}

	// Verify created_at was set
	if req.CreatedAt.IsZero() {
		t.Error("CreatedAt was not set")
	}

	t.Logf("Created request with ID: %d", req.ID)
}

// TestLogRequestWithError tests that requests with errors are properly logged
func TestLogRequestWithError(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-error-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	// Create request with error
	req := &db.Request{
		IP:             "10.0.0.1",
		RepoURL:        "github.com/nonexistent/repo",
		RequestMode:    "scan",
		Error:          "repository not found",
		ResponseTimeMS: 500,
	}

	err = database.LogRequest(req)
	if err != nil {
		t.Fatalf("LogRequest with error failed: %v", err)
	}

	if req.ID == 0 {
		t.Error("Request ID was not assigned for error request")
	}

	t.Logf("Created error request with ID: %d", req.ID)
}

// TestLogRequestWithCacheHit tests that cache hit requests are properly logged
func TestLogRequestWithCacheHit(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-cache-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	// Create a repo first
	repo, err := database.CreateRepo("github.com/test/cached-repo", "/tmp/test-cached-repo")
	if err != nil {
		t.Fatalf("Failed to create repo: %v", err)
	}

	// Update repo with commit info
	err = database.UpdateRepoFetched(repo.ID, "cachedcommit123", 1024, 10)
	if err != nil {
		t.Fatalf("Failed to update repo: %v", err)
	}

	// Create a scan for this repo
	scan := &db.Scan{
		RepoID:        repo.ID,
		CommitSHA:     "cachedcommit123",
		ResultsJSON:   "[]",
		SecurityScore: 85,
		FilesScanned:  10,
		ScanDurationMS: 1000,
	}
	err = database.CreateScan(scan)
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Create cache hit request
	req := &db.Request{
		IP:             "172.16.0.1",
		RepoURL:        "github.com/test/cached-repo",
		CommitSHA:      "cachedcommit123",
		RequestMode:    "scan",
		ScanID:         &scan.ID,
		CacheHit:       true,
		ResponseTimeMS: 100, // Fast because of cache
	}

	err = database.LogRequest(req)
	if err != nil {
		t.Fatalf("LogRequest with cache hit failed: %v", err)
	}

	if req.ID == 0 {
		t.Error("Request ID was not assigned for cache hit request")
	}

	t.Logf("Created cache hit request with ID: %d, ScanID: %d", req.ID, *req.ScanID)
}

// TestLogRequestWithSSHFingerprint tests logging requests with SSH key fingerprints
func TestLogRequestWithSSHFingerprint(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-ssh-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	// Create request with SSH fingerprint
	req := &db.Request{
		IP:                "192.168.1.100",
		SSHKeyFingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
		RepoURL:           "github.com/test/ssh-repo",
		RequestMode:       "scan",
		ResponseTimeMS:    2000,
	}

	err = database.LogRequest(req)
	if err != nil {
		t.Fatalf("LogRequest with SSH fingerprint failed: %v", err)
	}

	if req.ID == 0 {
		t.Error("Request ID was not assigned for SSH request")
	}

	t.Logf("Created SSH request with ID: %d", req.ID)
}

// TestLogMultipleRequestsForRateLimiting tests that multiple requests can be logged and counted
func TestLogMultipleRequestsForRateLimiting(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-ratelimit-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	testIP := "10.20.30.40"
	testRepo := "github.com/test/ratelimit-repo"

	// Log multiple requests from the same IP
	for i := 0; i < 5; i++ {
		req := &db.Request{
			IP:             testIP,
			RepoURL:        testRepo,
			RequestMode:    "scan",
			ResponseTimeMS: int64(100 + i*10),
		}
		err = database.LogRequest(req)
		if err != nil {
			t.Fatalf("LogRequest %d failed: %v", i, err)
		}
	}

	// Count requests from this IP
	count, err := database.CountRecentRequestsByIP(testIP, 1*time.Minute)
	if err != nil {
		t.Fatalf("CountRecentRequestsByIP failed: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected 5 requests, got %d", count)
	}

	// Count requests from this IP to this repo
	repoCount, err := database.CountRecentRequestsByIPAndRepo(testIP, testRepo, 1*time.Minute)
	if err != nil {
		t.Fatalf("CountRecentRequestsByIPAndRepo failed: %v", err)
	}

	if repoCount != 5 {
		t.Errorf("Expected 5 repo requests, got %d", repoCount)
	}

	t.Logf("Logged %d requests, counted %d", 5, count)
}

// TestLogRequestModes tests logging requests with different modes
func TestLogRequestModes(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-modes-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	modes := []string{"scan", "clone", "json", "plain"}

	for _, mode := range modes {
		req := &db.Request{
			IP:             "192.168.1.1",
			RepoURL:        "github.com/test/mode-repo",
			RequestMode:    mode,
			ResponseTimeMS: 1000,
		}

		err = database.LogRequest(req)
		if err != nil {
			t.Fatalf("LogRequest with mode %q failed: %v", mode, err)
		}

		t.Logf("Logged request with mode %q, ID: %d", mode, req.ID)
	}
}

// TestScanAndRequestRelationship tests that scans and requests are properly linked
func TestScanAndRequestRelationship(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-relationship-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	// Create a repo
	repo, err := database.CreateRepo("github.com/test/linked-repo", "/tmp/test-linked-repo")
	if err != nil {
		t.Fatalf("Failed to create repo: %v", err)
	}

	// Create a scan
	scan := &db.Scan{
		RepoID:         repo.ID,
		CommitSHA:      "linkedcommit789",
		ResultsJSON:    `[{"rule":"test-rule","severity":"high"}]`,
		CriticalCount:  0,
		HighCount:      1,
		MediumCount:    0,
		LowCount:       0,
		SecurityScore:  85,
		FilesScanned:   25,
		ScanDurationMS: 3000,
	}
	err = database.CreateScan(scan)
	if err != nil {
		t.Fatalf("Failed to create scan: %v", err)
	}

	// Create a request linked to this scan
	req := &db.Request{
		IP:             "192.168.1.1",
		RepoURL:        "github.com/test/linked-repo",
		CommitSHA:      "linkedcommit789",
		RequestMode:    "scan",
		ScanID:         &scan.ID,
		CacheHit:       false,
		ResponseTimeMS: 5000,
	}
	err = database.LogRequest(req)
	if err != nil {
		t.Fatalf("LogRequest failed: %v", err)
	}

	// Verify the relationship
	if req.ScanID == nil || *req.ScanID != scan.ID {
		t.Errorf("Request not properly linked to scan: expected ScanID %d, got %v", scan.ID, req.ScanID)
	}

	// Retrieve the scan by commit prefix
	retrievedScan, err := database.GetScanByCommitPrefix("linked")
	if err != nil {
		t.Fatalf("GetScanByCommitPrefix failed: %v", err)
	}
	if retrievedScan == nil {
		t.Fatal("Scan not found by commit prefix")
	}
	if retrievedScan.ID != scan.ID {
		t.Errorf("Retrieved wrong scan: expected ID %d, got %d", scan.ID, retrievedScan.ID)
	}

	t.Logf("Successfully linked Request %d to Scan %d", req.ID, scan.ID)
}

// TestLogAllScanScenarios tests that logging occurs for all scan scenarios
func TestLogAllScanScenarios(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-scenarios-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	testIP := "10.0.0.100"

	// Scenario 1: Successful scan (no cache)
	req1 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario1",
		CommitSHA:      "commit1",
		RequestMode:    "scan",
		CacheHit:       false,
		ResponseTimeMS: 5000,
	}
	if err := database.LogRequest(req1); err != nil {
		t.Fatalf("Scenario 1 (success) failed: %v", err)
	}

	// Scenario 2: Cache hit
	req2 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario2",
		CommitSHA:      "commit2",
		RequestMode:    "scan",
		CacheHit:       true,
		ResponseTimeMS: 100,
	}
	if err := database.LogRequest(req2); err != nil {
		t.Fatalf("Scenario 2 (cache hit) failed: %v", err)
	}

	// Scenario 3: Fetch error (repo not found)
	req3 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario3",
		RequestMode:    "scan",
		Error:          "fetch error: repository not found",
		ResponseTimeMS: 2000,
	}
	if err := database.LogRequest(req3); err != nil {
		t.Fatalf("Scenario 3 (fetch error) failed: %v", err)
	}

	// Scenario 4: Scan error
	req4 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario4",
		CommitSHA:      "commit4",
		RequestMode:    "scan",
		Error:          "scan error: opengrep timeout",
		ResponseTimeMS: 60000,
	}
	if err := database.LogRequest(req4); err != nil {
		t.Fatalf("Scenario 4 (scan error) failed: %v", err)
	}

	// Scenario 5: Client disconnected
	req5 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario5",
		RequestMode:    "scan",
		Error:          "client disconnected",
		ResponseTimeMS: 1000,
	}
	if err := database.LogRequest(req5); err != nil {
		t.Fatalf("Scenario 5 (client disconnected) failed: %v", err)
	}

	// Scenario 6: Disk space error
	req6 := &db.Request{
		IP:             testIP,
		RepoURL:        "github.com/test/scenario6",
		RequestMode:    "scan",
		Error:          "server disk space low",
		ResponseTimeMS: 50,
	}
	if err := database.LogRequest(req6); err != nil {
		t.Fatalf("Scenario 6 (disk space) failed: %v", err)
	}

	// Verify all requests were logged
	count, err := database.CountRecentRequestsByIP(testIP, 1*time.Minute)
	if err != nil {
		t.Fatalf("CountRecentRequestsByIP failed: %v", err)
	}

	if count != 6 {
		t.Errorf("Expected 6 requests for all scenarios, got %d", count)
	}

	t.Logf("Successfully logged all %d scan scenarios", count)
}

// TestSuspiciousRequestLogging tests logging of suspicious requests
func TestSuspiciousRequestLogging(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-suspicious-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	testIP := "192.168.100.1"

	// Log suspicious requests
	suspiciousPaths := []string{
		"/.env",
		"/admin",
		"/.git/config",
		"/wp-admin",
		"/.ssh/id_rsa",
	}

	for _, path := range suspiciousPaths {
		err = database.LogSuspiciousRequest(testIP, path, "suspicious-agent/1.0")
		if err != nil {
			t.Fatalf("LogSuspiciousRequest failed for path %q: %v", path, err)
		}
	}

	// Count suspicious requests
	count, err := database.CountRecentSuspiciousRequests(testIP, 1*time.Minute)
	if err != nil {
		t.Fatalf("CountRecentSuspiciousRequests failed: %v", err)
	}

	if count != len(suspiciousPaths) {
		t.Errorf("Expected %d suspicious requests, got %d", len(suspiciousPaths), count)
	}

	t.Logf("Successfully logged %d suspicious requests", count)
}

// TestIPBanning tests IP banning functionality
func TestIPBanning(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "gitscan-db-ban-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	dbPath := filepath.Join(tmpDir, "test.db")
	database, err := db.New(dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}
	defer database.Close()

	testIP := "10.10.10.10"
	reason := "automated scanning detected"

	// Ban the IP for 24 hours
	err = database.BanIP(testIP, reason, 24*time.Hour)
	if err != nil {
		t.Fatalf("BanIP failed: %v", err)
	}

	// Check if IP is banned
	banned, bannedReason, err := database.IsIPBanned(testIP)
	if err != nil {
		t.Fatalf("IsIPBanned failed: %v", err)
	}

	if !banned {
		t.Error("IP should be banned")
	}
	if bannedReason != reason {
		t.Errorf("Ban reason = %q, want %q", bannedReason, reason)
	}

	// Check an IP that's not banned
	notBanned, _, err := database.IsIPBanned("1.2.3.4")
	if err != nil {
		t.Fatalf("IsIPBanned for non-banned IP failed: %v", err)
	}
	if notBanned {
		t.Error("IP 1.2.3.4 should not be banned")
	}

	t.Logf("Successfully banned IP %s with reason: %s", testIP, reason)
}
