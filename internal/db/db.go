package db

import (
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

//go:embed schema.sql
var schemaSQL string

// DB wraps the SQLite database connection
type DB struct {
	conn *sql.DB
}

// New creates a new database connection and initializes the schema
func New(dbPath string) (*DB, error) {
	conn, err := sql.Open("sqlite3", dbPath+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Set connection pool settings
	conn.SetMaxOpenConns(1) // SQLite only supports one writer
	conn.SetMaxIdleConns(1)
	conn.SetConnMaxLifetime(time.Hour)

	// Initialize schema
	if _, err := conn.Exec(schemaSQL); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	// Run migrations
	db := &DB{conn: conn}
	if err := db.runMigrations(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return db, nil
}

// runMigrations applies any pending database migrations
func (db *DB) runMigrations() error {
	// Add license column to repos table if it doesn't exist
	_, err := db.conn.Exec(`ALTER TABLE repos ADD COLUMN license TEXT`)
	if err != nil {
		// Ignore error if column already exists
		if !isColumnExistsError(err) {
			return err
		}
	}

	// Add scan_level column to scans table
	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN scan_level TEXT DEFAULT 'normal'`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	// Add cached_file_count column to scans table
	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN cached_file_count INTEGER DEFAULT 0`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	// Add scanned_file_count column to scans table
	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN scanned_file_count INTEGER DEFAULT 0`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	// Add comprehensive request logging columns
	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN referer TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN git_version TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN request_type TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN http_method TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN success BOOLEAN DEFAULT TRUE`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE requests ADD COLUMN query_params TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	// Add partial scan tracking columns
	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN is_partial BOOLEAN DEFAULT FALSE`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN partial_reason TEXT`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	// Add info_leak_count column to scans table
	_, err = db.conn.Exec(`ALTER TABLE scans ADD COLUMN info_leak_count INTEGER DEFAULT 0`)
	if err != nil && !isColumnExistsError(err) {
		return err
	}

	return nil
}

// isColumnExistsError checks if the error is a "column already exists" error
func isColumnExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return strings.Contains(errStr, "duplicate column name") ||
		strings.Contains(errStr, "SQLITE_ERROR")
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
}

// ResetTables clears all data from the database tables
// This is useful for fresh starts during development or testing
func (db *DB) ResetTables() error {
	tables := []string{
		"scans",
		"requests",
		"repos",
		"banned_ips",
		"suspicious_requests",
	}

	var deletedCounts []string
	for _, table := range tables {
		// Count rows before deletion
		var count int
		err := db.conn.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&count)
		if err != nil {
			// Table might not exist, skip it
			continue
		}

		// Delete all rows
		_, err = db.conn.Exec(fmt.Sprintf("DELETE FROM %s", table))
		if err != nil {
			return fmt.Errorf("failed to clear table %s: %w", table, err)
		}

		if count > 0 {
			deletedCounts = append(deletedCounts, fmt.Sprintf("%s: %d", table, count))
		}
	}

	// Run VACUUM to reclaim disk space
	if _, err := db.conn.Exec("VACUUM"); err != nil {
		// VACUUM can fail, but it's not critical
		fmt.Printf("Warning: VACUUM failed: %v\n", err)
	}

	if len(deletedCounts) > 0 {
		fmt.Printf("Database reset: cleared %s\n", strings.Join(deletedCounts, ", "))
	} else {
		fmt.Println("Database reset: no data to clear")
	}

	return nil
}

// Repo represents a cached repository
type Repo struct {
	ID            int64
	URL           string
	LocalPath     string
	DefaultBranch string
	LastCommitSHA string
	LastFetchedAt time.Time
	SizeBytes     int64
	FileCount     int
	License       string
	CreatedAt     time.Time
}

// Scan represents a scan result
type Scan struct {
	ID               int64
	RepoID           int64
	CommitSHA        string
	ResultsJSON      string
	SummaryJSON      string
	InfoLeakCount    int // Data exfiltration / credential theft findings
	CriticalCount    int
	HighCount        int
	MediumCount      int
	LowCount         int
	InfoCount        int
	SecurityScore    int // 0-100 run risk score (0=safe, 100=dangerous)
	FilesScanned     int
	ScanDurationMS   int64
	OpenGrepVersion  string
	RulesVersion     string
	ScanLevel        string // 'quick', 'normal', 'thorough'
	CachedFileCount  int    // Number of files reused from cache
	ScannedFileCount int    // Number of files actually scanned
	IsPartial        bool   // True if scan timed out with partial results
	PartialReason    string // Why partial: "timeout after 3m", etc.
	CreatedAt        time.Time
}

// Request represents a request log entry
type Request struct {
	ID                int64
	IP                string
	SSHKeyFingerprint string
	UserAgent         string
	Referer           string
	GitVersion        string
	RepoURL           string
	CommitSHA         string
	RequestMode       string
	RequestType       string // 'info_refs', 'upload_pack'
	HTTPMethod        string // 'GET', 'POST'
	ScanID            *int64
	CacheHit          bool
	Success           bool
	ResponseTimeMS    int64
	QueryParams       string // JSON
	Error             string
	CreatedAt         time.Time
}

// GetRepoByURL retrieves a repo by its URL
func (db *DB) GetRepoByURL(url string) (*Repo, error) {
	row := db.conn.QueryRow(`
		SELECT id, url, local_path, default_branch, last_commit_sha,
		       last_fetched_at, size_bytes, file_count, license, created_at
		FROM repos WHERE url = ?
	`, url)

	var r Repo
	var lastFetched, created sql.NullTime
	var defaultBranch, lastCommit, license sql.NullString
	var sizeBytes, fileCount sql.NullInt64

	err := row.Scan(&r.ID, &r.URL, &r.LocalPath, &defaultBranch, &lastCommit,
		&lastFetched, &sizeBytes, &fileCount, &license, &created)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	r.DefaultBranch = defaultBranch.String
	r.LastCommitSHA = lastCommit.String
	r.LastFetchedAt = lastFetched.Time
	r.SizeBytes = sizeBytes.Int64
	r.FileCount = int(fileCount.Int64)
	r.License = license.String
	r.CreatedAt = created.Time

	return &r, nil
}

// CreateRepo creates a new repo record
func (db *DB) CreateRepo(url, localPath string) (*Repo, error) {
	result, err := db.conn.Exec(`
		INSERT INTO repos (url, local_path) VALUES (?, ?)
	`, url, localPath)
	if err != nil {
		return nil, err
	}

	id, _ := result.LastInsertId()
	return &Repo{
		ID:        id,
		URL:       url,
		LocalPath: localPath,
		CreatedAt: time.Now(),
	}, nil
}

// UpdateRepoFetched updates the repo after a successful fetch
func (db *DB) UpdateRepoFetched(id int64, commitSHA string, sizeBytes int64, fileCount int) error {
	_, err := db.conn.Exec(`
		UPDATE repos
		SET last_commit_sha = ?, last_fetched_at = ?, size_bytes = ?, file_count = ?
		WHERE id = ?
	`, commitSHA, time.Now(), sizeBytes, fileCount, id)
	return err
}

// UpdateRepoLicense updates the repo's detected license
func (db *DB) UpdateRepoLicense(id int64, license string) error {
	_, err := db.conn.Exec(`UPDATE repos SET license = ? WHERE id = ?`, license, id)
	return err
}

// GetScanByRepoAndCommit retrieves a cached scan result
func (db *DB) GetScanByRepoAndCommit(repoID int64, commitSHA string) (*Scan, error) {
	row := db.conn.QueryRow(`
		SELECT id, repo_id, commit_sha, results_json, summary_json,
		       COALESCE(info_leak_count, 0), critical_count, high_count, medium_count, low_count, info_count,
		       COALESCE(security_score, 0), files_scanned, scan_duration_ms,
		       opengrep_version, rules_version, created_at,
		       COALESCE(scan_level, 'normal'), COALESCE(cached_file_count, 0), COALESCE(scanned_file_count, 0),
		       COALESCE(is_partial, FALSE), partial_reason
		FROM scans WHERE repo_id = ? AND commit_sha = ?
	`, repoID, commitSHA)

	var s Scan
	var summaryJSON sql.NullString
	var filesScanned sql.NullInt64
	var openGrepVer, rulesVer, partialReason sql.NullString

	err := row.Scan(&s.ID, &s.RepoID, &s.CommitSHA, &s.ResultsJSON, &summaryJSON,
		&s.InfoLeakCount, &s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
		&s.SecurityScore, &filesScanned, &s.ScanDurationMS, &openGrepVer, &rulesVer, &s.CreatedAt,
		&s.ScanLevel, &s.CachedFileCount, &s.ScannedFileCount,
		&s.IsPartial, &partialReason)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.SummaryJSON = summaryJSON.String
	s.FilesScanned = int(filesScanned.Int64)
	s.OpenGrepVersion = openGrepVer.String
	s.RulesVersion = rulesVer.String
	s.PartialReason = partialReason.String

	return &s, nil
}

// CreateScan creates a new scan record
func (db *DB) CreateScan(scan *Scan) error {
	result, err := db.conn.Exec(`
		INSERT INTO scans (repo_id, commit_sha, results_json, summary_json,
		                   info_leak_count, critical_count, high_count, medium_count, low_count, info_count,
		                   security_score, files_scanned, scan_duration_ms, opengrep_version, rules_version,
		                   scan_level, cached_file_count, scanned_file_count,
		                   is_partial, partial_reason)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scan.RepoID, scan.CommitSHA, scan.ResultsJSON, scan.SummaryJSON,
		scan.InfoLeakCount, scan.CriticalCount, scan.HighCount, scan.MediumCount, scan.LowCount, scan.InfoCount,
		scan.SecurityScore, scan.FilesScanned, scan.ScanDurationMS, scan.OpenGrepVersion, scan.RulesVersion,
		scan.ScanLevel, scan.CachedFileCount, scan.ScannedFileCount,
		scan.IsPartial, nullString(scan.PartialReason))
	if err != nil {
		return err
	}

	scan.ID, _ = result.LastInsertId()
	scan.CreatedAt = time.Now()
	return nil
}

// LogRequest logs a request for analytics and rate limiting
func (db *DB) LogRequest(req *Request) error {
	result, err := db.conn.Exec(`
		INSERT INTO requests (ip, ssh_key_fingerprint, user_agent, referer, git_version,
		                      repo_url, commit_sha, request_mode, request_type, http_method,
		                      scan_id, cache_hit, success, response_time_ms, query_params, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.IP, nullString(req.SSHKeyFingerprint), nullString(req.UserAgent), nullString(req.Referer),
		nullString(req.GitVersion), req.RepoURL, nullString(req.CommitSHA), nullString(req.RequestMode),
		nullString(req.RequestType), nullString(req.HTTPMethod), req.ScanID, req.CacheHit, req.Success,
		req.ResponseTimeMS, nullString(req.QueryParams), nullString(req.Error))
	if err != nil {
		return err
	}

	req.ID, _ = result.LastInsertId()
	req.CreatedAt = time.Now()
	return nil
}

// CountRecentRequestsByIP counts requests from an IP in the last duration
func (db *DB) CountRecentRequestsByIP(ip string, duration time.Duration) (int, error) {
	var count int
	since := time.Now().Add(-duration)
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM requests WHERE ip = ? AND created_at > ?
	`, ip, since).Scan(&count)
	return count, err
}

// CountRecentRequestsByIPAndRepo counts requests from an IP to a specific repo
func (db *DB) CountRecentRequestsByIPAndRepo(ip, repoURL string, duration time.Duration) (int, error) {
	var count int
	since := time.Now().Add(-duration)
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM requests WHERE ip = ? AND repo_url = ? AND created_at > ?
	`, ip, repoURL, since).Scan(&count)
	return count, err
}

// CountRecentRequestsBySSHKey counts requests from an SSH key in the last duration
func (db *DB) CountRecentRequestsBySSHKey(fingerprint string, duration time.Duration) (int, error) {
	var count int
	since := time.Now().Add(-duration)
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM requests WHERE ssh_key_fingerprint = ? AND created_at > ?
	`, fingerprint, since).Scan(&count)
	return count, err
}

func nullString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// ScanWithRepo represents a scan with its associated repo info
type ScanWithRepo struct {
	Scan
	RepoURL string
	License string
}

// GetScanByCommitPrefix retrieves a scan by commit SHA prefix (for report URLs)
func (db *DB) GetScanByCommitPrefix(commitPrefix string) (*ScanWithRepo, error) {
	row := db.conn.QueryRow(`
		SELECT s.id, s.repo_id, s.commit_sha, s.results_json, s.summary_json,
		       s.critical_count, s.high_count, s.medium_count, s.low_count, s.info_count,
		       COALESCE(s.security_score, 100), s.files_scanned, s.scan_duration_ms,
		       s.opengrep_version, s.rules_version, s.created_at,
		       r.url, r.license
		FROM scans s
		JOIN repos r ON s.repo_id = r.id
		WHERE s.commit_sha LIKE ?
		ORDER BY s.created_at DESC
		LIMIT 1
	`, commitPrefix+"%")

	var s ScanWithRepo
	var summaryJSON sql.NullString
	var filesScanned sql.NullInt64
	var openGrepVer, rulesVer, license sql.NullString

	err := row.Scan(&s.ID, &s.RepoID, &s.CommitSHA, &s.ResultsJSON, &summaryJSON,
		&s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
		&s.SecurityScore, &filesScanned, &s.ScanDurationMS, &openGrepVer, &rulesVer, &s.CreatedAt,
		&s.RepoURL, &license)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.SummaryJSON = summaryJSON.String
	s.FilesScanned = int(filesScanned.Int64)
	s.OpenGrepVersion = openGrepVer.String
	s.RulesVersion = rulesVer.String
	s.License = license.String

	return &s, nil
}

// GetScansByRepo retrieves all scans for a repository URL
func (db *DB) GetScansByRepo(repoURL string, limit int) ([]ScanWithRepo, error) {
	if limit <= 0 {
		limit = 50 // Default limit
	}

	rows, err := db.conn.Query(`
		SELECT s.id, s.repo_id, s.commit_sha, s.results_json, s.summary_json,
		       s.critical_count, s.high_count, s.medium_count, s.low_count, s.info_count,
		       COALESCE(s.security_score, 100), s.files_scanned, s.scan_duration_ms,
		       s.opengrep_version, s.rules_version, s.created_at,
		       r.url, r.license
		FROM scans s
		JOIN repos r ON s.repo_id = r.id
		WHERE r.url = ?
		ORDER BY s.created_at DESC
		LIMIT ?
	`, repoURL, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []ScanWithRepo
	for rows.Next() {
		var s ScanWithRepo
		var summaryJSON sql.NullString
		var filesScanned sql.NullInt64
		var openGrepVer, rulesVer, license sql.NullString

		err := rows.Scan(&s.ID, &s.RepoID, &s.CommitSHA, &s.ResultsJSON, &summaryJSON,
			&s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
			&s.SecurityScore, &filesScanned, &s.ScanDurationMS, &openGrepVer, &rulesVer, &s.CreatedAt,
			&s.RepoURL, &license)
		if err != nil {
			return nil, err
		}

		s.SummaryJSON = summaryJSON.String
		s.FilesScanned = int(filesScanned.Int64)
		s.OpenGrepVersion = openGrepVer.String
		s.RulesVersion = rulesVer.String
		s.License = license.String

		scans = append(scans, s)
	}

	return scans, rows.Err()
}

// GetLatestScanByRepo retrieves the most recent scan for a repository
func (db *DB) GetLatestScanByRepo(repoURL string) (*ScanWithRepo, error) {
	row := db.conn.QueryRow(`
		SELECT s.id, s.repo_id, s.commit_sha, s.results_json, s.summary_json,
		       s.critical_count, s.high_count, s.medium_count, s.low_count, s.info_count,
		       COALESCE(s.security_score, 100), s.files_scanned, s.scan_duration_ms,
		       s.opengrep_version, s.rules_version, s.created_at,
		       r.url, r.license
		FROM scans s
		JOIN repos r ON s.repo_id = r.id
		WHERE r.url = ?
		ORDER BY s.created_at DESC
		LIMIT 1
	`, repoURL)

	var s ScanWithRepo
	var summaryJSON sql.NullString
	var filesScanned sql.NullInt64
	var openGrepVer, rulesVer, license sql.NullString

	err := row.Scan(&s.ID, &s.RepoID, &s.CommitSHA, &s.ResultsJSON, &summaryJSON,
		&s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
		&s.SecurityScore, &filesScanned, &s.ScanDurationMS, &openGrepVer, &rulesVer, &s.CreatedAt,
		&s.RepoURL, &license)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	s.SummaryJSON = summaryJSON.String
	s.FilesScanned = int(filesScanned.Int64)
	s.OpenGrepVersion = openGrepVer.String
	s.RulesVersion = rulesVer.String
	s.License = license.String

	return &s, nil
}

// GetTopScannedRepos returns repositories with the most scans
func (db *DB) GetTopScannedRepos(limit int) ([]struct {
	URL       string
	ScanCount int
	LastScan  time.Time
}, error) {
	if limit <= 0 {
		limit = 10
	}

	rows, err := db.conn.Query(`
		SELECT r.url, COUNT(s.id) as scan_count, MAX(s.created_at) as last_scan
		FROM repos r
		JOIN scans s ON r.id = s.repo_id
		GROUP BY r.url
		ORDER BY scan_count DESC, last_scan DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []struct {
		URL       string
		ScanCount int
		LastScan  time.Time
	}

	for rows.Next() {
		var item struct {
			URL       string
			ScanCount int
			LastScan  time.Time
		}
		if err := rows.Scan(&item.URL, &item.ScanCount, &item.LastScan); err != nil {
			return nil, err
		}
		results = append(results, item)
	}

	return results, rows.Err()
}

// GetLargestRepo returns the repository with the most files
func (db *DB) GetLargestRepo() (*struct {
	URL       string
	FileCount int
	SizeBytes int64
}, error) {
	row := db.conn.QueryRow(`
		SELECT url, file_count, size_bytes
		FROM repos
		WHERE file_count IS NOT NULL
		ORDER BY file_count DESC
		LIMIT 1
	`)

	var result struct {
		URL       string
		FileCount int
		SizeBytes int64
	}

	var fileCount, sizeBytes sql.NullInt64
	err := row.Scan(&result.URL, &fileCount, &sizeBytes)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	result.FileCount = int(fileCount.Int64)
	result.SizeBytes = sizeBytes.Int64

	return &result, nil
}

// GetRecentScans returns recent scans across all repositories
func (db *DB) GetRecentScans(limit int) ([]struct {
	RepoURL      string
	CommitSHA    string
	ScannedAt    time.Time
	DurationMS   int64
	TotalCount   int
}, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := db.conn.Query(`
		SELECT r.url, s.commit_sha, s.created_at, s.scan_duration_ms,
		       (s.critical_count + s.high_count + s.medium_count + s.low_count) as total_findings
		FROM scans s
		JOIN repos r ON s.repo_id = r.id
		ORDER BY s.created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []struct {
		RepoURL      string
		CommitSHA    string
		ScannedAt    time.Time
		DurationMS   int64
		TotalCount   int
	}

	for rows.Next() {
		var item struct {
			RepoURL      string
			CommitSHA    string
			ScannedAt    time.Time
			DurationMS   int64
			TotalCount   int
		}

		var durationMS sql.NullInt64
		if err := rows.Scan(&item.RepoURL, &item.CommitSHA, &item.ScannedAt, &durationMS, &item.TotalCount); err != nil {
			return nil, err
		}
		item.DurationMS = durationMS.Int64
		results = append(results, item)
	}

	return results, rows.Err()
}

// GetTotalRepoCount returns the total number of unique repositories scanned
func (db *DB) GetTotalRepoCount() (int, error) {
	var count int
	err := db.conn.QueryRow(`SELECT COUNT(*) FROM repos`).Scan(&count)
	return count, err
}

// GetRecentFailedRequests retrieves recent failed clone/scan requests
func (db *DB) GetRecentFailedRequests(limit int) ([]struct {
	RepoURL     string
	Error       string
	RequestMode string
	CreatedAt   time.Time
}, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := db.conn.Query(`
		SELECT repo_url, error, request_mode, created_at
		FROM requests
		WHERE success = FALSE AND error IS NOT NULL AND error != ''
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []struct {
		RepoURL     string
		Error       string
		RequestMode string
		CreatedAt   time.Time
	}

	for rows.Next() {
		var r struct {
			RepoURL     string
			Error       string
			RequestMode string
			CreatedAt   time.Time
		}
		var requestMode sql.NullString
		if err := rows.Scan(&r.RepoURL, &r.Error, &requestMode, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.RequestMode = requestMode.String
		results = append(results, r)
	}

	return results, rows.Err()
}

// LogSuspiciousRequest logs a suspicious request attempt
func (db *DB) LogSuspiciousRequest(ip, path, userAgent string) error {
	_, err := db.conn.Exec(`
		INSERT INTO suspicious_requests (ip, path, user_agent)
		VALUES (?, ?, ?)
	`, ip, path, nullString(userAgent))
	return err
}

// CountRecentSuspiciousRequests counts suspicious requests from an IP in the last duration
func (db *DB) CountRecentSuspiciousRequests(ip string, duration time.Duration) (int, error) {
	var count int
	since := time.Now().Add(-duration)
	err := db.conn.QueryRow(`
		SELECT COUNT(*) FROM suspicious_requests WHERE ip = ? AND created_at > ?
	`, ip, since).Scan(&count)
	return count, err
}

// BanIP adds an IP to the ban list
func (db *DB) BanIP(ip, reason string, duration time.Duration) error {
	var expiresAt interface{}
	if duration > 0 {
		expiresAt = time.Now().Add(duration)
	} // else NULL for permanent ban

	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at, expires_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
	`, ip, reason, expiresAt)
	return err
}

// IsIPBanned checks if an IP is currently banned
func (db *DB) IsIPBanned(ip string) (bool, string, error) {
	var reason string
	var expiresAt sql.NullTime

	err := db.conn.QueryRow(`
		SELECT reason, expires_at FROM banned_ips WHERE ip = ?
	`, ip).Scan(&reason, &expiresAt)

	if err == sql.ErrNoRows {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}

	// Check if ban has expired
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		// Ban expired, remove it
		db.conn.Exec(`DELETE FROM banned_ips WHERE ip = ?`, ip)
		return false, "", nil
	}

	return true, reason, nil
}

// FileScan represents a cached scan result for a single file
type FileScan struct {
	FileHash       string
	ScanLevel      string
	FindingsJSON   string
	FindingCount   int
	CriticalCount  int
	HighCount      int
	MediumCount    int
	LowCount       int
	ScanDurationMS int64
	ScannedAt      time.Time
}

// ScanFile represents a file that was part of a scan
type ScanFile struct {
	ScanID    int64
	FileHash  string
	FilePath  string
	FileSize  int64
	FromCache bool
}

// GetFileScan retrieves a cached file scan result
func (db *DB) GetFileScan(fileHash, scanLevel string) (*FileScan, error) {
	row := db.conn.QueryRow(`
		SELECT file_hash, scan_level, findings_json, finding_count,
		       critical_count, high_count, medium_count, low_count,
		       scan_duration_ms, scanned_at
		FROM file_scans
		WHERE file_hash = ? AND scan_level = ?
	`, fileHash, scanLevel)

	var fs FileScan
	err := row.Scan(&fs.FileHash, &fs.ScanLevel, &fs.FindingsJSON, &fs.FindingCount,
		&fs.CriticalCount, &fs.HighCount, &fs.MediumCount, &fs.LowCount,
		&fs.ScanDurationMS, &fs.ScannedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return &fs, nil
}

// SaveFileScan saves a file scan result to the cache
func (db *DB) SaveFileScan(fs *FileScan) error {
	_, err := db.conn.Exec(`
		INSERT OR REPLACE INTO file_scans
		(file_hash, scan_level, findings_json, finding_count,
		 critical_count, high_count, medium_count, low_count,
		 scan_duration_ms, scanned_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, fs.FileHash, fs.ScanLevel, fs.FindingsJSON, fs.FindingCount,
		fs.CriticalCount, fs.HighCount, fs.MediumCount, fs.LowCount,
		fs.ScanDurationMS, time.Now())

	return err
}

// GetCachedFileHashes performs a batch lookup of file hashes at a specific scan level
// Returns a map of file_hash -> FileScan for all found hashes
func (db *DB) GetCachedFileHashes(fileHashes []string, scanLevel string) (map[string]*FileScan, error) {
	if len(fileHashes) == 0 {
		return make(map[string]*FileScan), nil
	}

	// Build placeholders for SQL IN clause
	placeholders := make([]string, len(fileHashes))
	args := make([]interface{}, len(fileHashes)+1)
	args[0] = scanLevel
	for i, hash := range fileHashes {
		placeholders[i] = "?"
		args[i+1] = hash
	}

	query := fmt.Sprintf(`
		SELECT file_hash, scan_level, findings_json, finding_count,
		       critical_count, high_count, medium_count, low_count,
		       scan_duration_ms, scanned_at
		FROM file_scans
		WHERE scan_level = ? AND file_hash IN (%s)
	`, strings.Join(placeholders, ","))

	rows, err := db.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	results := make(map[string]*FileScan)
	for rows.Next() {
		var fs FileScan
		err := rows.Scan(&fs.FileHash, &fs.ScanLevel, &fs.FindingsJSON, &fs.FindingCount,
			&fs.CriticalCount, &fs.HighCount, &fs.MediumCount, &fs.LowCount,
			&fs.ScanDurationMS, &fs.ScannedAt)
		if err != nil {
			return nil, err
		}
		results[fs.FileHash] = &fs
	}

	return results, rows.Err()
}

// LinkFilesToScan records which files were part of a scan
func (db *DB) LinkFilesToScan(scanID int64, files []ScanFile) error {
	if len(files) == 0 {
		return nil
	}

	tx, err := db.conn.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO scan_files (scan_id, file_hash, file_path, file_size, from_cache)
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, file := range files {
		_, err = stmt.Exec(scanID, file.FileHash, file.FilePath, file.FileSize, file.FromCache)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
