package db

import (
	"database/sql"
	_ "embed"
	"fmt"
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
	return nil
}

// isColumnExistsError checks if the error is a "column already exists" error
func isColumnExistsError(err error) bool {
	return err != nil && (err.Error() == "duplicate column name: license" ||
		err.Error() == "SQLITE_ERROR: duplicate column name: license")
}

// Close closes the database connection
func (db *DB) Close() error {
	return db.conn.Close()
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
	ID              int64
	RepoID          int64
	CommitSHA       string
	ResultsJSON     string
	SummaryJSON     string
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	InfoCount       int
	SecurityScore   int // 0-100 weighted security score
	FilesScanned    int
	ScanDurationMS  int64
	OpenGrepVersion string
	RulesVersion    string
	CreatedAt       time.Time
}

// Request represents a request log entry
type Request struct {
	ID                 int64
	IP                 string
	SSHKeyFingerprint  string
	UserAgent          string
	RepoURL            string
	CommitSHA          string
	RequestMode        string
	ScanID             *int64
	CacheHit           bool
	ResponseTimeMS     int64
	Error              string
	CreatedAt          time.Time
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
		       critical_count, high_count, medium_count, low_count, info_count,
		       COALESCE(security_score, 100), files_scanned, scan_duration_ms,
		       opengrep_version, rules_version, created_at
		FROM scans WHERE repo_id = ? AND commit_sha = ?
	`, repoID, commitSHA)

	var s Scan
	var summaryJSON sql.NullString
	var filesScanned sql.NullInt64
	var openGrepVer, rulesVer sql.NullString

	err := row.Scan(&s.ID, &s.RepoID, &s.CommitSHA, &s.ResultsJSON, &summaryJSON,
		&s.CriticalCount, &s.HighCount, &s.MediumCount, &s.LowCount, &s.InfoCount,
		&s.SecurityScore, &filesScanned, &s.ScanDurationMS, &openGrepVer, &rulesVer, &s.CreatedAt)
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

	return &s, nil
}

// CreateScan creates a new scan record
func (db *DB) CreateScan(scan *Scan) error {
	result, err := db.conn.Exec(`
		INSERT INTO scans (repo_id, commit_sha, results_json, summary_json,
		                   critical_count, high_count, medium_count, low_count, info_count,
		                   security_score, files_scanned, scan_duration_ms, opengrep_version, rules_version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, scan.RepoID, scan.CommitSHA, scan.ResultsJSON, scan.SummaryJSON,
		scan.CriticalCount, scan.HighCount, scan.MediumCount, scan.LowCount, scan.InfoCount,
		scan.SecurityScore, scan.FilesScanned, scan.ScanDurationMS, scan.OpenGrepVersion, scan.RulesVersion)
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
		INSERT INTO requests (ip, ssh_key_fingerprint, user_agent, repo_url, commit_sha,
		                      request_mode, scan_id, cache_hit, response_time_ms, error)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, req.IP, nullString(req.SSHKeyFingerprint), nullString(req.UserAgent),
		req.RepoURL, nullString(req.CommitSHA), nullString(req.RequestMode),
		req.ScanID, req.CacheHit, req.ResponseTimeMS, nullString(req.Error))
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
