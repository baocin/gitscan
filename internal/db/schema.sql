-- GitScan SQLite Schema

-- Cached repositories
CREATE TABLE IF NOT EXISTS repos (
    id INTEGER PRIMARY KEY,
    url TEXT UNIQUE NOT NULL,              -- github.com/user/repo
    local_path TEXT NOT NULL,              -- /var/cache/gitscan/repos/...
    default_branch TEXT,                   -- main, master, etc.
    last_commit_sha TEXT,
    last_fetched_at DATETIME,
    size_bytes INTEGER,
    file_count INTEGER,
    license TEXT,                          -- MIT, Apache-2.0, GPL-3.0, etc.
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Migration: Add license column if it doesn't exist
-- SQLite doesn't support ADD COLUMN IF NOT EXISTS, so we use a workaround
CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY);
INSERT OR IGNORE INTO _migrations (name) VALUES ('add_license_column');
-- The actual migration is done in Go code

-- Scan results (cached per commit)
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    repo_id INTEGER NOT NULL REFERENCES repos(id),
    commit_sha TEXT NOT NULL,
    results_json TEXT NOT NULL,            -- Full opengrep SARIF output
    summary_json TEXT,                     -- Condensed findings
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    info_count INTEGER DEFAULT 0,
    security_score INTEGER DEFAULT 100,    -- 0-100 weighted security score
    files_scanned INTEGER,
    scan_duration_ms INTEGER,
    opengrep_version TEXT,
    rules_version TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(repo_id, commit_sha)
);

-- Request tracking (rate limiting + analytics)
CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    ssh_key_fingerprint TEXT,              -- Available for SSH connections
    user_agent TEXT,
    repo_url TEXT NOT NULL,
    commit_sha TEXT,
    request_mode TEXT,                     -- 'scan', 'clone', 'json', 'plain'
    scan_id INTEGER REFERENCES scans(id),  -- NULL if rate limited or error
    cache_hit BOOLEAN DEFAULT FALSE,
    response_time_ms INTEGER,
    error TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Security: Track suspicious requests and bans
CREATE TABLE IF NOT EXISTS suspicious_requests (
    id INTEGER PRIMARY KEY,
    ip TEXT NOT NULL,
    path TEXT NOT NULL,
    user_agent TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS banned_ips (
    ip TEXT PRIMARY KEY,
    reason TEXT,
    banned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME  -- NULL for permanent ban
);

-- File-level scan cache for cross-repo deduplication
CREATE TABLE IF NOT EXISTS file_scans (
    file_hash TEXT NOT NULL,           -- SHA256 of file content
    scan_level TEXT NOT NULL,          -- 'quick', 'normal', 'thorough'
    findings_json TEXT NOT NULL,       -- SARIF findings for this file
    finding_count INTEGER DEFAULT 0,
    critical_count INTEGER DEFAULT 0,
    high_count INTEGER DEFAULT 0,
    medium_count INTEGER DEFAULT 0,
    low_count INTEGER DEFAULT 0,
    scan_duration_ms INTEGER,
    scanned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (file_hash, scan_level)
);

-- Link files to scans (track which files were in which repo scans)
CREATE TABLE IF NOT EXISTS scan_files (
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    file_hash TEXT NOT NULL,
    file_path TEXT NOT NULL,          -- Relative path in repo
    file_size INTEGER,
    from_cache BOOLEAN DEFAULT FALSE, -- Was result reused from cache?
    PRIMARY KEY (scan_id, file_hash, file_path)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_repos_url ON repos(url);
CREATE INDEX IF NOT EXISTS idx_scans_repo_commit ON scans(repo_id, commit_sha);
CREATE INDEX IF NOT EXISTS idx_requests_ip_time ON requests(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_requests_ssh_time ON requests(ssh_key_fingerprint, created_at)
    WHERE ssh_key_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_requests_repo_time ON requests(repo_url, created_at);
CREATE INDEX IF NOT EXISTS idx_suspicious_ip_time ON suspicious_requests(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_banned_ips_expires ON banned_ips(expires_at);
CREATE INDEX IF NOT EXISTS idx_file_scans_hash_level ON file_scans(file_hash, scan_level);
CREATE INDEX IF NOT EXISTS idx_scan_files_scan ON scan_files(scan_id);
CREATE INDEX IF NOT EXISTS idx_scan_files_hash ON scan_files(file_hash);
