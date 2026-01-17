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
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

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

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_repos_url ON repos(url);
CREATE INDEX IF NOT EXISTS idx_scans_repo_commit ON scans(repo_id, commit_sha);
CREATE INDEX IF NOT EXISTS idx_requests_ip_time ON requests(ip, created_at);
CREATE INDEX IF NOT EXISTS idx_requests_ssh_time ON requests(ssh_key_fingerprint, created_at)
    WHERE ssh_key_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_requests_repo_time ON requests(repo_url, created_at);
