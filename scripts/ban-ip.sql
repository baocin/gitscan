-- Ban malicious IP 165.227.170.186 for WebDAV PROPFIND scanning
-- Run with: sqlite3 /var/lib/gitvet/data/gitvet.db < scripts/ban-ip.sql

INSERT OR REPLACE INTO banned_ips (ip, reason, banned_at, expires_at)
VALUES ('165.227.170.186', 'WebDAV PROPFIND scanning attempt - malicious reconnaissance', datetime('now'), NULL);

-- Verify the ban
SELECT ip, reason, banned_at, expires_at FROM banned_ips WHERE ip = '165.227.170.186';
