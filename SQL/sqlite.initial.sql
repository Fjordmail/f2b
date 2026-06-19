-- Roundcube f2b initial database structure

-- Table structure for table "f2b_failed_logins"

CREATE TABLE IF NOT EXISTS f2b_failed_logins (
    rip varchar(45) NOT NULL,
    email TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_f2b_failed_logins_rip_timestamp
    ON f2b_failed_logins (rip, timestamp);

-- Table structure for table "f2b_banned"

CREATE TABLE IF NOT EXISTS f2b_banned (
    rip varchar(45) NOT NULL PRIMARY KEY,
    banned_until TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Record the schema version (read by bin/updatedb.sh --package=f2b)

INSERT OR IGNORE INTO system (name, value) VALUES ('f2b-version', '2026061902');
