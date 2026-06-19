-- Roundcube f2b initial database structure

-- Table structure for table "f2b_failed_logins"
-- NB: rip stores a normalized IP key (IPv4 address or IPv6 network prefix),
--     so it is a textual column rather than an integer.

CREATE TABLE IF NOT EXISTS f2b_failed_logins (
    rip varchar(45) NOT NULL,
    email varchar(320) NOT NULL,
    timestamp timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_f2b_failed_logins_rip_timestamp
    ON f2b_failed_logins (rip, timestamp);

-- Table structure for table "f2b_banned"

CREATE TABLE IF NOT EXISTS f2b_banned (
    rip varchar(45) NOT NULL,
    banned_until timestamp NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_f2b_banned_rip_banned_until
    ON f2b_banned (rip, banned_until);

-- Record the schema version (read by bin/updatedb.sh --package=f2b)

INSERT INTO system (name, value) VALUES ('f2b-version', '2026061901')
    ON CONFLICT (name) DO UPDATE SET value = EXCLUDED.value;
