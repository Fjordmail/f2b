-- Add indexes used by the lookup/cleanup queries.

CREATE INDEX IF NOT EXISTS idx_f2b_failed_logins_rip_timestamp
    ON f2b_failed_logins (rip, timestamp);
CREATE INDEX IF NOT EXISTS idx_f2b_banned_rip_banned_until
    ON f2b_banned (rip, banned_until);
