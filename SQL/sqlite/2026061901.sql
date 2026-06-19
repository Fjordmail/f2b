-- Switch rip to a textual key (IPv4 address or IPv6 network prefix) for IPv6
-- support. The failed-login / ban data is ephemeral, so the tables are recreated.

DROP TABLE IF EXISTS f2b_failed_logins;
DROP TABLE IF EXISTS f2b_banned;

CREATE TABLE f2b_failed_logins (
    rip varchar(45) NOT NULL,
    email TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_f2b_failed_logins_rip_timestamp
    ON f2b_failed_logins (rip, timestamp);

CREATE TABLE f2b_banned (
    rip varchar(45) NOT NULL,
    banned_until TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX idx_f2b_banned_rip_banned_until
    ON f2b_banned (rip, banned_until);
