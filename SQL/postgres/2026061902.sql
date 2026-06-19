-- Enforce one ban row per key (rip) so concurrent requests can't create
-- duplicate bans. The ban data is ephemeral, so the table is recreated.

DROP TABLE IF EXISTS f2b_banned;

CREATE TABLE f2b_banned (
    rip varchar(45) NOT NULL PRIMARY KEY,
    banned_until timestamp NOT NULL DEFAULT now()
);
