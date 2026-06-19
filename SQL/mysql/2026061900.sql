-- Add indexes used by the lookup/cleanup queries.

ALTER TABLE `f2b_failed_logins` ADD INDEX `idx_f2b_failed_logins_rip_timestamp` (`rip`, `timestamp`);
ALTER TABLE `f2b_banned` ADD INDEX `idx_f2b_banned_rip_banned_until` (`rip`, `banned_until`);
