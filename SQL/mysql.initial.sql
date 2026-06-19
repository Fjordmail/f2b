-- Roundcube f2b initial database structure

SET FOREIGN_KEY_CHECKS=0;

-- Table structure for table `f2b_failed_logins`

CREATE TABLE IF NOT EXISTS `f2b_failed_logins` (
  `rip` varchar(45) NOT NULL,
  `email` varchar(320) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp(),
  INDEX `idx_f2b_failed_logins_rip_timestamp` (`rip`, `timestamp`)
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `f2b_banned`

CREATE TABLE IF NOT EXISTS `f2b_banned` (
  `rip` varchar(45) NOT NULL,
  `banned_until` timestamp NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`rip`)
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Record the schema version (read by bin/updatedb.sh --package=f2b)

INSERT INTO `system` (`name`, `value`) VALUES ('f2b-version', '2026061902')
  ON DUPLICATE KEY UPDATE `value` = '2026061902';

SET FOREIGN_KEY_CHECKS=1;
