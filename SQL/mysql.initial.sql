-- Roundcube f2b initial database structure

SET FOREIGN_KEY_CHECKS=0;

-- Table structure for table `f2b_failed_logins`

CREATE TABLE IF NOT EXISTS `f2b_failed_logins` (
  `rip` int(11) NOT NULL,
  `email` varchar(320) NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT current_timestamp()
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Table structure for table `f2b_banned`

CREATE TABLE IF NOT EXISTS `f2b_banned` (
  `rip` int(11) NOT NULL,
  `banned_until` timestamp NOT NULL DEFAULT current_timestamp()
) ROW_FORMAT=DYNAMIC ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
