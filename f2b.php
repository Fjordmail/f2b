<?php

/**
 * Inbox.com
 *
 * Fail2ban plugin for Roundcube
 *
 * @author Sebastian Karlsen <sebastian@corp.inbox.com>
 * @version 1.0.0
 */

class f2b extends rcube_plugin
{
    public $task = 'login';

    private rcmail $rcmail;
    private rcube_db_mysql $dbh;
    private string $rip;
    private array $whitelist;
    private array $blacklist;

    /**
     * Init: add hooks.
     *
     * @return void
     */
    public function init(): void
    {
        $this->load_config();
        $this->add_texts('localization/', true);

        $this->rcmail = rcmail::get_instance();
        $this->rip = rcube_utils::remote_addr();
        $this->dbh = $this->rcmail->get_dbh();
        $this->whitelist = $this->rcmail->config->get('f2b_whitelist', [ '127.0.0.1/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16' ]);
        $this->blacklist = $this->rcmail->config->get('f2b_blacklist', []);

        $this->add_hook('authenticate', [$this, 'check_invalid_chars']);

        // Unless whitelisted, check if the user is banned / register failed logins
        if (!$this->is_whitelisted()) {
            $this->add_hook('authenticate', [$this, 'check_ban']);
            $this->add_hook('login_failed', [$this, 'register_failed_login']);
        }
    }

    /**
     * Check if the username contains invalid characters.
     * If so, abort login early. Log the event.
     *
     * @param array $args
     * @return array
     */
    public function check_invalid_chars(array $args): array
    {
        if ($args['abort'])
            return $args;

        // Abort if no invalid chars are configured
        if (empty($invalid_chars = str_split($this->rcmail->config->get('f2b_invalid_chars', ' '))))
            return $args;

        foreach ($invalid_chars as $char) {
            if (str_contains($args['user'], $char)) {
                return $this->abort_login(
                    $args,
                    $this->gettext('f2b_invalid_chars'),
                    sprintf('%s/%s(): Invalid characters in username: abort login to "%s" from %s', __CLASS__, __FUNCTION__, $args['user'], $this->rip)
                );
            }
        }

        return $args;
    }

    /**
     * Check if the user is banned or if an IP is blacklisted and if so, abort login.
     * Also, apply the policies and ban the IP if the threshold is reached.
     * Log both events.
     *
     * @param array $args
     * @return array
     */
    public function check_ban(array $args): array
    {
        if ($args['abort'])
            return $args;

        // Check early if network is blacklisted
        if ($this->is_blacklisted()) {
            return $this->abort_login(
                $args,
                $this->gettext('f2b_blacklisted'),
                sprintf('%s/%s(): Blacklisted: abort login to %s from %s', __CLASS__, __FUNCTION__, $args['user'], $this->rip)
            );
        }

        // Check if the user is already banned
        if ($this->is_banned())
            return $this->abort_login($args);

        // Loop through the policies and apply
        $policies = $this->rcmail->config->get('f2b_policies', []);
        foreach ($policies as $policy) {
            $count = $this->get_failed_login_attemps_nb($policy['ban_window']);

            if ($count >= $policy['ban_threshold']) {
                $this->ban($policy['ban_time']);

                return $this->abort_login(
                    $args,
                    str_replace(':ban_time', $policy['ban_time'], $this->gettext('f2b_banned_for'))
                );
            }
        }

        return $args;
    }

    /**
     * Register a failed login, unless the IP already is banned.
     * Used to determine if an IP should be banned.
     * Log the event.
     *
     * @param array $args
     * @return array
     */
    public function register_failed_login(array $args): array
    {
        $user = $args['user'];

        // Don't register failed login if the user already is banned
        if ($this->is_banned())
            return $args;

        $this->dbh->query(
            'INSERT INTO `f2b_failed_logins` (`rip`, `email`, `timestamp`) VALUES (?, ?, CURRENT_TIMESTAMP());',
            ip2long($this->rip), $user
        );

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): Register failed login to %s from %s at %s',
            __CLASS__, __FUNCTION__, $user, $this->rip, date('Y-m-d H:i:s')
        ));

        $this->clean_expired_bans();

        return $args;
    }

    /**
     * Ban an IP for a given time and log the event
     *
     * @param int $ban_time
     * @return void
     */
    private function ban(int $ban_time): void
    {
        $this->dbh->query(
            'INSERT INTO `f2b_banned` (`rip`, `banned_until`) VALUES (?, TIMESTAMPADD(MINUTE, ?, CURRENT_TIMESTAMP()));',
            ip2long($this->rip), $ban_time
        );

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): Banning %s for %d minutes',
            __CLASS__, __FUNCTION__, $this->rip, $ban_time
        ));
    }

    /**
     * Abort the login and log the event
     *
     * @param array $args
     * @return array
     */
    private function abort_login(array $args, ?string $error = NULL, ?string $log_msg = NULL): array
    {
        $args['abort'] = true;
        $args['error'] = (empty($error))
            ? $this->gettext('f2b_banned')
            : $error;

        $log_msg = (empty($log_msg))
            ? sprintf('%s/%s(): Banned: abort login to %s from %s', __CLASS__, __FUNCTION__, $args['user'], $this->rip)
            : $log_msg;

        rcmail::write_log(__CLASS__, $log_msg);
        return $args;
    }

    /**
     * Check if a given IP has been banned
     *
     * @return bool
     */
    private function is_banned(): bool
    {
        // Check if there is an active ban in the database
        $sql_result = $this->dbh->query(
            'SELECT COUNT(`rip`) AS `count` FROM `f2b_banned` WHERE `rip` = ? AND `banned_until` >= CURRENT_TIMESTAMP()',
            ip2long($this->rip)
        );
        $sql_arr = $this->dbh->fetch_assoc($sql_result);

        $count = ($sql_arr == false) ? 0 : intval($sql_arr['count']);

        return $count > 0;
    }

     /**
     * Check if a given IP address lies
     * within a given CIDR range
     *
     * @param string $rip
     * @param array $ip_list
     * @return bool
     */
    private function ip_in_list(string $rip, array &$ip_list): bool
    {
        foreach ($ip_list as $cidr)
            if ($this->cidr_match($rip, $cidr))
                return true;

        return false;
    }

    private function is_whitelisted(): bool { return $this->ip_in_list($this->rip, $this->whitelist); }
    private function is_blacklisted(): bool { return $this->ip_in_list($this->rip, $this->blacklist); }

    /**
     * Get the number of failed login attempts
     * from a given IP address during a given time window
     *
     * @param int $ban_window
     * @return int
     */
    private function get_failed_login_attemps_nb(int $ban_window): int
    {
        $sql_result = $this->dbh->query(
            'SELECT COUNT(`rip`) AS `count` FROM `f2b_failed_logins` WHERE rip = ? AND `timestamp` >= NOW() - INTERVAL ? MINUTE;',
            ip2long($this->rip), $ban_window
        );
        $sql_arr = $this->dbh->fetch_assoc($sql_result);

        return ($sql_arr == false) ? 0 : intval($sql_arr['count']);
    }

    /**
     * Clean expired bans
     * Runs at a configurable frequency (default: 1/500)
     * Log the number of deleted bans
     *
     * @return void
     */
    private function clean_expired_bans(): void
    {
        // Don't run too often
        $clean_freq = $this->rcmail->config->get('f2b_clean_frequency', 500);
        if (rand(1, $clean_freq) != 1)
            return;

        if (empty($policies = $this->rcmail->config->get('f2b_policies', [])))
            return;
        $longest_ban_time = max(array_column($policies, 'ban_time'));

        $q1 = $this->dbh->query(
            'DELETE FROM `f2b_failed_logins` WHERE `timestamp` < NOW() - INTERVAL ? MINUTE;',
            $longest_ban_time
        );

        $q2 = $this->dbh->query('DELETE FROM `f2b_banned` WHERE `banned_until` < CURRENT_TIMESTAMP();');

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): %d failed logins and %d bans (from the last %d minutes) deleted',
            __CLASS__, __FUNCTION__, $q1->rowCount(), $q2->rowCount(), $longest_ban_time
        ));
    }

    /**
     * Check if a given IP address is in a given CIDR range
     * https://stackoverflow.com/questions/594112/check-whether-or-not-a-cidr-subnet-contains-an-ip-address
     *
     * @param string $rip
     * @param string $range
     * @return bool
     */
    private function cidr_match(string $rip, string $range): bool
    {
        [ $subnet, $bits ] = explode('/', $range);

        $bits = ($bits === NULL)
            ? 32
            : intval($bits);

        $ip = ip2long($rip);
        $subnet = ip2long($subnet);
        $mask = -1 << (32 - $bits);
        $subnet &= $mask; // nb: in case the supplied subnet wasn't correctly aligned

        return ($ip & $mask) == $subnet;
    }
}

?>
