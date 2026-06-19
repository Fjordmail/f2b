<?php declare(strict_types=1);

/**
 * Inbox.com
 *
 * Fail2ban plugin for Roundcube
 *
 * @author Sebastian Karlsen <sebastian@corp.inbox.com>
 */

class f2b extends rcube_plugin
{
    public $task = 'login';

    private rcmail $rcmail;
    private rcube_db $dbh;
    private string $rip;
    private ?string $ripkey;

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
        $this->ripkey = $this->ip_key();
        $this->dbh = $this->rcmail->get_dbh();

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

        // An empty config disables the check
        $invalid_chars = (string) $this->rcmail->config->get('f2b_invalid_chars', ' ');
        if ($invalid_chars === '')
            return $args;

        foreach (str_split($invalid_chars) as $char) {
            if (str_contains($args['user'], $char)) {
                return $this->abort_login(
                    $args,
                    $this->gettext('f2b_invalid_chars'),
                    sprintf('%s/%s(): Invalid characters in username: abort login to "%s" from %s', __CLASS__, __FUNCTION__, $this->log_safe($args['user']), $this->rip)
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
                sprintf('%s/%s(): Blacklisted: abort login to %s from %s', __CLASS__, __FUNCTION__, $this->log_safe($args['user']), $this->rip)
            );
        }

        // Check if the user is already banned
        if ($this->is_banned())
            return $this->abort_login($args);

        // Apply the harshest matching policy (longest ban_time) regardless of
        // config order: sort by ban_time descending so the first match wins.
        $policies = $this->rcmail->config->get('f2b_policies', []);
        usort($policies, fn($a, $b) => $b['ban_time'] <=> $a['ban_time']);

        foreach ($policies as $policy) {
            $count = $this->get_failed_login_attempts_nb($policy['ban_window']);

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

        // Can't track a request we couldn't resolve to an IP
        if ($this->ripkey === null)
            return $args;

        // Don't register failed login if the user already is banned
        if ($this->is_banned())
            return $args;

        $this->dbh->query(
            'INSERT INTO f2b_failed_logins (rip, email) VALUES (?, ?)',
            $this->ripkey, $user
        );

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): Register failed login to %s from %s at %s',
            __CLASS__, __FUNCTION__, $this->log_safe($user), $this->rip, date('Y-m-d H:i:s')
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
        // Upsert (rip is unique) so concurrent requests can't pile up duplicate
        // ban rows for the same key. Time stays DB-side to keep clock semantics.
        $banned_until = $this->dbh->now($ban_time * 60);
        $sql = 'INSERT INTO f2b_banned (rip, banned_until) VALUES (?, ' . $banned_until . ')';
        $sql .= match ($this->dbh->db_provider) {
            'postgres', 'sqlite' => ' ON CONFLICT (rip) DO UPDATE SET banned_until = EXCLUDED.banned_until',
            default              => ' ON DUPLICATE KEY UPDATE banned_until = ' . $banned_until,
        };

        $this->dbh->query($sql, $this->ripkey);

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): Banning %s for %d minutes',
            __CLASS__, __FUNCTION__, $this->ripkey, $ban_time
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
            ? sprintf('%s/%s(): Banned: abort login to %s from %s', __CLASS__, __FUNCTION__, $this->log_safe($args['user']), $this->rip)
            : $log_msg;

        rcmail::write_log(__CLASS__, $log_msg);
        return $args;
    }

    /**
     * Sanitize an untrusted value (e.g. a submitted username) for safe inclusion in a log line: 
     * escape control characters such as CR/LF that could otherwise be used to forge log entries.
     *
     * @param string $s
     * @return string
     */
    private function log_safe(string $s): string
    {
        return addcslashes($s, "\x00..\x1f\x7f");
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
            'SELECT COUNT(rip) AS cnt FROM f2b_banned WHERE rip = ? AND banned_until >= ' . $this->dbh->now(),
            $this->ripkey
        );
        $sql_arr = $this->dbh->fetch_assoc($sql_result);

        $count = ($sql_arr == false) ? 0 : intval($sql_arr['cnt']);

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
    private function ip_in_list(string $rip, array $ip_list): bool
    {
        foreach ($ip_list as $cidr)
            if ($this->cidr_match($rip, $cidr))
                return true;

        return false;
    }

    private function is_whitelisted(): bool { return $this->ip_in_list($this->rip, $this->rcmail->config->get('f2b_whitelist', [ '127.0.0.0/8', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '::1/128', 'fc00::/7', 'fe80::/10' ])); }
    private function is_blacklisted(): bool { return $this->ip_in_list($this->rip, $this->rcmail->config->get('f2b_blacklist', [])); }

    /**
     * Get the number of failed login attempts
     * from a given IP address during a given time window
     *
     * @param int $ban_window
     * @return int
     */
    private function get_failed_login_attempts_nb(int $ban_window): int
    {
        $sql_result = $this->dbh->query(
            'SELECT COUNT(rip) AS cnt FROM f2b_failed_logins WHERE rip = ? AND timestamp >= ' . $this->dbh->now(-$ban_window * 60),
            $this->ripkey
        );
        $sql_arr = $this->dbh->fetch_assoc($sql_result);

        return ($sql_arr == false) ? 0 : intval($sql_arr['cnt']);
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

        $longest_ban_window = max(array_column($policies, 'ban_window'));

        $q1 = $this->dbh->query(
            'DELETE FROM f2b_failed_logins WHERE timestamp < ' . $this->dbh->now(-$longest_ban_window * 60)
        );

        $q2 = $this->dbh->query('DELETE FROM f2b_banned WHERE banned_until < ' . $this->dbh->now());

        rcmail::write_log(__CLASS__, sprintf(
            '%s/%s(): %d failed logins (older than %d minutes) and %d expired bans deleted',
            __CLASS__, __FUNCTION__, $q1->rowCount(), $longest_ban_window, $q2->rowCount()
        ));
    }

    /**
     * Build the key used to bucket failed logins and bans for the
     * current remote IP. IPv4 is keyed on the full address; IPv6 is
     * aggregated to its network prefix (default /64) so an attacker
     * can't trivially rotate addresses within their own allocation.
     *
     * @return string|null The normalized key, or null for an invalid/unknown IP
     */
    private function ip_key(): ?string
    {
        $bin = @inet_pton($this->rip);
        if ($bin === false)
            return null;

        // IPv6: mask down to the configured prefix
        if (strlen($bin) === 16) {
            $prefix = intval($this->rcmail->config->get('f2b_ipv6_prefix', 64));
            if ($prefix < 0 || $prefix > 128)
                $prefix = 64;
            $bin = $this->apply_mask($bin, $prefix);
        }

        return inet_ntop($bin);
    }

    /**
     * Zero out every bit of a packed (inet_pton) address beyond the
     * given prefix length. Works for both IPv4 (4 bytes) and IPv6 (16 bytes).
     *
     * @param string $bin  Packed address
     * @param int $bits    Prefix length in bits
     * @return string      Packed network address
     */
    private function apply_mask(string $bin, int $bits): string
    {
        $out = '';
        for ($i = 0, $len = strlen($bin); $i < $len; $i++) {
            $remaining = $bits - $i * 8;

            if ($remaining >= 8)
                $out .= $bin[$i];                                 // whole byte kept
            elseif ($remaining <= 0)
                $out .= "\0";                                     // fully masked out
            else
                $out .= $bin[$i] & chr((0xff << (8 - $remaining)) & 0xff); // partial byte
        }

        return $out;
    }

    /**
     * Check if a given IP address lies within a given CIDR range.
     * Handles both IPv4 and IPv6; a range without a prefix length is
     * treated as a single host. Mismatched address families never match.
     *
     * @param string $rip
     * @param string $range
     * @return bool
     */
    private function cidr_match(string $rip, string $range): bool
    {
        if (str_contains($range, '/')) {
            [ $subnet, $bits ] = explode('/', $range, 2);

            if (!ctype_digit($bits)) // Reject a malformed prefix rather than silently treating it as /0
                return false;
            $bits = intval($bits);
        } else {
            $subnet = $range;
            $bits = null;
        }

        $ip_bin = @inet_pton($rip);
        $subnet_bin = @inet_pton($subnet);

        // Both must be valid and of the same family (4 or 16 bytes)
        if ($ip_bin === false || $subnet_bin === false || strlen($ip_bin) !== strlen($subnet_bin))
            return false;

        $max_bits = strlen($ip_bin) * 8;
        if ($bits === null)
            $bits = $max_bits;
        if ($bits > $max_bits)
            return false;

        return $this->apply_mask($ip_bin, $bits) === $this->apply_mask($subnet_bin, $bits);
    }
}
