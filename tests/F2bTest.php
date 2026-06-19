<?php declare(strict_types=1);

use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Unit tests for f2b's pure IP / sanitization logic.
 *
 * These exercise the real plugin methods via reflection; they need no
 * database or Roundcube runtime (see tests/bootstrap.php).
 */
final class F2bTest extends TestCase
{
    private function plugin(): f2b
    {
        // Minimal stub for the plugin API the rcube_plugin constructor reads.
        return new f2b((object) ['dir' => '', 'url' => '']);
    }

    /** Invoke a private/protected method (accessible by default since PHP 8.1). */
    private function call(f2b $p, string $method, array $args = []): mixed
    {
        return (new ReflectionMethod($p, $method))->invokeArgs($p, $args);
    }

    private function setRip(f2b $p, string $rip): void
    {
        (new ReflectionProperty($p, 'rip'))->setValue($p, $rip);
    }

    // ---- apply_mask: the IPv4/IPv6 network-masking math ----

    public function test_apply_mask_ipv4(): void
    {
        $p = $this->plugin();
        $mask = fn (string $ip, int $bits) => inet_ntop($this->call($p, 'apply_mask', [inet_pton($ip), $bits]));

        $this->assertSame('192.168.1.0', $mask('192.168.1.55', 24));
        $this->assertSame('192.168.0.0', $mask('192.168.1.55', 16));
        $this->assertSame('192.168.1.55', $mask('192.168.1.55', 32));
        $this->assertSame('0.0.0.0', $mask('192.168.1.55', 0));
        $this->assertSame('192.168.1.52', $mask('192.168.1.55', 30)); // partial byte
    }

    public function test_apply_mask_ipv6(): void
    {
        $p = $this->plugin();
        $mask = fn (string $ip, int $bits) => inet_ntop($this->call($p, 'apply_mask', [inet_pton($ip), $bits]));

        $this->assertSame('2001:db8:1:2::', $mask('2001:db8:1:2:3:4:5:6', 64));
        $this->assertSame('2001:db8:1::', $mask('2001:db8:1:2:3:4:5:6', 48));
        $this->assertSame('::', $mask('2001:db8::1', 0));
        $this->assertSame('2001:db8:1:2:3:4:5:6', $mask('2001:db8:1:2:3:4:5:6', 128));
    }

    // ---- ip_key: IPv4 path (does not touch the framework) ----

    public function test_ip_key_ipv4_keeps_full_address(): void
    {
        $p = $this->plugin();
        $this->setRip($p, '203.0.113.45');
        $this->assertSame('203.0.113.45', $this->call($p, 'ip_key'));
    }

    public function test_ip_key_invalid_returns_null(): void
    {
        $p = $this->plugin();
        // inet_pton is strict: bogus and non-canonical (leading-zero) addresses
        // are rejected, so they bucket to null rather than a wrong key.
        foreach (['not-an-ip', '', '999.1.1.1', '203.0.000.045'] as $bad) {
            $this->setRip($p, $bad);
            $this->assertNull($this->call($p, 'ip_key'), "input: {$bad}");
        }
    }

    // ---- cidr_match: whitelist/blacklist matching ----

    #[DataProvider('cidrCases')]
    public function test_cidr_match(string $ip, string $range, bool $expected): void
    {
        $this->assertSame($expected, $this->call($this->plugin(), 'cidr_match', [$ip, $range]));
    }

    public static function cidrCases(): array
    {
        return [
            'v4 in /16'             => ['192.168.1.50', '192.168.0.0/16', true],
            'v4 out /16'            => ['192.169.1.50', '192.168.0.0/16', false],
            'v4 /8 loopback'        => ['127.0.0.1', '127.0.0.0/8', true],
            'v4 edge of /12'        => ['172.31.255.255', '172.16.0.0/12', true],
            'v4 just outside /12'   => ['172.32.0.1', '172.16.0.0/12', false],
            'v4 bare host match'    => ['8.8.8.8', '8.8.8.8', true],
            'v4 bare host no match' => ['8.8.4.4', '8.8.8.8', false],
            'v6 loopback'           => ['::1', '::1/128', true],
            'v6 in /32'             => ['2001:db8:1::1', '2001:db8::/32', true],
            'v6 ULA /7'             => ['fd12:3456::1', 'fc00::/7', true],
            'v6 link-local /10'     => ['fe80::abcd', 'fe80::/10', true],
            'family mismatch v4/v6' => ['192.168.1.1', '::/0', false],
            'family mismatch v6/v4' => ['2001:db8::1', '0.0.0.0/0', false],
            'explicit /0 matches'   => ['1.2.3.4', '0.0.0.0/0', true],
            // malformed input must never match (no over-matching, no warning)
            'malformed trailing /'  => ['1.2.3.4', '1.2.3.0/', false],
            'malformed prefix abc'  => ['1.2.3.4', '1.2.3.0/abc', false],
            'malformed prefix -1'   => ['1.2.3.4', '1.2.3.0/-1', false],
            'v4 prefix over 32'     => ['1.2.3.4', '1.2.3.4/33', false],
            'non-ip subnet'         => ['1.2.3.4', 'garbage/24', false],
            'non-ip rip'            => ['garbage', '1.2.3.0/24', false],
        ];
    }

    // ---- log_safe: log-forging defense ----

    public function test_log_safe_escapes_control_chars(): void
    {
        $p = $this->plugin();
        $out = $this->call($p, 'log_safe', ["victim\nadmin logged in"]);
        $this->assertStringNotContainsString("\n", $out);
        $this->assertSame('victim\nadmin logged in', $out);
        $this->assertSame('a\tb\rc', $this->call($p, 'log_safe', ["a\tb\rc"]));
    }

    public function test_log_safe_leaves_normal_text(): void
    {
        $this->assertSame('john.doe@example.com',
            $this->call($this->plugin(), 'log_safe', ['john.doe@example.com']));
    }
}
