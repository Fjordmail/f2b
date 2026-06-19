# Roundcube Fail2ban

This plugin will prevent clients with banned IP addresses from logging in.

Both IPv4 and IPv6 are supported. IPv4 is tracked per address; IPv6 is tracked
per network prefix (`f2b_ipv6_prefix`, default /64) so attackers can't evade
bans by rotating addresses within their allocation.

## Install

Run : `composer require inboxcom/f2b`.

## Database support

Works with MySQL/MariaDB, PostgreSQL and SQLite. The matching schema in `SQL/` is applied automatically by the Roundcube plugin installer on first install.

## Upgrading

Schema changes ship as versioned migrations under `SQL/<driver>/`. After updating the plugin, apply them from the Roundcube root:

```
bin/updatedb.sh --dir=plugins/f2b/SQL --package=f2b
```
