# Roundcube Fail2ban

This plugin will prevent clients with banned IP addresses from logging in.

## Install

1. Run `composer require inboxcom/f2b`
2. Add `f2b` to `$config['plugins']`

## Database support

Works with MySQL/MariaDB, PostgreSQL and SQLite. The matching schema in `SQL/` is applied automatically by the Roundcube plugin installer on first install.

## Upgrading

Schema changes ship as versioned migrations under `SQL/<driver>/`. After updating the plugin, apply them from the Roundcube root:

```
bin/updatedb.sh --dir=plugins/f2b/SQL --package=f2b
```

## To do

- Add support for IPv6
