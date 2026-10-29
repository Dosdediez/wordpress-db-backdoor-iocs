# WordPress persistence backdoors after core exploitation — IOCs and detection

Indicators of compromise and read-only detection commands from an incident response we handled in June–August 2026 on a multi-tenant Plesk server hosting WordPress sites.

Full write-up (Spanish): https://www.dosdediez.com/ *(replace with the article URL)*

Author: Andrés Gil Fernández — [Dosdediez Estudio](https://www.dosdediez.com/diseno-web-en-galicia/auditoria-seguridad-web/)

> No malicious code is published here. This repository only describes the mechanisms and gives defenders a way to find them.

## Summary

Attackers exploited a vulnerability in WordPress core (affected 6.9.0–6.9.4 and 7.0.0–7.0.1; fixed in 6.9.5 and 7.0.2) through the REST API batch endpoint (`POST /wp-json/batch/v1`) combined with SQL injection. This allowed them to plant payloads **directly in the database**, so cleaning files alone did not remove the infection.

Several persistence layers were found on different sites:

| # | Layer | Where |
|---|-------|-------|
| 1 | Fake plugin with a command-execution webshell | `wp-content/plugins/` |
| 2 | Fraudulent administrator accounts | `wp_users` |
| 3 | Payload stored as a fake site transient (base64) | `wp_options` |
| 4 | Loader injected into `wp-config.php` that writes the payload to `/tmp` | `wp-config.php` |
| 5 | Fake object cache drop-in acting as loader | `wp-content/object-cache.php` |
| 6 | Injected blocks | `.htaccess` |
| 7 | Cron job that recreates the webshell if deleted | user crontab |

## Indicators of compromise

**Fake plugins**
- Plugin presenting itself as "Security Headers Manager", text domain `advanced-cache-handler-<hex>`
- `database-repair-assistant-<hex>/class-wp-taxonomy-<hex>.php`
- `wp2shell-<hex>/` containing `direct.php` and `loot.php`
- Webshell uses `shell_exec`, `exec`, `passthru`, `system`, `proc_open`, `popen`, gated by a token checked with `hash_equals`

**Accounts**
- Administrator users with prefixes `w2s_` and `wpsvc_` (one site had 21 created over one week)

**Database**
- Option named `_site_transient_health_<hex>` containing a base64 payload

**wp-config.php**
- Lines wrapped in comments `/* WP_Core_Integrity <hex> */`
- Code reading an option from the database and writing a file under `/tmp/php<random>`

**object-cache.php**
- Presents itself as a "compatibility shim"
- Defines empty `wp_cache_*` functions, which disables real caching. Side effect worth watching for: a slow admin panel and thousands of queries per page load

**.htaccess**
- Blocks marked `wp_compat_<hex>`

**Cron**
- Entry disguised with the comment `# WP_CRON` that checks whether the webshell exists and copies it back from a hidden file such as `wp-content/uploads/class-wp-cache-<hex>.php`

**Webshell in /tmp**
- Authentication through three channels (cookie, parameter or header) — "AUTH GATE triple channel"

**Logs**
- `POST /wp-json/batch/v1` requests from unknown IPs

## Detection (read-only)

Paths are for Plesk. **Include subdomains**: `/var/www/vhosts/*/httpdocs` alone misses them, so use both globs below.

```bash
ROOTS="/var/www/vhosts/*/httpdocs /var/www/vhosts/*/*/"
```

Core version in the vulnerable ranges:

```bash
for f in $(ls -d $ROOTS 2>/dev/null); do
  v="$f/wp-includes/version.php"
  [ -f "$v" ] && echo "$(grep -oP "wp_version = '\K[^']+" "$v") $f"
done | grep -E '^(6\.9\.[0-4]|7\.0\.[01]) '
```

Fake plugins:

```bash
for f in $(ls -d $ROOTS 2>/dev/null); do
  ls -d "$f"/wp-content/plugins/{advanced-cache-handler-*,database-repair-assistant-*,wp2shell-*} 2>/dev/null
done
```

wp-config.php, object-cache.php and .htaccess:

```bash
for f in $(ls -d $ROOTS 2>/dev/null); do
  grep -l "WP_Core_Integrity" "$f/wp-config.php" 2>/dev/null
  grep -l "compatibility shim" "$f/wp-content/object-cache.php" 2>/dev/null
  grep -l "wp_compat_" "$f/.htaccess" 2>/dev/null
done
```

Database option and suspicious admins (run per site with WP-CLI):

```bash
wp option list --search='_site_transient_health_%' --fields=option_name --path=<site>
wp user list --role=administrator --fields=user_login,user_registered --path=<site> | grep -E 'w2s_|wpsvc_'
```

Cron persistence and its execution history:

```bash
grep -rl "WP_CRON" /var/spool/cron/ 2>/dev/null
grep -E "database-repair-assistant|class-wp-taxonomy|class-wp-cache-" /var/log/cron
```

Batch endpoint in access logs:

```bash
grep -h "POST /wp-json/batch/v1" /var/www/vhosts/*/logs/access*log 2>/dev/null
```

Names are randomised per site. These searches catch the variants we saw, not every possible one, so treat a clean result as "not found", not as proof the site is clean.

## Remediation notes

1. Update core to a fixed version **first**, otherwise the site is reinfected.
2. Isolate suspicious files outside the web root before deleting them, to keep evidence.
3. Remove the database option, the wp-config.php lines, the .htaccess blocks, the fake drop-in and the cron entry. Check `php -l wp-config.php` after editing.
4. Delete fraudulent admins, change the database password and regenerate salts (`wp config shuffle-salts`) to invalidate every session.
5. Sweep **every** site on the server, subdomains included, and check the database, not only files.

## License

CC BY 4.0
