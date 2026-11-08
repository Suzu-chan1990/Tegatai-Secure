=== Tegatai Security ===
Contributors: tegatai
Tags: security, firewall, malware scanner, hardening, 2fa
Requires at least: 7.1
Tested up to: 7.2
Requires PHP: 8.4
Stable tag: 2.1.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Firewall, login protection and 2FA, anti-spam, scanners, server rules, encrypted database backups and IP ban sharing between your own sites.

Security plugin for WordPress: firewall, login protection, anti-spam, scanners, server rules, encrypted database backups and a small network ("The Hive") that shares IP bans between your own sites.

Many protections are written as server rules (`tegatai-nginx.conf` or `.htaccess`), so the web server blocks those requests before PHP and WordPress start. Everything else runs inside WordPress.

Current version: `2.1.1` – see [CHANGELOG.md](CHANGELOG.md).

---

## Requirements

* WordPress 7.1 or newer
* PHP 8.4 or newer, with OpenSSL and sodium (Hive protocol v2, backup keys); zlib for the GeoIP database
* nginx, Apache or LiteSpeed (WP Masking needs nginx)
* WP-CLI for the key commands

---

## Installation

1. Copy the plugin folder to `wp-content/plugins/tegatai-Secure`.
2. Activate it under **Plugins**.
3. Open **Tegatai Secure** in the admin menu and switch on the modules you want.

### Server rules

**nginx:** Tegatai writes `tegatai-nginx.conf` into the WordPress folder. Include it once in the `server` block and reload nginx:

```nginx
server {
    # ...
    include /path/to/wordpress/tegatai-nginx.conf;
}
```

After changing server rules or WP Masking in Tegatai, reload nginx again.

**Apache / LiteSpeed:** the rules are written into `.htaccess`.

---

## Modules

The admin page is split into five areas plus three separate pages.

### Protection

* **Firewall:** WAF patterns, bad bots, AI and SEO bots, rate limit, 404 trap, upload guard, URL whitelist, custom regex rules, IP whitelist and blacklist
* **Login:** login attempt limit, custom login slug, hide `/wp-admin/`, disable application passwords, trusted devices, restricted dashboard, idle logout, magic links, two-factor authentication (email, authenticator app or both)
* **Anti-spam:** Cloudflare Turnstile, honeypot field, time check, disposable email list, link and referrer checks
* **GeoIP:** block or allow countries, looked up in a local database (see below)

### Server & System

* **Server rules:** directory listing, sensitive and system files, dotfiles, XML-RPC, PHP in uploads, hotlink protection, protected directories
* **HTTP headers:** CSP, HSTS, X-Frame-Options and other security headers
* **WP Masking:** see below
* **Hardening:** user enumeration, file editor, version footprints, privilege escalation checks, admin honeypot

### Scanners

Malware scanner, WordPress core check, file integrity monitor, database scan (injected scripts), option scan, cron scan, uploads monitor, file permission check. Files found by the scanner can be moved to a quarantine.

### Management

* **IP Prison:** active bans with reason, source (this site or a Hive peer) and expiry; release single IPs
* **Sessions:** active sessions, end sessions remotely, IP and browser binding, one session per user
* **Backups:** database backups, see below
* **Extras & API:** webhook for Discord or Slack, AbuseIPDB, other settings
* **Secrets:** status of the secrets file

### Logs

Event log and timeline.

### Separate pages

* **Terminal:** live view of the traffic log in the browser
* **API Guard:** protection for your own endpoints, see below
* **The Hive:** see below

---

## GeoIP

Countries are looked up in the free "IP to Country Lite" database by [DB-IP](https://db-ip.com) (CC BY 4.0), read with the bundled MaxMind DB reader. Visitor IPs never leave the server.

* The database (a few MB) is stored in `wp-content/uploads/tegatai-geoip/` and is only downloaded while the GeoIP block is on: by the daily maintenance job when it is missing or older than 30 days, or with **Download database** on the GeoIP tab.
* Behind a trusted proxy the `CF-IPCountry` header is used instead.
* Unknown countries, a missing database and an empty list never block anyone (fail open).
* Country codes can be separated by new lines, commas or spaces.

---

## Backups

* Database only (all tables of the database), no files
* Daily or weekly via WP-Cron, or manually
* Stored in `wp-content/uploads/tegatai-backups/`, the newest 7 are kept (configurable)
* Streamed: rows are read one at a time, compressed and encrypted in 1 MB chunks, so memory use does not grow with the database size
* A backup is written to a temporary file and only gets its final name when everything succeeded. On any error (disk full, database error) the temporary file is deleted, the error is logged, and old backups are not removed.
* Never unencrypted: without the PHP sodium extension no backup is written
* The download is a gzip-compressed SQL file with `DROP TABLE IF EXISTS` and `CREATE TABLE` per table; it can be imported with `mysql` or phpMyAdmin

### Encryption

With a backup key (recommended), created like the Hive key:

```bash
sudo -u <fpm-user> wp tegatai backup-keygen --path=/path/to/site
```

* The key pair is written to `secrets/tegatai-backup-key.php` next to `tegatai-secrets.php` (file `0600`, folder `0700`; an existing folder that others can read is set to `0700`, and the command stops if that is not possible). Another location: `define('TEGATAI_BACKUP_KEY_FILE', '/path/tegatai-backup-key.php');`
* Every backup gets its own random key, which is sealed to the public key (X25519, `crypto_box_seal`). The data is encrypted in chunks with XChaCha20-Poly1305 (`crypto_secretstream`); changed, reordered or cut-off files are rejected.
* Tegatai never creates this key on its own, and the command does not overwrite an existing key (`--replace` creates a new one; older backups then need a copy of the old file).
* **Keep a copy of the key file outside the server.** Without it the backups cannot be decrypted.
* Optional: if the file only contains `public_key` (the `private_key` line removed and kept offline), the server can still write backups but cannot decrypt them. To download one decrypted, put the full file back for that time.

Without a backup key, backups use the same XChaCha20-Poly1305 chunks with a key derived from `TEGATAI_BACKUP_SECRET` (or a secret stored in the database). Older backups (AES-256-GCM, AES-256-CBC) can still be downloaded.

---

## Secrets

Secrets do not have to be stored in the database. Tegatai reads them from a PHP file outside the web root, or from `wp-config.php`.

### Secrets file

Default location, one level above the WordPress folder:

```text
/var/www/example.com/htdocs/                          <- WordPress
/var/www/example.com/secrets/tegatai-secrets.php      <- secrets
```

Content:

```php
<?php
return [
    'TEGATAI_HIVE_SECRET'   => 'tg_hmac_...',
    'TEGATAI_API_SECRET'    => '...',
    'TEGATAI_SUDO_PIN'      => '$2y$10$...',
    'TEGATAI_BACKUP_SECRET' => '...',
    'TEGATAI_ABUSEIPDB_KEY' => '...',
];
```

Another location is set in `wp-config.php` (only the path, no secret):

```php
define('TEGATAI_SECRETS_FILE', '/path/outside/webroot/tegatai-secrets.php');
```

* Only these five names are read. A value that is also defined in `wp-config.php` wins.
* **Management → Secrets → Create secrets file** copies the secrets currently defined in `wp-config.php` into the file. Remove the `define()` lines from `wp-config.php` afterwards.
* Permissions: `chmod 600`, owned by the PHP-FPM user.
* The Secrets tab shows the commands to create each value.

Create values:

```bash
php -r "echo 'tg_hmac_' . bin2hex(random_bytes(32)), PHP_EOL;"           # TEGATAI_HIVE_SECRET
php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"                        # TEGATAI_API_SECRET / TEGATAI_BACKUP_SECRET
php -r "echo password_hash('YourPin', PASSWORD_BCRYPT), PHP_EOL;"        # TEGATAI_SUDO_PIN
```

### Sudo PIN

`TEGATAI_SUDO_PIN` is a bcrypt hash. The PIN unlocks the display of secrets that are stored in the database. Only the hash is stored, never the PIN.

---

## AbuseIPDB

Banned IPs can be reported to [AbuseIPDB](https://www.abuseipdb.com) (Firewall → "Report bans to AbuseIPDB"). The API key goes into the secrets file as `TEGATAI_ABUSEIPDB_KEY`.

* Reported: honeypot URL, 404 instant ban, 404 scan, login traps, and bans received through The Hive
* Sent in the background via WP-Cron; a ban never waits for the API
* Only the IP, the category and the ban type are sent; no URLs, usernames or other request data
* Private and reserved IPs are never reported
* The same IP at most once per 15 minutes; on HTTP 429 sending pauses until the API allows it again

---

## WP Masking (nginx)

Hides the WordPress structure in the pages visitors receive (Server & System → WP Masking).

* **Plugin and theme paths:** `/wp-content/plugins/<folder>/` and `/wp-content/themes/<theme>/` become `/assets/<name>/`. Names are set per plugin and theme; empty fields get a short automatic name.
* **WordPress core:** `/wp-includes/` → `/lib/`, `/wp-json/` → `/api/`, `admin-ajax.php` → `/ajax` (all names can be changed). `/wp-json/` keeps working.
* **Versions and identifiers:** removes `?ver=`, script and style ids, generator tags, RSD / wlwmanifest / shortlink / REST links, the emoji script, speculation rules and the `X-Pingback` header.
* **Hide file names:** masked files get a neutral name per file, e.g. `/assets/bar/css/kanri-bar.css` → `/assets/bar/css/t3f9a0c1d2e4`. Folders stay, so relative URLs in CSS and JS keep working. A changed file gets a new name.
* **Block original paths:** direct requests for the original paths of masked entries get a 404. Logged-in users and files loaded by the site's own pages keep access.

nginx maps the new paths back to the real files (static files only, never PHP). The rules are part of `tegatai-nginx.conf`.

Activation:

1. Switch the options on and save the names.
2. Reload nginx.
3. Click **Check new paths**.

Tegatai requests every new path once and only uses paths that returned the real file, so a missing nginx reload does not break the site. New file names are found when pages are visited and checked every hour. With Apache or LiteSpeed the check finds no working paths and nothing changes; removing versions and identifiers works on every server.

---

## The Hive

Shares IP bans between your own WordPress sites. A ban on one site is sent to the other sites in the peer list.

### Protocol

* **v2 (Ed25519):** every site has its own key pair. Messages are signed with the private key; the other sites only know the public key. The payload (IP, reason, level) is encrypted with `crypto_box` (X25519, derived from the same keys).
* Every message contains the recipient, a timestamp (±60 s) and a one-time request ID.
* **v1 (HMAC-SHA256):** for sites without a key. A peer with an Ed25519 key is never accepted over HMAC.
* Endpoint: `/?rest_route=/tegatai/v1/hive/receive`. Redirects are not followed; a message only counts as delivered when the endpoint itself answers.
* Per-peer rate limit, ban duration and a never-ban allowlist. Firewall whitelists, private ranges, the server itself and IPs of logged-in admins (30 days) are never banned.

### Node keys

Tegatai never creates keys on its own. Create the key once per site, **as the site's PHP-FPM user** (not as root):

```bash
sudo -u <fpm-user> wp tegatai hive-keygen --path=/path/to/site
```

* The private key is written to `secrets/tegatai-hive-key.php` next to `tegatai-secrets.php` (file `0600`, folder `0700`). It is never printed.
* The command does not overwrite an existing key. `--replace` creates a new one; all peers then need the new public key.
* Other location: `define('TEGATAI_HIVE_KEY_FILE', '/path/tegatai-hive-key.php');`, or the key itself as `TEGATAI_HIVE_PRIVATE_KEY` in `wp-config.php`. If two sites share one secrets folder, give each its own `TEGATAI_HIVE_KEY_FILE`.
* The line for the other sites is printed by the command, shown on the Hive page and printed by `wp tegatai hive-pubkey`.

### Peer list

On every site, list all other sites, one per line:

```text
https://site-a.example | ed25519:<public key of site A>
https://site-b.example | ed25519:<public key of site B>
https://old-site.example | tg_hmac_pair-secret        (no key yet, HMAC)
```

Sites can be switched one by one. To remove a site from the network, delete its line on the others. When all sites use keys, `TEGATAI_HIVE_SECRET` can be removed and strict peer mode switched on.

---

## API Guard

Protects your own endpoints (match by "contains", exact path or regex).

* Static token or HMAC signature
* Timestamp check and one-time request IDs
* IPv4 / IPv6 CIDR allowlist
* Rate limit
* Delay after failed authentication
* WP-CLI requests are not affected

HMAC example:

```php
$method    = 'POST';
$uri       = '/api/sync';                  // exact REQUEST_URI incl. query string
$timestamp = time();
$req_id    = bin2hex(random_bytes(16));
$body      = json_encode(['example' => true]);   // raw request body ('' for GET)

$signature = hash_hmac(
    'sha256',
    $method . '|' . $uri . '|' . $timestamp . '|' . $req_id . '|' . hash('sha256', $body),
    'YOUR_SECRET'
);
// Headers: X-Tegatai-Timestamp, X-Tegatai-Req-Id, X-Tegatai-Signature
```

Each `req_id` is accepted once. Since 1.4.2 the signature includes the method and the body hash; clients using the older `uri|timestamp|req_id` format must be updated.

---

## WP-CLI

```bash
wp tegatai hive-keygen [--replace]   # create the Hive key of this site
wp tegatai hive-pubkey               # print the peer line of this site
wp tegatai backup-keygen [--replace] # create the backup key of this site
```

Run them as the PHP-FPM user of the site.

---

## External services

GeoIP lookups are local. Tegatai only contacts these services when the matching feature is used:

| Service | Feature | Data sent |
|---|---|---|
| `download.db-ip.com` | GeoIP database download (monthly) | none (plain download) |
| AbuseIPDB | ban reports | IP, category, ban type |
| Cloudflare Turnstile | anti-spam / login | Turnstile token |
| `api.wordpress.org`, `core.svn.wordpress.org` | core file check, restoring a core file | WordPress version and locale, file path |
| `wpvulnerability.net` | daily vulnerability check of installed plugins | plugin slug |
| your webhook URL | Discord / Slack notifications | event text, IP, user agent |
| your own sites | The Hive | encrypted ban messages |

---

## Reporting a vulnerability

Please report security issues privately to `tegatai@anime-mitsuketa.tokyo`. See [SECURITY.md](SECURITY.md).

## License

GPL v2 or later.
