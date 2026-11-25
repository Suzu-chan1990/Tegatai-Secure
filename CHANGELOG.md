## [2.2.8] - CSP: upgrade-insecure-requests

### Fixed

* **Content Security Policy (basic)** now ends with `upgrade-insecure-requests`. Images, scripts and styles that a page still loads via `http://` are switched to `https://` by the browser before the policy is checked. Before, Firefox blocked such `http://` images (they stayed empty) because `https:` was the only allowed scheme, while Chrome upgraded them on its own and showed them.

### Upgrade notes

* `ENV_VERSION` 12: the server rules (which carry the headers) are written again once after the update. nginx: reload nginx afterwards.

## [2.2.7] - Data folder is always set up, nginx file is never missing

### Fixed

* **The data folder could stay missing for good.** The folders `uploads/tegatai-secure/` (`logs`, `backups`, `server`, `geoip`) were only set up once after an update. When that attempt failed, it was still marked as done and never repeated, while the Server tab and the first line of the nginx file already named `uploads/tegatai-secure/server/tegatai-nginx.conf`. An include pointing there stopped nginx (missing file). The folder is now checked on every admin, cron and WP-CLI request (a few `is_dir` calls) and created again when it or a subfolder is missing; the nginx file is written again right away when it is missing or was last written to another path. A failure is stored with the reason (folder, owner, mode, PHP user), shown on the Tegatai screens and in the log, and retried every ten minutes.
* **Moving the folders of older versions** (`tegatai-logs`, `tegatai-backups`, `tegatai-geoip`) is complete now: contents are merged into the existing subfolders (subfolders such as `logs/cache` included, identical files dropped, a different file with a taken name is kept as `<name>-old`), the protection files of the old folders are removed (also `index.html`, which used to block the removal), and the old folder is deleted.
* When the new nginx file cannot be written, the file in `uploads/tegatai-server/` (2.2.1) is still kept up to date, and the Server tab says to keep the include line there.

### Added

* **Include check (nginx):** the rules file answers `<uploads>/tegatai-secure/server/include-check` (exact `location`, matched before the deny block of the data folder). The Server tab requests it over HTTP and shows whether nginx uses the file ("nginx uses this file" / "does not use this file yet" / could not be checked), with "Check again". The copy in `uploads/tegatai-server/` does not contain this location.
* **Remove old folder:** once nginx uses the new file, the Server tab offers a button that deletes `uploads/tegatai-server/` (only Tegatai's own files). It is never removed on its own: PHP cannot see whether another server block still includes it, and nginx does not start when an included file is missing. The button runs a fresh include check first and refuses while nginx does not use the new file. On Apache / LiteSpeed the button is shown as well.
* The Backups tab shows the storage folder.
* Sites whose uploads folder is also the plugins folder: `uploads/tegatai-secure` would be the plugin folder itself (replaced on every update, and the deny rules would block the plugin's files). The data folder is named `tegatai-secure-data` there; the deny rules follow the name.

### Upgrade notes

* `ENV_VERSION` 11: folders are checked and the server rules are written again once after the update. nginx: reload nginx afterwards.
* nginx: change the include line to the path shown in the Server tab only after that file exists; test with `nginx -t` before reloading.
* New strings in the language files (de_DE, en_US).

## [2.2.6] - Cross-Origin headers, X-XSS-Protection "0"

### Added

* **Cross-Origin-Opener-Policy** (`header_coop`, off by default): `same-origin-allow-popups`. Windows of other sites lose their reference to this site (protection against cross-window attacks); windows the site opens itself (share dialogs, OAuth popups) keep working.
* **Cross-Origin-Resource-Policy** (`header_corp`, off by default): `same-site`. Browsers only let the same site (including subdomains) load files of this site. Leave it off when other domains embed images or files from the site. Server-side fetches (link previews of social networks) are not affected.
* Both are part of the PHP headers and of the server rules (nginx / `.htaccess`), like the other headers.

### Changed

* **X-XSS-Protection** sends `0` instead of `1; mode=block`. The XSS filter is gone from all current browsers, and `1; mode=block` could be abused in old ones; `0` is today's recommendation (OWASP, MDN). The admin text says to leave it off and rely on the Content Security Policy.

### Upgrade notes

* The server rules are written again once after the update (`ENV_VERSION` 10). nginx: reload nginx afterwards.
* New strings in the language files (de_DE, en_US).

## [2.2.5] - Security headers for every response

### Fixed

* **HTTP security headers were missing on most responses.** They were only sent by PHP (`send_headers`), so every response without PHP had none: pages from a page cache that the web server delivers directly (Kyasshu, WP Rocket, WP Super Cache, W3 Total Cache, LiteSpeed Cache …), static files and error pages of the web server. `send_headers` also never runs for the admin, the login page and `admin-ajax.php`.
* The enabled headers are now part of the server rules as well:
  * **nginx** (`tegatai-nginx.conf`): `add_header … always` on server block level, plus `fastcgi_hide_header` / `proxy_hide_header` for the same names, so the copy PHP sends is dropped and every header is sent once.
  * **Apache / LiteSpeed** (`.htaccess` block, needs `mod_headers`): `Header unset …` plus `Header always set …`. Apache keeps two header tables (PHP-FPM writes into the "always" one, mod_php into the normal one); this pair replaces PHP's copy in both cases and also covers Apache's own error pages.
* Tested on nginx 1.24 and Apache 2.4.58, each with PHP-FPM and with Kyasshu as page cache: every header is sent exactly once on cached pages (gzip/br/zstd), PHP pages, the login page, static files and error pages.
* PHP keeps sending the headers as before (for setups without the server rules) and now also on the admin and login screens (`admin_init`, `login_init`). Headers that WordPress or another plugin already set are not sent twice.
* Switching a header on or off writes the server rules again (before, only `server_*` switches did).
* Permissions-Policy no longer lists `interest-cohort` (FLoC no longer exists in any browser; it only caused console warnings).

### Upgrade notes

* The server rules are written again once after the update (`ENV_VERSION` 9). nginx: reload nginx afterwards.
* nginx inherits `add_header` only into locations that have no `add_header` of their own. A location of another configuration (e.g. a cache plugin's nginx rules) that sets its own headers does not get Tegatai's security headers. Kyasshu 2.8.9 and newer have no `add_header` in their locations.
* If the hosting panel already sends HSTS (e.g. Froxlor with "HSTS" enabled for the domain), leave Tegatai's HSTS switch off, otherwise the header is sent twice.

## [2.2.4] - Exceptions for direct PHP requests in plugins and themes

### Added

* **PHP exceptions:** new field "PHP Exceptions (Plugins & Themes)" under Server → Custom Protection (`server_php_exceptions`). One path per line relative to `wp-content/plugins/` or `wp-content/themes/`; files match exactly, a trailing `/` allows a folder. Entries with other characters or `..` are ignored. Preset (used while the field was never saved): `anzen/serve.php`, `litespeed-cache/guest.vary.php`, `matomo/app/index.php`, `matomo/app/matomo.php`, `matomo/app/piwik.php`, `burst-statistics/endpoint.php`, `burst-pro/endpoint.php`. An empty field allows nothing. The list becomes a negative lookahead in the deny location (nginx) and in the RewriteRule (`.htaccess`); before, only `anzen/serve.php` was hard-coded and only for plugins.
* **Switch "Allow direct PHP in Plugins & Themes"** (`server_allow_plugin_php`, off by default): drops the plugin and theme block entirely; the block for uploads stays.

### Upgrade notes

* Existing server rules are written again once after the update (`ENV_VERSION` 8), so the preset exceptions are active without saving.

## [2.2.3] - Apache / LiteSpeed: server rules and WP Masking

### Fixed

* **Apache / LiteSpeed:** the `.htaccess` block now has the same rules as the nginx file: directory listings, sensitive and system files, XML-RPC, protected folders, blocked files, hotlink protection (with whitelist), the data folder and no direct PHP requests in plugins and themes. Before, `write_apache_rules()` read most switches under option names that the settings page never saves (`block_dotfiles`, `block_system_files`), so on Apache only PHP-in-uploads, dotfiles and the bot filter were active. The block is moved in front of `# BEGIN WordPress`: behind it, WordPress' `[L]` rewrite to `index.php` meant the bot filter only ever saw static files. Only mod_rewrite is used; the former `<FilesMatch> Require all denied` caused a 500 error on servers that do not allow `Require` in `.htaccess`. `force_update()` returns the `.htaccess` result on Apache / LiteSpeed and the Server tab shows it (instead of the nginx include line).

* **WP Masking on Apache / LiteSpeed:** new `Tegatai_Mask::apache_lines()` writes the same mapping as the nginx rules into the Tegatai block of `.htaccess`: new plugin / theme / wp-includes paths (static file types only), the ajax alias, hidden file names (unknown names answer 404) and the 404 for original paths. The block checks `%{THE_REQUEST}`, because an internal rewrite in `.htaccess` starts a new round with the real path; logged-in users and requests with a referrer of the own site keep access, as on nginx. Before, the path check found no working paths on Apache and masking stayed inactive apart from removing versions and identifiers.
* Admin texts of WP Masking no longer say nginx only.

### Upgrade notes

* Apache / LiteSpeed: the `Tegatai-Secure` block in `.htaccess` is written again on the first request after the update (only where it already exists). Direct requests for PHP files in `plugins/` and `themes/` now get a 403, as on nginx; `anzen/serve.php` stays reachable.

## [2.2.2] - WordPress.org review: secrets, no code files, enqueued assets

### Security

* **No secrets in the database anymore.** The API sync secret, the backup secret, the Hive shared secret, the reCAPTCHA and Turnstile secret keys and the alert webhook URL (it contains a token) are only read from the secrets file or from constants in `wp-config.php` (`TEGATAI_API_SECRET`, `TEGATAI_BACKUP_SECRET`, `TEGATAI_HIVE_SECRET`, new: `TEGATAI_RECAPTCHA_SECRET`, `TEGATAI_TURNSTILE_SECRET`, `TEGATAI_ALERT_WEBHOOK`). The input fields for these values are gone; the settings show where each value comes from. "Generate New" (API Guard, Hive) only shows a new key, it never saves one.
* **Database copies from older versions** are read until the same secret exists in the file or `wp-config.php`, then they are deleted automatically (`tegatai_purge_legacy_db_secrets()` on `admin_init`). The backup secret is only deleted when both values are equal, so older backups stay readable. A notice on the Tegatai screens lists the secrets that are still in the database.
* **Tegatai writes no PHP files anymore.** The secrets file and the key files for The Hive and for backups are created by the administrator: the Secrets tab shows a shell command (run as the site's PHP-FPM user, not as root) that writes the complete secrets file with folder `0700` and file `0600`, including all values that are still in the database. `wp tegatai hive-keygen` and `wp tegatai backup-keygen` only print the key file; the command shown on the Hive page and in the Backups tab redirects it into the file and never overwrites an existing key (`mv -n`). `--replace` is gone. "Create secrets file" was removed.
* **IP / Browser Guard without data from the session token:** `Tegatai_SessionGuard` no longer stores an MD5 of the session token in user meta. It compares with the session data WordPress keeps itself (`WP_Session_Tokens`: `ua`) and with the client IP that Tegatai adds through the core filter `attach_session_information` (`tegatai_ip`, resolved with the trusted proxies). The old `teg_sess_ip_*` / `teg_sess_ua_*` meta keys are deleted by the daily maintenance.
* **Hive pair secrets:** peers with "URL | pair secret" still work, but the Hive screen warns that these secrets are stored with the peer list in the database and recommends Ed25519 keys (only public keys are stored).
* **Request data:** new helpers `tegatai_server()` (sanitized text), `tegatai_server_ip()` (validated IP) and `tegatai_server_raw()` (for firewall pattern matching only: control characters and invalid UTF-8 removed, length limited, percent-encoding kept) replace all direct `$_SERVER` reads. User agents in logs, login history, 2FA data and trusted-device mails, log messages, the 2FA return URL (built from `site_url()`, no longer from the `Host` header), `redirect_to` (validated with `wp_validate_redirect()` before it is stored) and the API Guard example (`home_url()` host) are sanitized or validated.

### Changed

* **WPVulnerability check is opt-in** (new switch in the Scanner tab, off by default). Without it, no plugin slugs are sent; activation contacts no external server.
* **Core integrity check only:** the "Heal" repair (download from core.svn and write to `wp-admin` / `wp-includes`) was removed. Damaged core files are restored with Dashboard > Updates > "Re-install version", linked from the Core tab. `wp-includes` is located with `ABSPATH . WPINC`.
* **Quarantine in the database:** file contents are stored in the new table `{prefix}tegatai_quarantine` (base64, SHA-256 checked before the file is deleted, up to 8 MB per file) and the file is deleted. Entries can be downloaded (as `.quarantined.txt`) or deleted in the Malware tab; Tegatai does not write them back to disk. The custom quarantine folder option was removed. Entries of older versions (`uploads/tegatai-quarantine/`, `wp-content/tegatai-quarantine/`, custom folder, old `*.quarantine` files) are moved into the table once and the old files are deleted. The scanner's auto quarantine uses the same table instead of `rename()`.
* **One data folder named after the plugin:** `wp-content/uploads/tegatai-secure/` with `logs`, `backups`, `server` and `geoip`. `tegatai-logs`, `tegatai-backups` and `tegatai-geoip` are moved there automatically. Private files (scanner snapshot and file list, FIM snapshot) get an unguessable name (`tegatai_private_file()`, random suffix per site). Protection files are `.htaccess`, `web.config` and an empty `index.html` (no `index.php` is written anymore); `tegatai_protect_directory()` returns the real write result.
* **nginx rules file** is now `wp-content/uploads/tegatai-secure/server/tegatai-nginx.conf`. It always contains `location ^~` blocks for the data folder and the folders of older versions; prefix locations take precedence over every regex location of the server block, so a static file rule (`.html`, `.json`, ...) above the include can no longer serve these files. On nginx the file is written on activation and on update even when no server rules are switched on. A file of 2.2.1 in `uploads/tegatai-server/` is kept up to date with the same content, so an include that still points there keeps working.
* **Web access check:** Tegatai requests `uploads/tegatai-secure/index.html` over HTTP (cached 12 hours, cleared when the rules are written) and shows a notice on its screens when the folder is reachable, with a "Check again" link. When the site cannot reach itself, no result is cached for long and no warning is shown.
* **Scanner:** scans the content folder, plugins (`WP_PLUGIN_DIR`), must-use plugins, themes (`get_theme_root()`) and uploads (`wp_upload_dir()`) at their real locations, without scanning a file twice and without Tegatai's own data folder. Snapshot keys are `<root>/<relative path>`, so moving the site no longer marks unchanged files as new. Snapshots of older versions are ignored: **create a new snapshot after the update.**
* **Backups read the database through `$wpdb`:** the direct `mysqli_*` calls are gone. Rows are read in pages of 1000 (by primary key for tables with a single integer key, otherwise `LIMIT`/`OFFSET` inside the consistent snapshot); binary and geometry columns are read with `HEX()`, `BIT` columns as numbers, text is escaped with `esc_sql()`. Without a key pair and without `TEGATAI_BACKUP_SECRET` no backup is written (clear error instead of creating a secret in the database).
* **WP Masking** uses the template output buffer of WordPress 6.9+ (filter `wp_template_enhancement_output_buffer`) instead of its own `ob_start()`. On the login screen the URLs of enqueued scripts and styles are rewritten where they are generated (`script_loader_src` / `style_loader_src`).
* **All admin CSS and JavaScript in files:** `css/admin.css`, `css/subpages.css`, `css/404.css`, `js/admin.js`, `js/twofa.js`, `js/subpages.js`, `js/terminal.js`, `js/bot-timer.js`. Loaded only on Tegatai's own screens (2FA script also on the profile), texts and nonces through `wp_localize_script()`. Confirm dialogs use `data-tegatai-confirm`, the 2FA box uses data attributes instead of inline handlers. The Hive test results are built with `textContent`. reCAPTCHA and Turnstile on `wp-login.php` and the anti-spam timer are enqueued; the fallback 404 page prints its stylesheet with `wp_print_styles()`. The admin header image moved to `images/tegatai-banner.png`.
* **Prefix `tegatai_`** for all stored names, AJAX actions, nonces and form fields (before partly `teg_`). Options and user meta are renamed once on the first request after the update (values kept, no duplicates); transients of the old names are dropped.
* **Settings** are registered with a schema-based `sanitize_callback` (`sanitize_options()`), unknown keys are dropped. The JSON import is size-limited and every value goes through the settings schema.
* **WP-CLI** key commands write the key file to STDOUT with `WP_CLI::line()` and hints to STDERR with `WP_CLI::warning()`.
* **readme.txt:** the description now lists all features without promotional text; setup steps (secrets file, keys, Hive peers, WP Masking, API Guard HMAC) moved to "Installation", technical details (backup contents, GeoIP, AbuseIPDB, masking, Hive protocol) to the FAQ. The WordPress.org entry under "External services" no longer mentions `core.svn.wordpress.org` (core files are only checked).

### Removed

* Core file repair ("Heal"), quarantine restore to disk, custom quarantine folder, "Create secrets file", the secret input fields in the settings, the yellow notice about old nginx file locations in the Server tab.

### Upgrade notes

* Run the command from the Secrets tab once per site (as the PHP-FPM user). It moves the secrets that are still in the database into the file; the database copies are deleted afterwards.
* nginx: point the include line to `wp-content/uploads/tegatai-secure/server/tegatai-nginx.conf` (an include of `uploads/tegatai-server/` keeps working) and reload nginx, then click "Check again".
* Create a new scanner snapshot. Switch the WPVulnerability check on if you want it.

## [2.2.1] - Hardening

### Security

* **Passwordless magic link login removed** (option "Magic links", the login form box and the `teg_magic_login` handler). Every login now needs the password.
* **Temporary admin accounts removed:** Tegatai no longer creates user accounts or sends login links ("Temp Admin Accounts" card and `tegatai_create_temp_admin` are gone). Accounts that older versions created still expire and are deleted by the daily cleanup.
* **2FA step bound to the password:** a 2FA challenge is only created after WordPress has verified the password (`password_ok` in the challenge), and only such challenges are accepted. A challenge can be completed once.
* **WP Masking without WordPress salts:** automatic aliases and hidden file names use an own random key (`tegatai_mask_key`, created once) with HMAC-SHA256 instead of `wp_salt('auth')`. Rotating the WordPress salts no longer changes masked names, and no salt-derived value is stored. File names from the old scheme are discarded once and recorded again with the new key.
* **AbuseIPDB opt-in is enforced on every run:** switching reporting off deletes the queued reports and the pending cron event at once (new action `tegatai_setting_updated`), and the background worker checks the opt-in before it sends anything.

### Added

* **GitHub updates (GitHub edition):** the Plugin Update Checker (5.6, `lib/plugin-update-checker`) is back and checks the GitHub releases of Suzu-chan1990/Tegatai-Secure; the ZIP attached to a release is used when there is one. The header `Update URI` keeps WordPress.org from offering its edition over this one. The check only runs in the admin, WP-Cron and WP-CLI, never on normal page views. The WordPress.org edition stays without it.
* **2FA backup codes:** 10 one-time codes per user (alphabet without 0/o, 1/l/i, format `abcde-12345`), stored only as password hashes. They are shown once after generating, with download (.txt), copy and print. Usable in every 2FA mode; each code works once, and using one sends an email to the account owner with the number of codes left. Generating new codes invalidates the old set.

### Changed

* **nginx rules file** moved to `wp-content/uploads/tegatai-server/tegatai-nginx.conf` (own folder, protected for Apache/IIS and denied by the nginx rules themselves). The old files in the WordPress root or the uploads root are no longer written; the Server tab lists them with the new include line. **Update the `include` line in the nginx server block, reload nginx, then delete the old file.**
* **Paths:** `.htaccess` is located with `get_home_path()` and the rules use the `home_url()` path; plugin paths come from `plugin_dir_path()` / `plugin_dir_url()` of Tegatai itself instead of `WP_PLUGIN_DIR` / `plugins_url()` (scanner, file integrity monitor, WP Masking, server rules).
* **Quarantine** moved to `wp-content/uploads/tegatai-quarantine/`; existing entries are moved over once and stay restorable.
* **Admin styles** (switches, buttons, terminal log) are scoped to `.teg-wrap`, so they no longer change other admin screens.
* **Frontend content protection** (right click / copy protection) is added with `wp_add_inline_script()` / `wp_add_inline_style()` instead of printing `<script>` / `<style>` in the footer.

### Fixed

* **Activation:** the logs table version is only recorded when the table really exists, so a failed `dbDelta()` is retried on the next admin request. The legacy zero-date default of `time` is only dropped when it is actually present (no `ALTER` on every install). `SHOW TABLES LIKE` uses `esc_like()`.
* **Backups made before 2.1** (TGB2, v1): a missing PHP OpenSSL extension gives a clear error instead of failing during decryption.

## [2.2.0] - Google reCAPTCHA

### Added

* **Google reCAPTCHA** for login and comments (Spam tab), as an alternative to Cloudflare Turnstile. Type **v2** ("I'm not a robot" checkbox) or **v3** (invisible, score based, adjustable minimum score 0.1–0.9, default 0.5). v3 requests the token only when the form is submitted, so it cannot expire while the visitor types.
* **Only one captcha at a time:** switching reCAPTCHA on switches Turnstile off and the other way round; the other switch is turned off in the settings page right away. If both are set anyway (old settings, config import), reCAPTCHA is used and Turnstile is shown as off.
* reCAPTCHA follows the same rules as Turnstile: checked for every login attempt (right or wrong password), the log entry `AUTH-BOT` / `SPAM-BOT` names the reason and Google's error codes (`missing`, `rejected: invalid-input-secret`, `score 0.3 below 0.5`, `unreachable` ...), and an outage of the service does not count towards the login limit.
* The reCAPTCHA secret key is not exported with the configuration (like the Turnstile secret key).
* German and English translations for the new settings.

## [2.1.4] - WordPress.org release

### Changed

* **GitHub updater removed:** the Plugin Update Checker call is gone; updates come from the WordPress.org plugin directory.
* **Translations** are loaded by WordPress through the `Domain Path` header; the `load_plugin_textdomain()` call was removed.
* **Plugin name** is "Tegatai Secure" in the plugin header and `readme.txt` (matches the slug and text domain `tegatai-secure`). License header: `GPLv2 or later`.
* **`readme.txt`** uses the WordPress.org format (Description, Installation, FAQ, External services with terms and privacy links, Screenshots, Changelog); short description within 150 characters.
* **Plugin Check:** `unlink()` replaced by `wp_delete_file()`, `is_writable()` by `wp_is_writable()`; documented exceptions (`phpcs:ignore` / `phpcs:disable` with reason) for the streamed backup files, the unbuffered mysqli dump, atomic `rename()`, and the files that must be written to the WordPress folder.

### Fixed

* **Turnstile (login and comments):** a failed captcha is now explained instead of looking like a wrong password or 2FA code. The log entry `AUTH-BOT` / `SPAM-BOT` names the reason and Cloudflare's error codes (`missing`: no token in the form, the widget did not load or was not solved; `rejected: invalid-input-secret`, `timeout-or-duplicate` ...; `unreachable`: no answer from Cloudflare). A form without a token is rejected without asking Cloudflare. The request to Cloudflare waits 10 instead of 5 seconds.
* **Turnstile is checked for every login attempt, not only after a correct password.** Before, passwords could be tried without solving the captcha, and the captcha error revealed that a password was correct. A failed captcha now gives the same answer for right and wrong passwords. Attempts without a token are rejected without a request to Cloudflare and count towards the login limit.
* **Turnstile outage no longer locks the IP:** when Cloudflare cannot be reached, the attempt does not count towards the login limit (5 failures = 60 minutes).
* **Turnstile messages** are English source strings and translatable (they were hard-coded German); German and English translations added.
* **Hide wp-admin** no longer answers 404 on the login page: it looked for `wp-admin` anywhere in the URL, including `?redirect_to=.../wp-admin/`, which WordPress adds whenever a logged-out visitor opens `/wp-admin/`. Only the path is checked now; `admin-post.php` and `admin-ajax.php` stay reachable, and posts with "wp-admin" in the slug are no longer hidden.

## [2.1.3] - Backups: snapshot, BIT columns, safer decryption

### Changed

* **Consistent snapshot:** the dump runs in one read-only transaction (`START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY`, REPEATABLE READ), like `mysqldump --single-transaction`. All InnoDB tables show the same point in time, also while the site keeps writing. Tables without transactions (MyISAM, Aria, MEMORY) are named at the top of the dump and in the log. Tested: a row inserted 2 seconds into a 6-second backup is not in the dump.
* **BIT columns** are read as `CAST(col AS UNSIGNED)`. mysqlnd returns BIT as a decimal string, libmysqlclient as raw bytes; the cast gives the same plain number with both. Tested with BIT(1), BIT(8), BIT(64) (incl. `18446744073709551615`) and NULL, imported under `NO_BACKSLASH_ESCAPES,ANSI_QUOTES,STRICT_ALL_TABLES`.
* **Decrypted temporary files** (download) are created with umask `0077`, set to `0600` and checked before anything is written; also for the old formats.
* **Decryption never ends in an uncaught error:** the whole decoder (sodium and OpenSSL) runs inside `try`/`catch`; damaged files, wrong keys or library exceptions come back as a normal "decryption failed".
* **Old backups:** v1 (AES-256-CBC, before 1.5) is now decrypted in 1 MB blocks. TGB2 (AES-256-GCM, 1.5 to 2.1.0) cannot be streamed with PHP (no streaming GCM); the file is read once (no extra copy) and the memory needed is checked against the PHP memory limit first, with a clear message instead of a fatal error. Tested with real TGB2 backups made by Tegatai 1.5 and 2.1.0, downloaded with 2.1.3 and imported (tables identical). TGB2 has always used the key `derive_key('enc')` (HMAC-SHA256 of the backup secret); only v1 used the hex secret directly.

### Fixed

* Download of a decrypted backup could send 0 bytes: the size of the temporary file was read from PHP's stat cache (from its creation).

## [2.1.2] - Backups: SQL modes

### Fixed

* **SQL mode on export:** the dump runs with a fixed session `sql_mode` and the old mode is restored afterwards. With `ANSI_QUOTES` in the server or session mode, `SHOW CREATE TABLE` returned `"double quoted"` names that do not import without that mode; with `NO_BACKSLASH_ESCAPES`, values were escaped differently than the dump expects.
* **SQL mode on import:** the dump now saves the session settings of the importing connection (`@OLD_SQL_MODE`, `FOREIGN_KEY_CHECKS`, character set), sets `SQL_MODE='NO_AUTO_VALUE_ON_ZERO'` and restores everything at the end, like mysqldump. A stored `0` in an AUTO_INCREMENT column stays `0`, and backslash escapes are read correctly even when the importer uses `NO_BACKSLASH_ESCAPES`. The 2.1.1 dump set the mode without restoring it.
* Tested: export from a session with `NO_BACKSLASH_ESCAPES,ANSI_QUOTES,STRICT_ALL_TABLES`, import with an empty mode, the MariaDB default, `NO_BACKSLASH_ESCAPES,ANSI_QUOTES,STRICT_ALL_TABLES,PIPES_AS_CONCAT` and `ANSI,NO_BACKSLASH_ESCAPES,TRADITIONAL`: every value identical, ids `0,1,2` kept, the session mode of the importer afterwards unchanged. Control: without the mode lines the `0` became `3`, and with `NO_BACKSLASH_ESCAPES` the import failed.

### Changed

* **The dump says what it contains:** "all base tables (structure and data)". Views, triggers, stored routines and events are not saved; when the database has any, their number is written at the top of the dump and logged with each backup.

## [2.1.1] - Backups: streaming and fail closed

### Changed

* **Backups are streamed:** rows are read unbuffered (one row in memory), gzip-compressed with `deflate_add()` and encrypted in 1 MB chunks straight into the file. Memory use no longer grows with the database size.
* **Fail closed:** a backup is never written unencrypted. Without a backup key the data is encrypted with XChaCha20-Poly1305 (`crypto_secretstream`, format `TGB4`) and a key derived from `TEGATAI_BACKUP_SECRET`; AES-256-GCM is no longer written. Without the sodium extension no backup is made.
* **Write errors are detected:** the backup is written to a temporary file (`0600`) and renamed only after every write, the gzip end, `fflush()` and `fclose()` succeeded. On an error (e.g. disk full) the temporary file is deleted, `BACKUP-ERR` is logged, the manual backup shows the error, and the retention cleanup does not run. Leftover temporary files older than a day are removed.
* **SQL export:** text values are escaped with `mysqli_real_escape_string()` (charset-aware) instead of `addslashes()`; binary columns (BLOB, BINARY, VARBINARY) are written as hex literals, numbers and BIT unquoted, `NULL` as `NULL`. Table names are quoted. Several rows per `INSERT`. The dump sets `NAMES`, turns foreign key checks off, sets `NO_AUTO_VALUE_ON_ZERO` and contains `DROP TABLE IF EXISTS` per table; views are skipped. The first line is now an SQL comment (`-- <?php exit; ?>`), so the file can be imported directly. Tested with a restore into an empty database (text with quotes, backslashes, NUL, `%`, Japanese and emoji; binary data; dates; decimals; BIT).
* **Download** decrypts into a temporary file in the protected backup folder first; a damaged or cut-off backup is rejected before anything is sent. Format `TGB3` and `TGB4` files are decrypted chunk by chunk.

### Fixed

* **Download and delete of backups did nothing:** `sanitize_file_name()` turned `name.sql.php.gz.enc` into `name.sql_.php_.gz.enc`, so the file was not found (download: "File not found", delete: silently nothing). Backup names are now checked against their pattern.
* **Key folders:** `wp tegatai hive-keygen` and `wp tegatai backup-keygen` set an existing key folder that group or others can access to `0700` and stop with a message if that fails (e.g. folder of another user). The key file is checked for `0600` before it replaces the old one.

## [2.1.0] - Local GeoIP, backup keys, IP Prison

### New

* **Backup key pair (format v3), same approach as the Hive keys:** `wp tegatai backup-keygen` creates an X25519 key pair in `secrets/tegatai-backup-key.php` next to `tegatai-secrets.php` (file `0600`, folder `0700`; other location via `TEGATAI_BACKUP_KEY_FILE`). Tegatai never creates it on its own and does not overwrite it without `--replace`.
  * Every backup gets its own random key, sealed to the public key (`crypto_box_seal`). The data is encrypted in 1 MB chunks with XChaCha20-Poly1305 (`crypto_secretstream`); magic and sealed key are authenticated with every chunk, and changed, reordered or cut-off files are rejected.
  * A key file with only `public_key` lets the server write backups it cannot read itself (private key kept offline).
  * Without a key, backups keep using AES-256-GCM with `TEGATAI_BACKUP_SECRET`. Older GCM and CBC backups can still be downloaded.
  * The Backups tab shows which encryption is active.
* **Local GeoIP:** countries are looked up in the DB-IP "IP to Country Lite" database (CC BY 4.0) with the bundled MaxMind DB reader (`lib/maxmind-db-reader`, Apache-2.0). Visitor IPs are no longer sent to `get.geojs.io`. The database is stored in `uploads/tegatai-geoip/`, downloaded only while the GeoIP block is on (daily check, renewed after 30 days) or with the new **Download database** button on the GeoIP tab, which also shows the edition and the last download result.

### Fixed

* **IP Prison tab was empty:** the tab had no output. It now lists all active bans (IP, reason, source, level, expiry; newest 500) with a **Release** button per IP. Releasing only affects this site.
* **GeoIP with a country list of one code per line did not work:** the settings ask for one code per line, but the list was split at commas only. A blacklist never blocked, and on the firewall side a whitelist blocked every visitor. Codes may now be separated by new lines, commas, semicolons or spaces.
* **GeoIP mode "Disabled" still looked up every visitor:** the code checked for `off`, the setting saves `disabled`. Lookups now only run in blacklist or whitelist mode.
* An empty whitelist blocked all logins (login side) while the firewall side allowed all; both now block nothing with an empty list.
* The country code example said `EN` (not a country code); now `DE`, `AT`.
* The scanner exclusion field showed a site-specific path as default value; it is now empty (placeholder `/wp-content/cache/`). Saved exclusions are not changed.

### Docs

* README rewritten: plain description, screenshots, correct requirements and backup description, list of external services.

## [2.0.2] - The Hive: endpoint via rest_route

### Changed

* **Hive messages are sent to `/?rest_route=/tegatai/v1/hive/receive`** instead of `/wp-json/tegatai/v1/hive/receive`. This form of the REST API works on every WordPress site, also when `/wp-json/` is renamed (WP Masking), blocked by server rules or answered by a maintenance or caching plugin (found on a site in maintenance mode, which answered `/wp-json/` with its maintenance page). Receiving sites need no change; all Tegatai versions accept it.
* Security is unchanged: only the route is in the URL. The message is in the POST body, signed (Ed25519 or HMAC), encrypted end to end for Ed25519 peers, and sent over HTTPS.

## [2.0.1] - The Hive: delivery check

### Fixed

* **Hive messages were counted as delivered without reaching the peer.** A redirect of the peer's endpoint (e.g. without/with `www`, `http` → `https`, a server rule) was followed automatically; the POST became a GET on another page that answered with HTTP 200. The connection test then showed "OK" and queued bans were dropped as delivered.
  * Redirects are no longer followed. The connection test shows "HTTP 301 redirect to …" with the target, so the peer URL can be corrected.
  * A message only counts as delivered when the peer's Hive endpoint itself confirms it (JSON answer). Any other HTTP 200 (cached page, proxy, Tegatai not active) is reported as an error and retried.
  * Refusals of the peer's endpoint (signature, protected IP, duplicate) are logged and not retried.

## [2.0] - The Hive: Ed25519 and Encryption

### New

* **Ed25519 node keys (protocol v2):** every site signs Hive messages with its own private key; the other sites only know its public key (`URL | ed25519:<public key>` in the peer list). A compromised site can no longer send bans in the name of another site, and a site is revoked by removing its line on the others – no new shared secret for everyone.
* **End-to-end encryption:** v2 messages carry the IP, reason and level encrypted with libsodium `crypto_box` (X25519 keys derived from the Ed25519 keys). Readable only by the receiving site, also behind a CDN or proxy that terminates TLS or with SSL verification off.
* **`wp tegatai hive-keygen`:** creates the key pair when the admin runs it (Tegatai never creates keys on its own). The private key goes to `secrets/tegatai-hive-key.php` next to `tegatai-secrets.php` (file `0600`, folder `0700`), is never printed and is not overwritten without `--replace`. Only the public key line is shown. Run it as the site's PHP-FPM user. Also `wp tegatai hive-pubkey`, and the public key on the Hive page.
* Other key locations: `TEGATAI_HIVE_KEY_FILE` (path) or `TEGATAI_HIVE_PRIVATE_KEY` (the key) in `wp-config.php`.

### Security

* **Signed recipient:** every message (v1 and v2) contains the receiving site; a message for another site is rejected, so it cannot be replayed to a different node within the time window.
* **No downgrade:** a peer with an Ed25519 key is only accepted with its Ed25519 signature, never over HMAC. Ed25519 peers are always strict (unknown senders are rejected).
* **Peers removed from the list** are no longer contacted from the retry queue.
* The connection test shows the method per peer ("Ed25519 verified, encrypted" / "HMAC Verified") and the reason of a 403.

### Compatibility

* Sites can be switched one by one: peers without a key keep using HMAC-SHA256 (protocol v1) with their pair secret or the shared secret. Sites before 2.0 ignore the new recipient field.
* Requires the PHP sodium extension (bundled with PHP 8.4); without it the Hive page shows a notice and only HMAC is used.

## [1.9] - WP Masking: File Names

### New

* **Hide file names (WP Masking):** file names of masked plugin, theme and wp-includes files are replaced by a neutral name per file, e.g. `/assets/bar/css/kanri-bar.css` → `/assets/bar/css/t3f9a0c1d2e4`, so neither the name nor the file type is visible in the page.
  * The folders stay, so relative URLs inside CSS and JS (fonts, images, script chunks) keep working; files loaded that way keep their real name.
  * A changed file gets a new name, which also makes browsers load the new version (the `?ver=` parameter is removed by "Remove versions and identifiers").
  * New files are found when pages are visited. Tegatai adds them to `tegatai-nginx.conf` and checks them every hour (WP-Cron) or right away with "Check new paths". A new name is only used after nginx was reloaded and the name answered with the real file; until then the page keeps the real file name.
  * Names of replaced files stay mapped for 30 days, so cached pages keep working.
  * nginx only handles the new names in a separate location (`.../t` + 11 characters), so other requests are not slowed down.

## [1.8] - WP Masking

### New

* **WP Masking (Server & System → WP Masking, nginx):** hides the WordPress structure in the pages visitors receive.
  * **Plugin and theme paths:** plugin and theme folders are shown as `/assets/<name>/`. The name is set per plugin and theme; empty fields get an automatic short name. The folder `assets` can be renamed.
  * **WordPress core:** `/wp-includes/` → `/lib/`, `/wp-json/` → `/api/`, `admin-ajax.php` → `/ajax` (names can be changed). `/wp-json/` keeps working for The Hive and other sites; REST links point to the new path.
  * **Versions and identifiers:** removes `?ver=` parameters, script/style ids, generator tags (also those of other plugins), RSD/wlwmanifest/shortlink/REST links, the emoji script, the speculation rules and the `X-Pingback` header.
  * **Block original paths:** direct requests for the original paths of masked entries answer 404. Logged-in users and files loaded by pages of the site itself keep access; `/wp-json/tegatai/` (The Hive) stays reachable.
* **Rules:** nginx maps the new paths back to the real files (static files only, never PHP). The rules are written to `tegatai-nginx.conf`, after all other rules.
* **Safe activation:** "Check new paths" requests every new path once without cookies and compares the answer with the real file. Only paths that work are used in the pages and blocked, so a missing nginx reload never breaks the site. A renamed path stays in use until the new one works, and earlier names stay mapped for cached pages.
* **Page caches:** the HTML is rewritten before page caches store it, so cached pages contain the new paths.

## [1.7.1] - Banner and Icon

### New

* **Banner:** The header of the Tegatai settings page shows the new Tegatai Secure banner (`assets/banner-772x250.png`) on a light cyan-to-lavender background. The Terminal, Hive and API Gateway pages keep their headers.
* **Icon:** New plugin icon `assets/icon-256x256.png`.
* **README:** The banner is shown at the top of the README.

### Fixes

* The version badge in the header showed `v1.5`; it now shows the installed version.

## [1.7] - AbuseIPDB Reporting

### New

* **AbuseIPDB reporting (Firewall tab):** Bans from the honeypot URL, the 404 instant ban, the 404 scan and the login traps are reported to AbuseIPDB, including bans received through The Hive. Categories: Web App Attack, Hacking, Bad Web Bot and Brute-Force, depending on the ban.
* **Background sending:** Reports are queued and sent via WP-Cron (up to 20 per run), so a ban never waits for the API.
* **Privacy:** Reports contain only the IP, the category and the type of the ban - no URLs, usernames or other request data. Private and reserved IPs are never reported.
* **Limits:** The same IP is reported at most once per 15 minutes. HTTP 429 pauses sending until the API allows it again; rejected reports (HTTP 422) are dropped; an invalid key stops sending and is shown in the status.
* **Status (Firewall tab):** Key found or missing, reports sent today and in total, waiting reports, last report and last error. Errors are also written to the Tegatai log (type `ABUSEIPDB`).
* **Secrets:** New secret `TEGATAI_ABUSEIPDB_KEY` (secrets file or `wp-config.php`), shown in the Secrets tab with a link to the AbuseIPDB API page.

### Developers

* New action `tegatai_hive_ban_applied` (`$ip, $reason, $level, $node`), fired when a ban from a Hive peer is applied.

## [1.6] - Secrets File

### New

* **Secrets file outside the web root:** `TEGATAI_HIVE_SECRET`, `TEGATAI_API_SECRET`, `TEGATAI_SUDO_PIN` and `TEGATAI_BACKUP_SECRET` can be stored in their own PHP file instead of `wp-config.php`. Default location is one level above the WordPress directory: `../secrets/tegatai-secrets.php`. Another location can be set in `wp-config.php` with the path only (`TEGATAI_SECRETS_FILE`). No `include` line is needed; Tegatai loads the file itself.
* **Secrets tab (Management → Secrets):**
  * Shows the path of the secrets file, whether it was found and its permissions (0600 recommended).
  * Shows for every secret where it is loaded from: secrets file, `wp-config.php`, database or not set. Secret values are never displayed.
  * **Create secrets file:** copies the secrets currently defined in `wp-config.php` into the file (directory 0700, file 0600). An existing file is never overwritten, and no new keys are generated automatically (Hive needs the same key on every site).
  * A guide explains what each key is for and shows the command to create it, plus a template for creating the file manually.

### Compatibility

* Secrets defined in `wp-config.php` keep working and take precedence over the secrets file. Remove the `define()` lines from `wp-config.php` after moving them.
* Keep `TEGATAI_BACKUP_SECRET` unchanged when moving it, otherwise existing backups cannot be decrypted.
* The secrets folder must be inside the PHP `open_basedir` of the site. If `open_basedir` only allows the document root (e.g. Froxlor "OpenBasedir path: document root"), PHP cannot read the file; allow the parent directory or home directory instead.

## [1.5] - Code Quality (Plugin Check)

### Fixes

* **Server rules:** `tegatai-nginx.conf` was deleted on every deactivation and never written again on activation, so after an update, a reinstall or a renamed plugin folder the rules were missing until "Write rules to config" was clicked. Deactivation now leaves an empty placeholder (nginx refuses to reload when an `include` points to a missing file), and activation writes the rules again.
* **Server rules:** "Write rules to config" failed silently and always reported success. It now reports the exact error (path and reason), and the "Server" tab shows where the file is and the matching `include` line.

### Code Quality (Plugin Check)

* **Output escaping:** All admin output is escaped late (`esc_html`, `esc_attr`, `esc_url`, `esc_js`, `wp_kses`). Nonce fields inside concatenated HTML go through `wp_kses()` with the `TEGATAI_KSES_INPUT` allow-list. `wp_die()` messages are escaped.
* **SQL:** Every query with a table name uses `$wpdb->prepare()` with the `%i` identifier placeholder (logger, terminal, option scanner, DB scan, backup, deep clean, settings table, expired transients).
* **Input:** Admin form fields are unslashed before sanitizing (`wp_unslash()`), nonces are sanitized before verification, missing `isset()` checks were added.
* **WordPress functions:** `wp_parse_url`, `gmdate`, `wp_rand`, `wp_strip_all_tags`, `wp_is_writable`, `wp_delete_file`, `wp_mkdir_p` and `wp_safe_redirect` replace their PHP counterparts.
* **Settings:** `register_setting()` has a `sanitize_callback`.
* **Translations:** `translators:` comments for all strings with placeholders; the alert e-mail string uses numbered placeholders (`.pot`, `.po` and `.mo` updated).
* **Bundled library:** Direct access guards in `lib/plugin-update-checker`.
* **readme.txt:** Plugin name matches the header, 5 tags, short description under 150 characters, "Requires at least" matches the header.
* **Documented exceptions** (`phpcs:ignore` / `phpcs:disable` with reason): raw request inspection in the firewall and API Guard, raw headers for fingerprints, public forms protected by tokens or Turnstile instead of nonces, Cloudflare Turnstile loaded from Cloudflare, direct queries on Tegatai's own tables, `unlink()`/`rename()` where the result controls the quarantine, core hooks `wp_login`/`wp_login_failed`, binary backup download, locally generated QR SVG.

## [1.4.2] - Security Fixes

### Fixes

* **Client IP detection:** Proxy headers (`CF-Connecting-IP`, `X-Real-IP`, `X-Forwarded-For`) are no longer trusted blindly. Previously `X-Forwarded-For: 127.0.0.1` bypassed the whole firewall, the API Guard allowlist and rate limits. Only `REMOTE_ADDR` counts unless the request comes from a trusted proxy (`TEGATAI_TRUSTED_PROXIES` or the `tegatai_trusted_proxies` filter). Local reverse proxies (loopback/`SERVER_ADDR`) are trusted for `X-Forwarded-For` automatically.
* **Activation/deactivation:** Hooks are now registered at file level. Previously `activate()` never ran, so the daily maintenance, backup, malware and FIM cron events were never scheduled. Existing installs are repaired automatically on the next admin or cron request.
* **Deactivation:** `.htaccess` rules are now removed (marker mismatch `TEGATAI` vs. `Tegatai-Secure`); all Tegatai cron events are cleared.
* **Log/backup directories:** `.htaccess` now works on Apache 2.2 and 2.4 (no more 500 without `mod_access_compat`); `tegatai-logs/` is protected as well.
* **API Guard HMAC v2 (breaking):** Signature is now `METHOD|URI|timestamp|req_id|sha256(body)`. Request IDs are claimed atomically and kept for the full timestamp window (also for Hive), closing a replay window.
* **Tarpit:** At most 2 concurrent delayed responses (filter `tegatai_api_tarpit_max_concurrent`), 2–4 s instead of unbounded 6–10 s, to avoid exhausting PHP-FPM workers.
* **Translations:** Text domain unified to `tegatai-secure`; German translations now load. Plugin header version aligned to 1.4.2.
* **The Hive:** Outgoing broadcasts were never triggered (no `do_action('tegatai_ip_banned')` anywhere); the firewall and login traps now fire it, sending happens asynchronously via WP-Cron. Per-peer secrets (`URL | secret`), optional strict peer mode, expiring bans (default 24 h) stored outside the manual blacklist, a never-ban allowlist (incl. whitelists, private ranges, recent admin IPs) and a per-peer rate limit.
* **Log maintenance:** `prune_logs()` received `''` from `do_action()` and deleted nothing; the transient cleanup query failed with MySQL error 1093. Log table IDs are now `bigint unsigned`, the zero-date default is gone, `time` is indexed.
* **Settings:** No more `SHOW TABLES` per request (table state is stored as an option). New values are stored as JSON, legacy serialized values are read with `allowed_classes => false`.
* **Backups:** New backups use AES-256-GCM (authenticated) with a properly derived 256-bit key; existing CBC backups can still be downloaded.
* **Removed:** The non-functional "Remote FTP" card (no upload or save handler existed; it echoed decrypted credentials into the page). Stored FTP credentials are deleted.
* **Admin links:** Redirects and the Terminal submenu used the slug `tegatai-secure` instead of `tegatai-Secure`.
* **Bans:** New central, expiring ban list (`Tegatai_Bans`) enforced on every request. Previously trap/404 bans were only checked on 404 pages, the admin-username trap created a permanent autoloaded option per IP and banned real accounts named "admin". Without Redis/APCu a 24 h ban expired after 5 minutes.
* **Login:** Turnstile and the login honeypot now really block (they ran before core's password check and were ignored). Idle logout no longer locks users out after a long break and writes at most once per minute. Custom login slug works on subdirectory installs. GeoIP failures are cached, `CF-IPCountry` is only trusted from configured proxies, GeoIP also applies to XML-RPC/REST logins.
* **Magic links:** One-time, rate-limited (per IP and user), go through 2FA, fire `wp_login`; temp-admin links work without the magic-link option.
* **2FA:** `wp_login` fires after the code step, `remember`/`redirect_to` are kept, the cookie works on HTTP sites, cookie re-auth and application passwords are not challenged, XML-RPC/REST with a plain password are rejected (use application passwords). Users without a TOTP secret get e-mail codes instead of being locked out; secrets are only shown to the user themself. Codes use `random_int`; wrong codes count towards the login limit.
* **Sessions:** Single session no longer logs the user out right after login, IP/Browser Guard now actually stores and checks the session, "Kill session" works.
* **Spam:** Server-side signed timer (no bypass via `teg_js_time`), logged-in commenters and pingbacks are no longer blocked, case-insensitive trash-mail check, exact referrer host check.
* **Hardening:** Privilege guard restores the previous roles (the role used to stay saved) and allows promotions by users with `promote_users` (REST, CLI); user enumeration via `?author=` is blocked before core's canonical redirect.
* **Firewall:** Lockdown keeps the login page and whitelisted IPs reachable. Rate limit and WAF exempt users with `edit_posts`; guest limits raised to 60/min (API/AJAX) and 180/min. WAF patterns use word boundaries ("medieval (" no longer blocked). `curl`/`wget` are no longer blocked (system cron, monitors). Good-bot rDNS verdicts are cached, IPv6 bots supported. Redis connects lazily, no DB write per new visitor. Nested upload arrays no longer cause a fatal error.
* **Server rules:** nginx/Apache rules use URL paths (subdirectory installs, quarantine dir covered); `/.well-known/` stays reachable. Existing rules are regenerated once on update.
* **Scanners:** The malware cron rescans after a finished pass and no longer stores the file list in an option; hex detection compiles again; Tegatai's own files are skipped; WP_Filesystem/retrieval false positives removed. The content scanner always progresses and skips unreadable directories; an interrupted scan can be resumed or reset. FIM snapshot is stored as a protected file instead of a multi-MB option. Uploads monitor ignores "Silence is golden" index files and has a time budget.
* **Quarantine:** Removed a restore endpoint without nonce (CSRF); protection files are written correctly; a failed quarantine is reported; core-file healing only accepts paths from the official checksums.
* **Admin:** Settings are validated against a schema (unknown keys dropped, WAF regexes kept intact and validated, login slug sanitized), server rules are regenerated after save/import, exports contain no secrets. Missing toggles added (Upload Guard, hide login errors, dashboard block, single session). Deep Clean only optimizes this site's tables. Temp admins are cleaned up daily, their content is reassigned, expired accounts can no longer log in. Copy protection no longer blocks pasting or image links. Terminal polling no longer triggers FLOOD alerts. HSTS `includeSubDomains` is opt-in; the CSP is labeled as a permissive baseline.

### Actionable Security Recommendations

* Added dynamic recommendations to the Security Status card based on the actual Tegatai configuration.
* Distinguishes important, recommended, and optional actions instead of treating every disabled feature as a security problem.
* Added direct links from recommendations to the relevant Tegatai module.
* Added an expandable “Why this score?” breakdown showing how the dashboard score is composed.
* Shows a positive “No action required” state when no configuration issue needs attention.
* No security engine, database schema, request handling, scanner, or module logic changed.

## [1.4.1] - Security Cockpit UI Polish

* Redesigned the Security Cockpit dashboard for a compact, professional WordPress admin layout.
* Added complete styling for status, activity, metrics, protection modules, top sources, and navigation cards.
* Added responsive layouts for tablet and mobile admin screens.
* No security, database, request, scanner, or module logic changed.

## [1.4.0] - Security Cockpit UI

* Redesigned the Tegatai admin dashboard as a security cockpit.
* Added a clear protection status and calculated security score.
* Added recent security activity / “While you were away” panel.
* Added compact 24-hour threat metrics.
* Added protection module status overview.
* Added top security-event sources for the last 24 hours.
* Kept existing module pages, settings, AJAX handlers, database tables, and security logic unchanged.
* No new frontend tracking or additional request-time work was introduced.

## [1.2.1]

* **Fix:** WordPress.WP.I18n.TextDomainMismatch

## [1.2.0]

### Admin Interface & UX

* **New:** Native Terminal Integration. The Live Terminal is no longer an isolated page but seamlessly integrated into the native WordPress dashboard layout using the new Froxlor Tile-UI.
* **New:** GeoIP Interface Restoration. Restored the missing GeoIP configuration tab with a clean, tile-based interface for operational modes and ISO country codes.
* **New:** Terminal UX Upgrades. Added interactive "Pause/Resume" keyboard controls (P) and visual "Fetching..." indicators to the Live Terminal stream.
* **Update:** Complete UI Standardization. Successfully rolled out the unified, highly condensed "Tile & Grid" UI across all remaining modules (The Hive, API Guard, Terminal).

### Cryptography & Core Security

* **New:** Strict MD5 Checksum Verification. The Core Integrity "Heal" function now cryptographically verifies downloaded core files from WordPress.org via MD5 before writing them to the local disk, aborting on mismatch.
* **Fix:** Open Redirect Prevention (CWE-601). Replaced all instances of wp_redirect() with wp_safe_redirect() across the entire suite (Session Guard, User History, Extras, Sessions, Hardening).
* **Fix:** Privilege Escalation Guard Hardening. The escalation interceptor now correctly dispatches strict HTTP 403 Forbidden headers upon blocking unauthorized role upgrades.
* **Fix:** Header Conflict Guard. The system now actively parses existing server headers (via headers_list) before dispatching security headers, effectively preventing duplicate header errors and third-party plugin conflicts.
* **Fix:** Hardened all background static method calls (e.g., Tegatai_Logger) with defensive class_exists() wrappers to prevent fatal errors during plugin initializations or updates.

### Telemetry & Unified Logging

* **New:** Unified Proxy-Aware IP Routing. Completely eliminated raw $_SERVER['REMOTE_ADDR'] anomalies. Honeypot and Terminal modules now strictly route through the proxy-agnostic Tegatai_Logger::get_ip() method.
* **New:** Unified Login Telemetry. Successful logins are now instantly streamed into the central Live Terminal and Database Logger (Type: LOGIN), while maintaining legacy widget array compatibility.
* **New:** The Login Honeypot now automatically pushes real-time AUTH-BAN events directly to the central Live Terminal.

### Scanners & Threat Intelligence

* **New:** Dynamic Database XSS Auditing. The stored XSS scanner now accepts customizable, user-defined Regex patterns directly via the dashboard to actively hunt zero-day payloads.
* **New:** Automated Timeline Garbage Collection. Integrated a lightweight 30-day pruning routine into the existing 6-hour cron (tegatai_malware_cron) to keep the wp_options table perfectly clean.
* **New:** Absolute Path Tracking. The File Integrity Monitor (FIM) now structurally maps absolute server paths (abs) for changed, new, and deleted files, laying the foundation for future automated file-healing.
* **Fix:** Anti-Spam Client Timer. Injected a missing native JavaScript timer payload into the frontend wp_footer to ensure accurate bot-speed detection without triggering false positives for real users.
* **Fix:** Terminal DDoS Protection. Hardened the Live Terminal AJAX endpoint with strict nonce validation and a 2-second In-Memory Leaky-Bucket Rate Limit (Unified Cache) to prevent database spamming.

## [1.1.1]

### WAF, Firewall & Server Rules

* **New:** Enterprise Bad-Bot & AI-Scraper Protection. Server rules (Nginx & Apache) now accurately categorize and block aggressive SEO bots, scanners, and AI crawlers (ChatGPT, Claude, etc.).
* **New:** ReDoS Shield (Regular Expression Denial of Service). All regex validations in the WAF, API Guard, and Scanner are now safely caught (@preg_match & preg_last_error()) to prevent server crashes caused by broken custom rules.
* **New:** Dynamic path detection for Nginx rules (now uses wp_upload_dir and plugins_url instead of hardcoded paths).
* **Fix:** Added Apache Loopback bypass (127.0.0.1 / ::1) to prevent internal server scripts from accidentally being locked out by bot rules.
* **Fix:** Removed top-level code in the firewall. All checks now safely run via WP hooks (init), preventing issues during plugin deactivation or aggressive caching.

### Core & Performance Engine

* **New:** Implemented Unified Cache Engine. Modules (Firewall, GeoIP, API Guard, Scanner) now intelligently utilize memory (APCu / Redis / Object Cache) before falling back to transients or file caching.
* **New:** Fixed a critical recursion bug in the old Redis class.
* **New:** Standardized centralized client IP detection (get_client_ip) and loopback verification (is_protected_ip) across all modules (DRY principle).
* **New:** Rate limiting now uses cache keys without query strings to prevent rate-limit bypass exploits (?rand=123).

### The Hive (Threat Intelligence)

* **New:** Background Retry-Queue via WP-Cron. If a broadcast to a peer node fails (e.g., timeout), the payload enters a queue and is re-signed with a fresh timestamp and resent in the background.
* **New:** 24-hour Garbage Collection (GC) for the Hive Queue to protect the database from dead peer nodes.
* **Fix:** Unified Sudo Vault logic. True separation between "Reveal" (showing the current secret) and "Generate" (creating a new secret).

### LoginGuard & 2FA

* **New:** Advanced Fingerprinting for Trusted Devices. In addition to IP and User-Agent, modern Client Hints (Sec-CH-UA, Platform) are now used for verification.
* **New:** Dynamic 2FA interface. The prompt now intelligently adapts depending on whether the user uses "App", "Email", or "Both".
* **New:** UX upgrade for the 2FA code input field (centered, increased letter spacing for smartphone users).
* **New:** Magic Links now use wp_safe_redirect(admin_url()) for full Multisite compatibility.
* **Fix:** Fixed Mojibake (broken German characters/umlauts) in the 2FA interface and made it fully translation-ready (esc_html__).

### Malware Scanner & Backup

* **New:** AES-256-CBC "Data-at-Rest" encryption for database backups. Backups are compressed and securely stored on the server, and only decrypted on-the-fly in RAM when "Download" is clicked in the backend.
* **New:** Backup Retention Policy. Old backups are automatically deleted via Garbage Collection (Default: keeps the last 7 backups) to save server storage.
* **New:** Intelligent CVE validation. The vulnerability scanner now actively compares the installed plugin version with the patch level (fixed_in) from the WP Vulnerability API to eliminate false positives.
* **New:** The background scanner is now completely "self-contained" and uses native WP-Crons with an aggressive 1-second chunking for massively faster scans.
* **New:** The scanner snapshot is now held in the Unified Cache (RAM), extremely reducing disk I/O on large sites.

### Admin Interface & UX

* **New:** Complete dashboard redesign. The interface now uses a highly condensed "Tile Grid" (Froxlor style) to save power users from endless scrolling.
* **New:** Tooltip system. Long descriptions are now hidden behind clean ? hover icons to maximize information density.
* **New:** Modern Clipboard API (navigator.clipboard) for all copy buttons, including visual feedback ("✔ Copied!").

## [1.1.0]

### Security Core & Architecture

* **New:** Tegatai Sudo Vault: Master tokens and secrets (API Guard & The Hive) are no longer loaded into the HTML source code. Revealing or generating critical keys now requires active confirmation via a Sudo PIN (TEGATAI_SUDO_PIN).
* **New:** Bcrypt Hash Verification: The Sudo PIN is no longer matched in plain text. It now uses secure one-way hashes (password_verify) to protect the infrastructure even in the event of local file theft.
* **New:** Data-at-Rest Protection (Zero-Knowledge): Keys can now be hardcoded via wp-config.php (TEGATAI_API_SECRET, TEGATAI_HIVE_SECRET). This completely locks the web input fields and eliminates the database as an attack vector.
* **UI:** Admin Bar Cleanup: The terminal icon has been removed from the global WordPress admin bar to prevent accidental clicks and keep the frontend clean.

### API Gateway (formerly API Guard)

* **Update:** Advanced Routing Engine: Endpoints can now be secured not only via simple text matching (Contains), but precisely via Exact Match or Regex.
* **New:** ReDoS Shield for Regex: Regex patterns are now limited to 255 characters and block recursive quantifiers to fend off "Regular Expression Denial of Service" attacks.
* **New:** Traffic Control (Rate Limiting): A new In-Memory Leaky-Bucket Rate-Limiting (10 requests/minute, 50 requests/hour) stops brute-force attacks extremely resource-efficiently by returning an HTTP 429 status early in the load cycle.
* **New:** IPv6 CIDR Allowlist: Added a strict network barrier. Only explicitly defined server IPs or subnets (IPv4 & IPv6 natively supported) are permitted to pass the gateway.
* **New:** HMAC v2 Handshake Mode: Webhooks can now be configured to cryptographically sign the URI, timestamp, and a unique request ID (req_id), completely neutralizing replay attacks.

### The Hive (Cross-Network Intelligence)

* **Update:** Zero-Trust Cryptography: All ban broadcasts across the network are now secured by an asynchronous HMAC-SHA256 signature of the payload (no more plain text secret headers).
* **New:** Anti-Replay Protection: Every sync request now requires a UNIX timestamp (max. 60s time drift) and a unique nonce ID to block spam or the injection of intercepted requests.
* **New:** Connection Tester: New diagnostic tool in the dashboard (bulletproof against third-party PHP warnings) to test HMAC handshakes with all peer nodes live.
* **Fix:** Explicit Whitelisting: The Hive now communicates strictly with manually entered peer node URLs, preventing unintentional pinging of external sites.

### Performance & Delta DB Scanner

* **New:** Asynchronous Delta Engine: The malware scanner (dbscan.php) no longer relies on slow WP_Query loops. It now executes high-performance, raw MariaDB queries ($wpdb).
* **New:** Smart Incremental Scans: The scanner remembers the timestamp of the last successful scan. During a regular run, only posts modified since that exact timestamp are checked. This reduces server load on massive databases by up to 99%.
* **New:** AJAX Chunking: Full ("Deep") scans are now processed in asynchronous batches of 500 records to prevent PHP timeouts, complete with a live UI progress bar.

### Firewall & System Immunity

* **Fix:** Universal System Immunity: Local server IPs and loopback addresses (127.0.0.1, ::1) are now absolutely immune and can no longer be banned by the firewall or The Hive.
* **Fix:** WP-CLI Bypass: Terminal commands (php_sapi_name() === 'cli') now automatically bypass the firewall. Cache flushes (wp kyasshu flush) or cron jobs will no longer lock out the system administrator.
* **Fix:** Memory Backend Abstraction: Added high-speed caching abstraction (APCu -> Object Cache -> Transients) for rate limits and nonces to prevent database locks during DDoS attacks.

## [1.0.0]

* Initial release.
