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
