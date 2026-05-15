=== Tegatai Secure ===
Contributors: tegatai
Tags: security, firewall, malware scanner, wordpress security, hardening, 2fa
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 8.x
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Enterprise-grade WordPress security suite: WAF, deep scanning, login protection, integrity monitoring, hardening, and logs.
== Description ==

**Tegatai Secure** is a high-performance, enterprise-grade security suite for WordPress. Unlike traditional security plugins that process everything at the PHP level, Tegatai integrates directly with your server (**Nginx, Apache, or LiteSpeed**) to block malicious traffic, bots, and brute-force attacks *before* WordPress is even loaded.

It features a zero-load architecture, 8 deep-scanning engines, and military-grade encryption for remote backups.

Key features:

* Key Advantages
* Complete Feature List
* Installation & Setup

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`
2. Activate the plugin in WordPress
3. Open **Tegatai Secure** and configure your modules

== Frequently Asked Questions ==

= Does this plugin use external services? =
No. Tegatai Secure is self-hosted and runs on your server.

= Will the firewall block legitimate users? =
It can if rules are too aggressive. Use whitelists and safe mode while tuning.

== Screenshots ==

1. Security Dashboard
2. Firewall Settings
3. Malware Scanner
4. Login Security
5. Logs & Timeline

== Changelog ==

= 1.1.0 =

🔐 Security Core & Architecture

    [NEW] Tegatai Sudo Vault: Master tokens and secrets (API Guard & The Hive) are no longer loaded into the HTML source code. Revealing or generating critical keys now requires active confirmation via a Sudo PIN (TEGATAI_SUDO_PIN).
    [NEW] Bcrypt Hash Verification: The Sudo PIN is no longer matched in plain text. It now uses secure one-way hashes (password_verify) to protect the infrastructure even in the event of local file theft.
    [NEW] Data-at-Rest Protection (Zero-Knowledge): Keys can now be hardcoded via wp-config.php (TEGATAI_API_SECRET, TEGATAI_HIVE_SECRET). This completely locks the web input fields and eliminates the database as an attack vector.
    [UI] Admin Bar Cleanup: The terminal icon has been removed from the global WordPress admin bar to prevent accidental clicks and keep the frontend clean.

🛡️ API Gateway (formerly API Guard)

    [UPDATE] Advanced Routing Engine: Endpoints can now be secured not only via simple text matching (Contains), but precisely via Exact Match or Regex.
    [NEW] ReDoS Shield for Regex: Regex patterns are now limited to 255 characters and block recursive quantifiers to fend off "Regular Expression Denial of Service" attacks.
    [NEW] Traffic Control (Rate Limiting): A new In-Memory Leaky-Bucket Rate-Limiting (10 requests/minute, 50 requests/hour) stops brute-force attacks extremely resource-efficiently by returning an HTTP 429 status early in the load cycle.
    [NEW] IPv6 CIDR Allowlist: Added a strict network barrier. Only explicitly defined server IPs or subnets (IPv4 & IPv6 natively supported) are permitted to pass the gateway.
    [NEW] HMAC v2 Handshake Mode: Webhooks can now be configured to cryptographically sign the URI, timestamp, and a unique request ID (req_id), completely neutralizing replay attacks.

🌐 The Hive (Cross-Network Intelligence)

    [UPDATE] Zero-Trust Cryptography: All ban broadcasts across the network are now secured by an asynchronous HMAC-SHA256 signature of the payload (no more plain text secret headers).
    [NEW] Anti-Replay Protection: Every sync request now requires a UNIX timestamp (max. 60s time drift) and a unique nonce ID to block spam or the injection of intercepted requests.
    [NEW] Connection Tester: New diagnostic tool in the dashboard (bulletproof against third-party PHP warnings) to test HMAC handshakes with all peer nodes live.
    [FIX] Explicit Whitelisting: The Hive now communicates strictly with manually entered peer node URLs, preventing unintentional pinging of external sites.

⚡ Performance & Delta DB Scanner

    [NEW] Asynchronous Delta Engine: The malware scanner (dbscan.php) no longer relies on slow WP_Query loops. It now executes high-performance, raw MariaDB queries ($wpdb).
    [NEW] Smart Incremental Scans: The scanner remembers the timestamp of the last successful scan. During a regular run, only posts modified since that exact timestamp are checked. This reduces server load on massive databases by up to 99%.
    [NEW] AJAX Chunking: Full ("Deep") scans are now processed in asynchronous batches of 500 records to prevent PHP timeouts, complete with a live UI progress bar.

⚙️ Firewall & System Immunity

    [FIX] Universal System Immunity: Local server IPs and loopback addresses (127.0.0.1, ::1) are now absolutely immune and can no longer be banned by the firewall or The Hive.
    [FIX] WP-CLI Bypass: Terminal commands (php_sapi_name() === 'cli') now automatically bypass the firewall. Cache flushes (wp kyasshu flush) or cron jobs will no longer lock out the system administrator.
    [FIX] Memory Backend Abstraction: Added high-speed caching abstraction (APCu -> Object Cache -> Transients) for rate limits and nonces to prevent database locks during DDoS attacks.


= 1.0.2 =

# 🚀 Release v1.0.2 (Performance & Management Update)

This major update introduces high-performance infrastructure integrations, timeout-free background scanning, and significant quality-of-life improvements for server administrators.

## ✨ New Features & Enhancements
* **In-Memory WAF (Redis Integration):** The firewall now automatically detects and utilizes Redis (`SETEX`) to store IP bans and rate limits directly in RAM. This drastically reduces database load during severe brute-force or DDoS attacks, with a seamless fallback to DB transients if Redis is unavailable.
* **Asynchronous Background Scanner:** Malware and FIM scans now utilize WP-Cron for background processing. You can start a scan from the dashboard and safely close the tab while the server processes files in chunks without triggering HTTP/PHP timeouts.
* **Native WP-CLI Support:** Added the `wp tegatai scan` command. Server administrators can now execute full malware scans directly from the terminal for maximum performance on massive websites.
* **1-Click Quarantine Restore:** Added a new "Restore" action in the Quarantine dashboard. Administrators can now instantly revert false-positive files from the `.bin` quarantine back to their original file paths.
* **Built-in WP-Cron Manager:** The Cron Monitor tab now features a fully functional native UI to view all active scheduled tasks (hooks, schedules, next run time) and includes a 1-click "Delete" function to clear stuck or malicious cron jobs without requiring third-party plugins.

## 🛡️ Security & Core Fixes
* **Accurate Proxy/Cloudflare IP Detection:** Replaced direct `$_SERVER['REMOTE_ADDR']` calls with a robust fallback chain (`HTTP_CF_CONNECTING_IP`, `HTTP_X_FORWARDED_FOR`). Tegatai now correctly identifies the attacker's real IP behind proxies and load balancers instead of accidentally banning the proxy node.
* **Bulletproof Backup Directory:** The `tegatai-backups/` folder is now strictly secured against public directory traversal. The plugin automatically generates `.htaccess` (Apache/LiteSpeed), `web.config` (IIS), and provides native block rules for Nginx servers.
* **Cache-Safe Anti-Spam Timer:** Replaced the PHP-based form timestamp with a dynamic, client-side JavaScript execution timer. The bot-protection timer now works flawlessly on sites heavily optimized by page caching plugins (e.g., WP Rocket, LiteSpeed Cache).

## 🐛 Bug Fixes & UX Polish
* **Dashboard Stats Logic:** Fixed a rendering logic flaw where the 24-hour block and failed login statistics always displayed "0" due to premature HTML output. Metrics now calculate and display in real-time.
* **Mobile Session Guard Warning:** Added a clear UI warning to the "IP Guard" feature, alerting administrators that dynamic mobile network IPs (4G/5G) will trigger forced logouts.
* **Fatal Error Resolution:** Cleaned up duplicate AJAX method declarations (`ajax_restore_quarantine`, `ajax_delete_cron`) that caused fatal crashes in strict PHP environments during updates.
* **CLI Dashboard Hint:** Added a clean UI prompt within the Scanner tab to educate users about the available WP-CLI terminal commands.

---
*Recommended update for all users to ensure optimal WAF performance and strict proxy compatibility.*

== Upgrade Notice ==

== Changelog ==

= 1.0.1 =

🐛 Bug Fixes & Backend Polish

    Enterprise Features Activation: Added missing feature toggles (Admin Honeypot, Privilege Escalation Guard, Turnstile CAPTCHA, and Auto-Quarantine) to the strict internal whitelist. These enterprise protections can now be activated and saved without triggering AJAX validation errors.

    PHP Fatal Error Resolution: Fixed a critical typo in the form handler where a missing variable identifier ($_POST) caused the settings panel to crash on strict PHP environments.

    Syntax & Parsing Stability: Cleaned up residual syntax parsing errors in the admin dashboard controller to ensure flawless compatibility with PHP 8.1+.

    GeoIP UI Correction: Resolved a character encoding bug (mojibake) within the GeoIP settings tab that displayed corrupted text instead of the intended clean UI elements.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
