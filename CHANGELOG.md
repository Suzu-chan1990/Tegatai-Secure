# Changelog

## 1.2.0

🎨 Admin Interface & UX

    [NEW] Native Terminal Integration. The Live Terminal is no longer an isolated page but seamlessly integrated into the native WordPress dashboard layout using the new Froxlor Tile-UI.
    [NEW] GeoIP Interface Restoration. Restored the missing GeoIP configuration tab with a clean, tile-based interface for operational modes and ISO country codes.
    [NEW] Terminal UX Upgrades. Added interactive "Pause/Resume" keyboard controls (P) and visual "Fetching..." indicators to the Live Terminal stream.
    [UPDATE] Complete UI Standardization. Successfully rolled out the unified, highly condensed "Tile & Grid" UI across all remaining modules (The Hive, API Guard, Terminal).

🔐 Cryptography & Core Security

    [NEW] Strict MD5 Checksum Verification. The Core Integrity "Heal" function now cryptographically verifies downloaded core files from WordPress.org via MD5 before writing them to the local disk, aborting on mismatch.
    [FIX] Open Redirect Prevention (CWE-601). Replaced all instances of wp_redirect() with wp_safe_redirect() across the entire suite (Session Guard, User History, Extras, Sessions, Hardening).
    [FIX] Privilege Escalation Guard Hardening. The escalation interceptor now correctly dispatches strict HTTP 403 Forbidden headers upon blocking unauthorized role upgrades.
    [FIX] Header Conflict Guard. The system now actively parses existing server headers (via headers_list) before dispatching security headers, effectively preventing duplicate header errors and third-party plugin conflicts.
    [FIX] Hardened all background static method calls (e.g., Tegatai_Logger) with defensive class_exists() wrappers to prevent fatal errors during plugin initializations or updates.

🌐 Telemetry & Unified Logging

    [NEW] Unified Proxy-Aware IP Routing. Completely eliminated raw $_SERVER['REMOTE_ADDR'] anomalies. Honeypot and Terminal modules now strictly route through the proxy-agnostic Tegatai_Logger::get_ip() method.
    [NEW] Unified Login Telemetry. Successful logins are now instantly streamed into the central Live Terminal and Database Logger (Type: LOGIN), while maintaining legacy widget array compatibility.
    [NEW] The Login Honeypot now automatically pushes real-time AUTH-BAN events directly to the central Live Terminal.

🦠 Scanners & Threat Intelligence

    [NEW] Dynamic Database XSS Auditing. The stored XSS scanner now accepts customizable, user-defined Regex patterns directly via the dashboard to actively hunt zero-day payloads.
    [NEW] Automated Timeline Garbage Collection. Integrated a lightweight 30-day pruning routine into the existing 6-hour cron (tegatai_malware_cron) to keep the wp_options table perfectly clean.
    [NEW] Absolute Path Tracking. The File Integrity Monitor (FIM) now structurally maps absolute server paths (abs) for changed, new, and deleted files, laying the foundation for future automated file-healing.
    [FIX] Anti-Spam Client Timer. Injected a missing native JavaScript timer payload into the frontend wp_footer to ensure accurate bot-speed detection without triggering false positives for real users.
    [FIX] Terminal DDoS Protection. Hardened the Live Terminal AJAX endpoint with strict nonce validation and a 2-second In-Memory Leaky-Bucket Rate Limit (Unified Cache) to prevent database spamming.

## 1.1.1

WAF, Firewall & Server Rules

    [NEW] Enterprise Bad-Bot & AI-Scraper Protection. Server rules (Nginx & Apache) now accurately categorize and block aggressive SEO bots, scanners, and AI crawlers (ChatGPT, Claude, etc.).
    [NEW] ReDoS Shield (Regular Expression Denial of Service). All regex validations in the WAF, API Guard, and Scanner are now safely caught (@preg_match & preg_last_error()) to prevent server crashes caused by broken custom rules.
    [NEW] Dynamic path detection for Nginx rules (now uses wp_upload_dir and plugins_url instead of hardcoded paths).
    [FIX] Added Apache Loopback bypass (127.0.0.1 / ::1) to prevent internal server scripts from accidentally being locked out by bot rules.
    [FIX] Removed top-level code in the firewall. All checks now safely run via WP hooks (init), preventing issues during plugin deactivation or aggressive caching.

⚡ Core & Performance Engine

    [NEW] Implemented Unified Cache Engine. Modules (Firewall, GeoIP, API Guard, Scanner) now intelligently utilize memory (APCu / Redis / Object Cache) before falling back to transients or file caching.
    [NEW] Fixed a critical recursion bug in the old Redis class.
    [NEW] Standardized centralized client IP detection (get_client_ip) and loopback verification (is_protected_ip) across all modules (DRY principle).
    [NEW] Rate limiting now uses cache keys without query strings to prevent rate-limit bypass exploits (?rand=123).

🌐 The Hive (Threat Intelligence)

    [NEW] Background Retry-Queue via WP-Cron. If a broadcast to a peer node fails (e.g., timeout), the payload enters a queue and is re-signed with a fresh timestamp and resent in the background.
    [NEW] 24-hour Garbage Collection (GC) for the Hive Queue to protect the database from dead peer nodes.
    [FIX] Unified Sudo Vault logic. True separation between "Reveal" (showing the current secret) and "Generate" (creating a new secret).

🔑 LoginGuard & 2FA

    [NEW] Advanced Fingerprinting for Trusted Devices. In addition to IP and User-Agent, modern Client Hints (Sec-CH-UA, Platform) are now used for verification.
    [NEW] Dynamic 2FA interface. The prompt now intelligently adapts depending on whether the user uses "App", "Email", or "Both".
    [NEW] UX upgrade for the 2FA code input field (centered, increased letter spacing for smartphone users).
    [NEW] Magic Links now use wp_safe_redirect(admin_url()) for full Multisite compatibility.
    [FIX] Fixed Mojibake (broken German characters/umlauts) in the 2FA interface and made it fully translation-ready (esc_html__).

🦠 Malware Scanner & Backup

    [NEW] AES-256-CBC "Data-at-Rest" encryption for database backups. Backups are compressed and securely stored on the server, and only decrypted on-the-fly in RAM when "Download" is clicked in the backend.
    [NEW] Backup Retention Policy. Old backups are automatically deleted via Garbage Collection (Default: keeps the last 7 backups) to save server storage.
    [NEW] Intelligent CVE validation. The vulnerability scanner now actively compares the installed plugin version with the patch level (fixed_in) from the WP Vulnerability API to eliminate false positives.
    [NEW] The background scanner is now completely "self-contained" and uses native WP-Crons with an aggressive 1-second chunking for massively faster scans.
    [NEW]: The scanner snapshot is now held in the Unified Cache (RAM), extremely reducing disk I/O on large sites.

🎨 Admin Interface & UX

    [NEW] Complete dashboard redesign. The interface now uses a highly condensed "Tile Grid" (Froxlor style) to save power users from endless scrolling.

    [NEW] Tooltip system. Long descriptions are now hidden behind clean ? hover icons to maximize information density.

    [NEW] Modern Clipboard API (navigator.clipboard) for all copy buttons, including visual feedback ("✔ Copied!").

## 1.1.0
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

## 1.0.0
- Initial release.
