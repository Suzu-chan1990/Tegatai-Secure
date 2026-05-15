# Changelog
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
