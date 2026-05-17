# Tegatai Security Suite - Architecture

The Tegatai Security Suite (v1.2) is built on a modular, performance-first architecture designed to protect WordPress environments with zero-trust principles.

## Core Modules
1. **WAF & Firewall (`firewall.php`, `headers.php`):** Frontline defense against malicious bots, automated exploits, and missing HTTP security headers.
2. **Scanner & Integrity (`scanner.php`, `core_integrity.php`, `fim.php`, `dbscan.php`):** A multi-layered detection engine covering malware signatures, WordPress core MD5 verification, absolute-path file integrity monitoring, and stored XSS detection.
3. **Login & Session Guard (`login.php`, `session_guard.php`, `twofa.php`, `honeypot.php`):** Hardened authentication featuring 2FA, trusted device fingerprinting, strict session termination (Open Redirect protected), and invisible honeypots.
4. **API Gateway (`api_guard.php`):** A strictly controlled, HMAC-secured gateway for external integrations, featuring in-memory rate limiting and exact/regex path matching.
5. **The Hive (`hive.php`):** A P2P Threat Intelligence network that synchronizes IP bans across multiple trusted nodes using HMAC-SHA256 payloads.
6. **Telemetry & Terminal (`logger.php`, `terminal.php`):** Centralized, proxy-aware event logging with a native UI live-stream and automated 30-day database pruning.
