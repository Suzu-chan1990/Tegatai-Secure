![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-blue)
![PHP](https://img.shields.io/badge/PHP-8.x-purple)
![License](https://img.shields.io/badge/license-GPLv2%2B-green)
![Security](https://img.shields.io/badge/security-active-red)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

# 🛡️ Tegatai Secure (Enterprise WordPress Security)

**Tegatai Secure** is a high-performance, enterprise-grade security suite for WordPress. Unlike traditional security plugins that process everything at the PHP level, Tegatai integrates directly with your server (**Nginx, Apache, or LiteSpeed**) to block malicious traffic, bots, and brute-force attacks *before* WordPress is even loaded.

It features a zero-load architecture, multiple deep-scanning engines, cryptographic authentication systems, hardened API protection, and encrypted remote communication.

---

# 🚀 Key Advantages

* **Zero-Load Protection:** Malicious requests are dropped directly by the web server via auto-generated `nginx.conf` or `.htaccess` rules.
* **Zero-Knowledge Architecture:** Sensitive secrets and master tokens can be completely removed from the database and securely stored inside `wp-config.php`.
* **Cryptographic API Protection:** HMAC-based request signing with replay protection and rolling timestamps.
* **Enterprise Security without Bloat:** Lightweight architecture focused on performance and real protection.
* **Server-Level Hardening:** Deep integration with Nginx, Apache, and LiteSpeed.
* **Fully CLI Compatible:** Designed to avoid unnecessary PHP timeouts and support large-scale automation.
* **Fully Internationalized:** Translation-ready and multilingual.

---

# 🔐 Zero-Knowledge Security Architecture

Tegatai Secure introduces a hardened secret-management system designed to minimize attack surfaces.

## 🗝️ Sudo Vault

Critical secrets can be protected using a dedicated Sudo Vault system.

Instead of exposing master keys in the WordPress dashboard or storing them permanently in the database, Tegatai supports secure secret handling through `wp-config.php`.

### Example:

```php
// Generate a Bcrypt hash:
// php -r "echo password_hash('YourSecretPin123', PASSWORD_BCRYPT);"

define('TEGATAI_SUDO_PIN', '$2y$10$YourGeneratedHashHere');
```

The PIN itself is never stored in the database.

---

## 🔑 API Secret Locking

Sensitive API secrets can also be fully externalized:

```php
define('TEGATAI_API_SECRET', 'your-super-long-random-secret');
define('TEGATAI_HIVE_SECRET', 'your-hive-network-secret');
```

When configured:

* Secrets are hidden from the UI
* Secrets are never exposed through AJAX
* Secrets are removed from normal database workflows
* Database leaks become significantly less dangerous

---

# 🌐 Tegatai Hive (Distributed Threat Network)

Tegatai Hive allows multiple WordPress installations to communicate and synchronize threat intelligence securely.

## Features

* HMAC-SHA256 signed payloads
* Strict timestamp validation
* Replay-attack protection
* Request-ID verification
* Distributed IP ban synchronization
* Secure node-to-node communication
* Optional SSL verification
* Zero-trust architecture

Every node validates incoming requests cryptographically before applying actions.

---

# 🛡️ API Gateway & Endpoint Protection

The integrated API Gateway protects custom endpoints and synchronization routes.

## Included Features

* Static Token Authentication
* HMAC v2 Authentication
* Replay Protection
* Timestamp Validation
* Request-ID Verification
* IPv4 & IPv6 CIDR Allowlists
* Rate Limiting
* ReDoS-Protected Regex Routing
* CLI / WP-CLI bypass support
* Tarpit delay system for failed authentication

### HMAC Example

```php
$uri = '/api/sync';
$timestamp = time();
$req_id = bin2hex(random_bytes(16));

$signature = hash_hmac(
    'sha256',
    $uri . '|' . $timestamp . '|' . $req_id,
    'YOUR_SECRET'
);
```

---

# 🔥 Complete Feature List

## 🛡️ Web Application Firewall (WAF) & Network

* Bad Bot Blocking
* AI & SEO Bot Blocking
* GeoIP Filtering
* Rate Limiting
* 404 Trap System
* IP Prison
* Distributed Threat Sync (Hive)
* REST API Restriction

---

## ⚡ Server Rules Engine (Nginx / Apache / LiteSpeed)

* Disable PHP in Uploads
* Dotfile Protection
* Sensitive File Protection
* XML-RPC Blocking
* Hotlink Protection
* System File Shielding
* Custom server rule generation

---

## 🔐 Authentication & Login Guard

* Two-Factor Authentication (TOTP / Email)
* Login Attempt Limits
* Magic Links
* Trusted Device Monitoring
* Custom Login Slugs
* Hide `/wp-admin/`
* Idle Logout
* Session Hijack Detection

---

## 🛑 Anti-Spam & Content Protection

* Cloudflare Turnstile
* Honeypot Protection
* Bot Timer Validation
* Disposable Email Blocking
* Referrer Checks
* Link Spam Protection

---

## 🔎 Integrity & Malware Scanners

* Malware Scanner
* File Integrity Monitor (FIM)
* WordPress Core Verification
* Database Injection Scanner
* Dangerous Option Scanner
* Suspicious Cron Detection
* Uploads Monitoring
* File Permission Auditing

---

## 💻 System Hardening

* Security Headers
* CSP / HSTS / X-Frame-Options
* Privilege Escalation Protection
* WP Footprint Removal
* User Enumeration Blocking
* Admin Honeypot
* File Editor Disabling

---

## 👥 Session Security

* IP & Browser Validation
* Single Session Enforcement
* Remote Session Termination
* Active Session Monitoring

---

## 💾 Secure Backups

* Automated Scheduling
* Remote FTP Transfer
* AES-256-CBC Encryption
* Encrypted Credential Storage

---

## 📡 Logging & Monitoring

* Live Traffic Logs
* WAF Event Logs
* Security Timeline
* Discord / Slack Notifications
* Real-Time Threat Monitoring

---

# ⚙️ Installation

## Standard Installation

1. Upload the plugin to:

```text
/wp-content/plugins/tegatai-secure
```

2. Activate the plugin inside WordPress.
3. Open **Tegatai Secure** in the admin dashboard.
4. Configure your preferred protection modules.

---

## Nginx Integration

Tegatai generates an optimized `tegatai-nginx.conf` file.

Example:

```nginx
server {
    # Existing configuration

    include /path/to/wordpress/tegatai-nginx.conf;
}
```

---

## Apache / LiteSpeed

Rules are automatically injected into `.htaccess`.

---

# ⚙️ Requirements

* WordPress 6.0+
* PHP 8.x+
* Recommended: Nginx / OpenResty / LiteSpeed

---

# 💻 CLI Compatibility

Tegatai Secure is designed to work in large-scale and automated environments.

Features include:

* WP-CLI compatibility
* Timeout-safe workflows
* Cron-safe execution
* Large dataset handling
* Server automation support

---

# 🔒 Security Philosophy

Tegatai Secure follows a minimalistic security philosophy:

* Prevent attacks before PHP loads
* Reduce attack surfaces
* Avoid unnecessary dependencies
* Keep secrets outside the database whenever possible
* Prioritize performance and server stability
* Focus on real-world protection instead of marketing features

---

# 🤝 Contributing

See `CONTRIBUTING.md`

---

# 🚨 Security Reporting

If you discover a vulnerability, please report it privately.

Contact:

```text
security@your-domain.example
```

---

# 📄 License

GPL v2 or later.

See `LICENSE`.

---

# 📜 Changelog

Current Version: `1.1.x`

See `CHANGELOG.md` for detailed release notes.

