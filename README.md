![WordPress](https://img.shields.io/badge/WordPress-6.0%2B-blue)
![PHP](https://img.shields.io/badge/PHP-7.4%2B-purple)
![License](https://img.shields.io/badge/license-GPLv2%2B-green)
![Security](https://img.shields.io/badge/security-active-red)
![Status](https://img.shields.io/badge/status-stable-brightgreen)

# 🛡️ Tegatai Secure (Enterprise WordPress Security)

**Tegatai Secure** is a high-performance, enterprise-grade security suite for WordPress. Unlike traditional security plugins that process everything at the PHP level, Tegatai integrates directly with your server (**Nginx, Apache, or LiteSpeed**) to block malicious traffic, bots, and brute-force attacks *before* WordPress is even loaded.

It features a zero-load architecture, 8 deep-scanning engines, and military-grade encryption for remote backups.

---

## 🚀 Key Advantages

* **Zero-Load Protection:** Malicious requests are dropped by the web server (via auto-generated `nginx.conf` or `.htaccess`), keeping PHP-FPM and CPU load near zero.
* **Intrusion Prevention System (IPS):** Automatically quarantines suspicious files in a secure vault before they can be executed.
* **Fully Internationalized:** 100% i18n ready and translatable.
* **No Bloat:** A clean, modern UI without ads or upsells.

---

## 🔥 Complete Feature List

### 🛡️ Web Application Firewall (WAF) & Network
* **Bad Bot Blocking:** Drops known malicious bots, scrapers, and automated attack tools (e.g., sqlmap, masscan).
* **AI & SEO Bot Blocker:** Stops AI scrapers (OpenAI, ChatGPT, Claude) and aggressive SEO crawlers (Ahrefs, Semrush).
* **Rate Limiting:** Prevents DDoS and brute-force attacks by limiting requests per minute.
* **404 Trap:** Automatically bans IP addresses that generate too many "404 Not Found" errors (usually vulnerability scanners).
* **GeoIP Filtering:** Restrict access to your entire site or just the login area using a Whitelist or Blacklist approach.
* **IP Prison:** Manage blacklisted/whitelisted IPs and manually unban users directly from the dashboard.

### ⚡ Server Rules Engine (Nginx / Apache)
* **Disable PHP in Uploads:** Prevents execution of malicious backdoors in your media folders.
* **Protect Sensitive Files:** Blocks web access to `.env`, `.sql`, `.bak`, `.log`, and `.git` files.
* **System File Protection:** Hides `wp-config.php`, `readme.html`, and `license.txt`.
* **XML-RPC & Dotfile Block:** Completely disables `xmlrpc.php` and access to hidden dotfiles.
* **Advanced Hotlink Protection:** Prevents bandwidth theft with customizable whitelist support.

### 🔐 Authentication & Login Guard
* **Two-Factor Authentication (2FA):** Enforce 2FA for administrators via Authenticator App (TOTP), Email codes, or both.
* **Login Limit:** Locks out IPs after multiple failed login attempts.
* **Magic Links:** Allows passwordless, secure login via email tokens.
* **Custom Login Slug & Hide /wp-admin/:** Obfuscates your login routes to thwart automated attacks.
* **Trusted Devices:** Notifies administrators via email if a login occurs from an unknown device.
* **Idle Logout:** Automatically disconnects inactive administrators after 60 minutes.

### 🛑 Anti-Spam & Content Protection
* **Cloudflare Turnstile:** Privacy-friendly CAPTCHA integration for logins and comments.
* **Invisible Honeypot & Bot Timer:** Catches automated spam submissions using hidden fields and minimum-fill-time validation.
* **Trash Mail Blocker:** Rejects disposable/temporary email addresses during registration.
* **Referrer Check & Link Limits:** Blocks unauthorized form submissions and comment link spam.

### 🔎 8-Engine Integrity & Malware Scanners
1.  **Malware / Backdoor Scanner:** Signature-based scanning for common malware patterns in plugins and themes.
2.  **File Integrity Monitor (FIM):** Creates a baseline and alerts you to changed, new, or deleted core/plugin files.
3.  **WordPress Core Integrity:** Compares your local `wp-admin` and `wp-includes` files against official WordPress.org checksums.
4.  **Stored-XSS DB Scanner:** Scans database tables (posts, comments, options) for injected HTML/JS payloads.
5.  **Dangerous Options Scanner:** Scans `wp_options` for malicious `eval()`, `base64`, or hidden iframes.
6.  **Suspicious Cron Monitor:** Analyzes WP scheduled tasks for hidden mailers or crypto miners.
7.  **Uploads Monitor:** Specifically hunts for hidden `.php`, `.cgi`, or `.pl` executables masquerading as media.
8.  **File Permissions Monitor:** Audits critical files (`wp-config.php`, `.htaccess`) for world-writable vulnerabilities.

### 💻 System Hardening & HTTP Headers
* **Enterprise Privilege Guard:** Prevents unauthorized users from upgrading their roles to Administrator.
* **Admin Honeypot:** Permanently bans anyone attempting to log in with the username "admin".
* **Security Headers Enforcer:** Automatically injects `X-Frame-Options`, `Content-Security-Policy`, `HSTS`, `X-XSS-Protection`, and more.
* **Hide WP Footprint:** Removes WP version numbers, disables user enumeration, and disables the integrated file editor.

### 👥 Session Security & Management
* **IP & Browser Guard:** Instantly kills user sessions if their IP address or User-Agent changes mid-session (Session Hijacking prevention).
* **Single Session Limit:** Restricts users to one active session at a time.
* **Remote Kill-Switch:** View all active sessions and remotely disconnect suspicious users.

### 💾 Encrypted Backups
* **Automated Scheduling:** Generate full database backups daily or weekly.
* **Secure Remote FTP:** Send backups automatically to an external FTP server. All credentials are encrypted in your database using AES-256-CBC.

### 🛠️ Extras & API
* **Temporary Admin Accounts:** Generate time-limited admin access (e.g., 24 hours) for support staff. Accounts self-destruct securely after expiration.
* **REST API Restriction:** Require authentication for all sensitive REST API endpoints.
* **Content Protection:** Disable right-click and text highlighting/copying.
* **Discord / Slack Webhooks:** Get real-time alerts for critical security events straight to your messenger.
* **Live Traffic & Timeline Logs:** Monitor every block, WAF hit, and system event in real-time.

---

## ⚙️ Installation & Setup

1.  Upload and activate **Tegatai Secure** in your WordPress dashboard.
2.  Navigate to **Tegatai Secure -> Server Rules**.
3.  Configure your desired protections (e.g., Block Dotfiles, Disable PHP in Uploads).
4.  Click **"Write rules to server config"**.

**For Apache / LiteSpeed Users:**
Tegatai will automatically inject the required rules into your `.htaccess` file. You are fully protected immediately.

**For Nginx Users:**
Since Nginx does not support `.htaccess`, Tegatai generates a `tegatai-nginx.conf` file. You must include this file in your server block once:
```nginx
server {
    # Your existing config...
    
    # Include Tegatai Security Rules
    include /path/to/your/wordpress/tegatai-nginx.conf;
}

---

## Installation

1. Upload the plugin folder to:

```
/wp-content/plugins/tegatai-secure
```

2. Activate the plugin in the WordPress admin panel.
3. Open **Tegatai Secure** and configure your protection modules.

## Requirements

- WordPress 6.0+
- PHP 7.4+

## Contributing

See `CONTRIBUTING.md`.

## Security

If you discover a vulnerability, please report it privately.
- Contact: `security@your-domain.example`

## License

GPL v2 or later. See `LICENSE`.

## Changelog

See `CHANGELOG.md` (current: 1.0.0).
