=== Tegatai Secure ===
Contributors: tegatai
Tags: security, firewall, malware scanner, wordpress security, hardening, 2fa
Requires at least: 6.0
Tested up to: 6.5
Requires PHP: 7.4
Stable tag: 1.0.1
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

= 1.0.1 =

🐛 Bug Fixes & Backend Polish

    Enterprise Features Activation: Added missing feature toggles (Admin Honeypot, Privilege Escalation Guard, Turnstile CAPTCHA, and Auto-Quarantine) to the strict internal whitelist. These enterprise protections can now be activated and saved without triggering AJAX validation errors.

    PHP Fatal Error Resolution: Fixed a critical typo in the form handler where a missing variable identifier ($_POST) caused the settings panel to crash on strict PHP environments.

    Syntax & Parsing Stability: Cleaned up residual syntax parsing errors in the admin dashboard controller to ensure flawless compatibility with PHP 8.1+.

    GeoIP UI Correction: Resolved a character encoding bug (mojibake) within the GeoIP settings tab that displayed corrupted text instead of the intended clean UI elements.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
