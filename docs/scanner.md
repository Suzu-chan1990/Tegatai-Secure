# Scanners & Integrity Monitors

Tegatai features a comprehensive suite of scanners to detect modifications, injected backdoors, and database anomalies.

## 1. Malware / Backdoor Scanner
Uses a signature-based approach to detect common obfuscation patterns, eval-injections, and malicious payloads. Processes files in asynchronous batches to prevent PHP timeouts.

## 2. Core Integrity (with MD5 Validation)
Verifies `wp-admin` and `wp-includes` files against official WordPress.org checksums. 
**Heal Function:** When repairing a modified core file, the system downloads the original file via SVN, calculates its MD5 hash in memory, and cross-references it with the official API *before* writing it to disk.

## 3. File Integrity Monitor (FIM)
Tracks structural changes in `wp-content` (Plugins and Themes). The FIM calculates SHA-256 hashes and meticulously tracks the absolute filesystem paths (`abs`) of new, modified, or deleted files to prepare for future automated healing protocols.

## 4. Stored XSS Database Scanner
A read-only scanner that parses core database tables (posts, options, comments) for malicious HTML/JS patterns. Administrators can extend the detection engine by adding custom regex rules directly via the dashboard.
