# Telemetry & Live Terminal

Tegatai centralizes all security events (WAF drops, Spam, Logins, Hive syncs) into a unified logging engine.

## Unified IP Handling
The entire suite relies on a proxy-aware method (`Tegatai_Logger::get_ip()`) to resolve the true client IP behind Cloudflare, Load Balancers, or Reverse Proxies, ensuring accurate telemetry.

## The Live Terminal
A Froxlor-styled, native dashboard interface that streams database events in real-time.
* **DDoS Protection:** The terminal's AJAX polling endpoint is protected by a strict 2-second rate limit using the Unified Cache to prevent database spamming if browser tabs are left open.
* **UX Features:** Includes keyboard shortcuts for manual refresh (R), console clearance (C), and a Pause/Resume toggle (P) for comfortable log analysis.

## Automated Pruning
To maintain optimal database performance, Tegatai hooks into the `tegatai_malware_cron` (running every 6 hours) to execute a garbage collection routine. This automatically purges timeline events and logs older than 30 days.
