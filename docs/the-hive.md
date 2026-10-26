# The Hive (P2P Threat Intelligence)

The Hive allows multiple WordPress installations to share threat intelligence and synchronize IP bans in real-time.

## Architecture & Cryptography
The Hive is a decentralized Peer-to-Peer (P2P) network. For full synchronization, **every node must list every other node** in its configuration.
* **Signed Payloads:** All broadcasts are signed using `HMAC-SHA256` over the raw body, which contains the sender (`node`), timestamp and request ID. The sender is also sent as `X-Tegatai-Node` header.
* **Per-Peer Secrets:** Peers are configured one per line as `URL` or `URL | pair-secret`. A pair secret is shared only between two nodes (same value on both sides), so a compromised node cannot impersonate others and can be revoked on its own. Peers without a pair secret use the network-wide shared secret (`TEGATAI_HIVE_SECRET` in `wp-config.php` or the dashboard).
* **Strict Peer Mode:** When enabled, only listed peers that identify themselves are accepted. Leave it off until every node runs the current version.
* **Anti-Replay Protection:** Nodes reject requests with more than 60 seconds time drift; every `req_id` is claimed atomically and accepted only once.
* **Expiring Bans:** Received bans are stored separately from the manual blacklist and expire after the configured duration (default 24 h, max. 30 days). Each peer can submit at most 100 bans per hour (filter `tegatai_hive_max_bans_per_peer_hour`).
* **Never-Ban Protection:** Loopback, private/reserved ranges, the server's own IP, the firewall whitelists, the Hive allowlist and IPs administrators logged in from (last 30 days) are never banned or broadcast. Add your own IPs and verified crawler ranges (e.g. Googlebot) to the Hive allowlist.

## What Gets Broadcast
Bans are broadcast when the firewall or login protection catches clear attacks: honeypot URLs, instant-ban 404 probes (`.env`, `phpmyadmin`, …), 404 scans (20 hits), the admin-username honeypot and the login form honeypot. Each IP is broadcast at most once per hour. Other code can trigger a broadcast with `do_action('tegatai_ip_banned', $ip, $reason, $level)`.

## Background Queue
Broadcasts never block the visitor's request: payloads are queued and sent by WP-Cron (`tegatai_hive_flush`, retries via `tegatai_hive_retry_cron`) with fresh timestamps and signatures. Payloads are discarded after 4 failed attempts or 24 hours.
