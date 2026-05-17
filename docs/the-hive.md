# The Hive (P2P Threat Intelligence)

The Hive allows multiple WordPress installations to share threat intelligence and synchronize IP bans in real-time.

## Architecture & Cryptography
The Hive is a decentralized Peer-to-Peer (P2P) network. For full synchronization, **every node must list every other node** in its configuration.
* **Zero-Trust Payloads:** All broadcasts are signed using `HMAC-SHA256`. The shared secret should ideally be stored in `wp-config.php` (`TEGATAI_HIVE_SECRET`).
* **Anti-Replay Protection:** Every payload includes a unique `req_id` and a UNIX `timestamp`. Nodes reject requests older than 60 seconds (time drift) or duplicate IDs.
* **Immunity:** The network is completely immune to loopback bans. Localhost and the server's own IP are hardcoded to bypass bans.

## Background Queue
If a peer node is unreachable during a broadcast, the payload is placed into a local Retry-Queue. The `tegatai_hive_retry_cron` processes this queue, actively regenerating timestamps and signatures before attempting redelivery. Payloads are discarded after 3 failed attempts or 24 hours (Garbage Collection).
