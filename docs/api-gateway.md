# API Gateway

The API Guard protects custom integration endpoints, REST routes, and synchronization scripts from unauthorized access and DDoS attacks.

## Routing & Match Modes
Administrators can define protected URIs using three modes:
1. **Contains:** Matches if the URI contains the string.
2. **Exact:** Strict 1:1 string matching.
3. **Regex:** Advanced pattern matching. (Protected against ReDoS via `@preg_match`).

## Authentication Modes
* **Static Token:** Validates via the `X-Tegatai-Sync` header.
* **HMAC v2:** The client signs `METHOD|REQUEST_URI|timestamp|req_id|sha256(raw body)` with HMAC-SHA256 (headers `X-Tegatai-Timestamp`, `X-Tegatai-Req-Id`, `X-Tegatai-Signature`). Timestamps may drift ±60 s; every `req_id` is claimed atomically and accepted only once, so intercepted requests can neither be replayed nor reused with a different method or body.

## Rate Limiting & Allowlisting
The Gateway utilizes a high-speed, in-memory Leaky Bucket algorithm (falling back to Transients if APCu/Redis is unavailable). It restricts traffic to 10 requests per minute. Additionally, an IPv4/IPv6 CIDR Allowlist can completely drop traffic from unverified network ranges.
