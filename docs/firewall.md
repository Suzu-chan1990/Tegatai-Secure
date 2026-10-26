# Firewall (WAF) & Server Rules

Tegatai's Firewall operates at the earliest possible lifecycle stage to drop malicious traffic before it consumes expensive PHP/Database resources.

## Key Features
* **Bad Bot & AI Scraper Blocking:** Automatically drops requests from known aggressive crawlers, ChatGPT bots, and SEO scrapers.
* **GeoIP Protection:** Restrict access to the entire site or just the login portal based on ISO Alpha-2 country codes (Whitelist or Blacklist mode).
* **HTTP Security Headers:** Automatically injects modern security headers (`X-Frame-Options`, `Content-Security-Policy`, etc.). The engine actively probes for existing server headers to prevent duplicate header conflicts.
* **404 Trap & Rate Limiting:** Identifies vulnerability scanners by tracking excessive 404 errors and enforces strict request limits.
* **Custom Regex Rules:** Allows administrators to define custom blocking patterns (safeguarded against ReDoS via error-suppressed matching).


## Reverse Proxies, CDNs & Client IP

Tegatai uses `REMOTE_ADDR` as the client IP. Proxy headers are only evaluated when the request comes from a trusted proxy, otherwise any visitor could fake their IP (e.g. `X-Forwarded-For: 127.0.0.1`).

* **Local reverse proxy** (nginx in front of Apache/PHP on the same host): trusted automatically; `X-Forwarded-For` is evaluated right to left.
* **Cloudflare, load balancers, external proxies:** add their IPs/ranges in `wp-config.php`:

```php
define('TEGATAI_TRUSTED_PROXIES', '173.245.48.0/20, 103.21.244.0/22, 10.0.0.0/8');
```

Only for these proxies are `CF-Connecting-IP` and `X-Real-IP` honored as well. Alternatively use the `tegatai_trusted_proxies` filter.
