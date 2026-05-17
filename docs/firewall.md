# Firewall (WAF) & Server Rules

Tegatai's Firewall operates at the earliest possible lifecycle stage to drop malicious traffic before it consumes expensive PHP/Database resources.

## Key Features
* **Bad Bot & AI Scraper Blocking:** Automatically drops requests from known aggressive crawlers, ChatGPT bots, and SEO scrapers.
* **GeoIP Protection:** Restrict access to the entire site or just the login portal based on ISO Alpha-2 country codes (Whitelist or Blacklist mode).
* **HTTP Security Headers:** Automatically injects modern security headers (`X-Frame-Options`, `Content-Security-Policy`, etc.). The engine actively probes for existing server headers to prevent duplicate header conflicts.
* **404 Trap & Rate Limiting:** Identifies vulnerability scanners by tracking excessive 404 errors and enforces strict request limits.
* **Custom Regex Rules:** Allows administrators to define custom blocking patterns (safeguarded against ReDoS via error-suppressed matching).
