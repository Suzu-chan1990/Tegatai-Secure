# Login & Authentication Security

Authentication endpoints are the most targeted surfaces in WordPress. Tegatai hardens these routes through multi-factor and behavioral checks.

## Protections
* **Two-Factor Authentication (2FA):** Adaptive 2FA supporting both Authenticator Apps (TOTP) and Email codes.
* **Trusted Devices:** Fingerprints recognized administrator devices. Unrecognized logins trigger immediate email alerts.
* **Honeypot:** Injects invisible fields into the login form. Automated bots interacting with these fields are instantly blocked and logged centrally (`AUTH-BAN`).
* **Session Guard:** Monitors active sessions for IP or User-Agent changes. If a hijacked session is detected, it is killed instantly with a secure `wp_safe_redirect()`.
* **Temporary Sudo/Admin Access:** Generate time-limited, magic-link access for support teams. Accounts are automatically purged upon expiry.
