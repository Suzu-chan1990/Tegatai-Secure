<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_HEADERS_CONFLICT_FIX_PLUS_PROBE_V3 applied */
if (!function_exists('tegatai_header_present')) {
    function tegatai_header_present($name) {
        $name = trim((string)$name);
        if ($name === '') return false;
        foreach (headers_list() as $h) {
            // headers_list() returns 'Name: value'
            if (stripos($h, $name . ':') === 0) return true;
        }
        return false;
    }
}

/**
 * HTTP security headers.
 *
 * The headers are sent in two ways:
 *  - by PHP (send_headers, admin, login) for every page WordPress itself delivers;
 *  - as server rules (nginx file / .htaccess block of Tegatai_Server), so they also reach
 *    responses without PHP: pages from a page cache (Kyasshu, WP Rocket, WP Super Cache ...),
 *    static files and error pages.
 * Where both apply, the server rules replace the PHP copy (nginx: fastcgi_hide_header,
 * Apache: "Header set"), so every header is sent once.
 */
class Tegatai_Headers {
    public function __construct() { 
        add_action('send_headers', [$this, 'set_headers']); 
        // send_headers only runs for the front end; admin and login screens are covered here
        add_action('admin_init', [$this, 'set_headers']);
        add_action('login_init', [$this, 'set_headers']);
    }

    /**
     * Enabled headers as [name => value]. HSTS is only listed with $with_hsts, because it may
     * only be sent over HTTPS (the server rules add their own HTTPS condition).
     */
    public static function enabled($ops = null, $with_hsts = true) {
        if ($ops === null) $ops = tegatai_get_setting('tegatai_options');
        if (!is_array($ops)) $ops = [];
        $h = [];
        if (!empty($ops['header_xfo']))         $h['X-Frame-Options'] = 'SAMEORIGIN';
        if (!empty($ops['header_nosniff']))     $h['X-Content-Type-Options'] = 'nosniff';
        // The XSS filter is gone from all current browsers and "1; mode=block" could be abused in
        // old ones; "0" (filter off) is today's recommendation.
        if (!empty($ops['header_xss']))         $h['X-XSS-Protection'] = '0';
        if (!empty($ops['header_ref']))         $h['Referrer-Policy'] = 'strict-origin-when-cross-origin';
        if ($with_hsts && !empty($ops['header_hsts'])) {
            // includeSubDomains is opt-in: it breaks subdomains that are not reachable via HTTPS.
            $h['Strict-Transport-Security'] = 'max-age=31536000' . (!empty($ops['header_hsts_subdomains']) ? '; includeSubDomains' : '');
        }
        // "interest-cohort" (FLoC) is gone from all browsers; listing it only causes console warnings.
        if (!empty($ops['header_permissions'])) $h['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()';
        // Permissive baseline (HTTPS/same-origin only); it allows inline scripts/eval and is no XSS protection.
        // upgrade-insecure-requests: browsers switch http:// resources of the page to https:// before
        // the policy is checked (Firefox blocked http:// images that Chrome upgraded on its own)
        if (!empty($ops['header_csp']))         $h['Content-Security-Policy'] = "default-src 'self' https: wss: data: blob: 'unsafe-inline' 'unsafe-eval'; upgrade-insecure-requests";
        // Windows of other sites lose their reference to this site; windows this site opens
        // (share dialogs, OAuth popups) keep working.
        if (!empty($ops['header_coop']))        $h['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups';
        // Only the same site (including its subdomains) may load files of this site in the browser.
        if (!empty($ops['header_corp']))        $h['Cross-Origin-Resource-Policy'] = 'same-site';
        return $h;
    }
    
    public function set_headers() {
        if (headers_sent()) return;
        $h = self::enabled(null, is_ssl());
        foreach ($h as $name => $value) {
            if (!tegatai_header_present($name)) header($name . ': ' . $value);
        }
    }
}
