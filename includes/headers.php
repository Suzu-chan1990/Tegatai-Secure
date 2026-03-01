<?php


/* TEGATAI_HEADERS_CONFLICT_FIX_PLUS_PROBE_V2 applied 2026-02-26 22:01:45 */
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
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_Headers {
    public function __construct() { add_action('send_headers', [$this, 'set_headers']); }
    public function set_headers() {
        if (headers_sent()) return;
        $ops = get_option('tegatai_options');
        if (!empty($ops['header_xfo'])) header('X-Frame-Options: SAMEORIGIN');
        if (!empty($ops['header_nosniff'])) header('X-Content-Type-Options: nosniff');
        if (!empty($ops['header_xss'])) header('X-XSS-Protection: 1; mode=block');
        if (!empty($ops['header_ref'])) header('Referrer-Policy: strict-origin-when-cross-origin');
        if (!empty($ops['header_hsts']) && is_ssl()) header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        if (!empty($ops['header_permissions'])) header('Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()');
        if (!empty($ops['header_csp'])) header("Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';");
    }
}
