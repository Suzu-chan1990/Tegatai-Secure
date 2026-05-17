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

class Tegatai_Headers {
    public function __construct() { 
        add_action('send_headers', [$this, 'set_headers']); 
    }
    
    public function set_headers() {
        if (headers_sent()) return;
        $ops = get_option('tegatai_options');
        
        if (!empty($ops['header_xfo']) && !tegatai_header_present('X-Frame-Options')) {
            header('X-Frame-Options: SAMEORIGIN');
        }
        
        if (!empty($ops['header_nosniff']) && !tegatai_header_present('X-Content-Type-Options')) {
            header('X-Content-Type-Options: nosniff');
        }
        
        if (!empty($ops['header_xss']) && !tegatai_header_present('X-XSS-Protection')) {
            header('X-XSS-Protection: 1; mode=block');
        }
        
        if (!empty($ops['header_ref']) && !tegatai_header_present('Referrer-Policy')) {
            header('Referrer-Policy: strict-origin-when-cross-origin');
        }
        
        if (!empty($ops['header_hsts']) && is_ssl() && !tegatai_header_present('Strict-Transport-Security')) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        
        if (!empty($ops['header_permissions']) && !tegatai_header_present('Permissions-Policy')) {
            header('Permissions-Policy: geolocation=(), camera=(), microphone=(), interest-cohort=()');
        }
        
        if (!empty($ops['header_csp']) && !tegatai_header_present('Content-Security-Policy')) {
            header("Content-Security-Policy: default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval';");
        }
    }
}
