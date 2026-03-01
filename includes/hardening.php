<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_Hardening {
    public function __construct() {
        $ops = get_option('tegatai_options');
        add_action('set_user_role', [$this, 'check_privilege_escalation'], 10, 3);
        if (!empty($ops['hide_wp_version'])) { remove_action('wp_head', 'wp_generator'); add_filter('the_generator', '__return_empty_string'); }
        if (!empty($ops['disable_xmlrpc'])) { add_filter('xmlrpc_enabled', '__return_false'); add_filter('wp_headers', function($h) { unset($h['X-Pingback']); return $h; }); }
        if (!empty($ops['disable_file_editor'])) { if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true); }
        if (!empty($ops['block_user_enum'])) { add_action('template_redirect', function() { if (is_author() && isset($_GET['author'])) { Tegatai_Logger::log('ENUM', 'Blocked Enum'); wp_redirect(home_url()); exit; } }); }
        if (!empty($ops['hide_login_errors'])) { add_filter('login_errors', function(){ return 'Login invalid.'; }); }
        // Honeypot Trap in robots.txt
        add_filter('robots_txt', function($output, $public) {
            return $output . "\nDisallow: /secret-backup-db/\n";
        }, 10, 2);

    }

    /**
     * TEGATAI ENTERPRISE: Privilege Escalation Guard
     * Verhindert unbefugte Rechte-Upgrades zum Administrator.
     */
    public function check_privilege_escalation($user_id, $role, $old_roles) {
        $ops = get_option('tegatai_options');
        if (empty($ops['enable_role_guard']) || $role !== 'administrator') {
            return;
        }

        // Wenn die Aktion nicht durch einen eingeloggten Admin im Backend erfolgt
        if (!is_admin() || !current_user_can('manage_options')) {
            Tegatai_Logger::log('SEC-WARN', "Blockierter Rechte-Upgrade-Versuch für User ID: $user_id auf $role");
            
            // Sofortiger Abbruch und Sperrung des Ziel-Users zur Sicherheit
            wp_die('Unauthorized privilege escalation attempt detected and blocked.', 'Security Alert');
        }
    }

}
