<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_HARDENING_REFINEMENT_V1 applied */
class Tegatai_Hardening {
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');
        add_action('set_user_role', [$this, 'check_privilege_escalation'], 10, 3);
        add_action('add_user_role', [$this, 'check_added_role'], 10, 2);
        // WP_User::set_role() fires remove_user_role and add_user_role *before* set_user_role,
        // so the roles removed in this request are remembered to be able to restore them.
        add_action('remove_user_role', [$this, 'remember_removed_role'], 10, 2);
        
        if (!empty($ops['hide_wp_version'])) { 
            remove_action('wp_head', 'wp_generator'); 
            add_filter('the_generator', '__return_empty_string'); 
        }
        
        if (!empty($ops['disable_xmlrpc'])) { 
            add_filter('xmlrpc_enabled', '__return_false'); 
            add_filter('wp_headers', function($h) { unset($h['X-Pingback']); return $h; }); 
        }
        
        if (!empty($ops['disable_file_editor'])) { 
            if (!defined('DISALLOW_FILE_EDIT')) define('DISALLOW_FILE_EDIT', true); 
        }
        
        if (!empty($ops['block_user_enum'])) { 
            // Priority 1: must run before redirect_canonical (priority 10), which would otherwise
            // redirect ?author=N to /author/<username>/ and leak the login name.
            add_action('template_redirect', function() { 
                if (isset($_GET['author']) && !is_user_logged_in()) { 
                    if (class_exists('Tegatai_Logger')) {
                        Tegatai_Logger::log('ENUM', 'Blocked Enum'); 
                    }
                    wp_safe_redirect(home_url('/')); 
                    exit; 
                } 
            }, 1); 
        }
        
        if (!empty($ops['hide_login_errors'])) { 
            add_filter('login_errors', function(){ return __('Login invalid.', 'tegatai-secure'); }); 
        }
        
        // Honeypot Trap in robots.txt
        add_filter('robots_txt', function($output, $public) {
            return $output . "\nDisallow: /secret-backup-db/\n";
        }, 10, 2);

    }

    /**
     * Privilege Escalation Guard
     * Verhindert unbefugte Rechte-Upgrades zum Administrator.
     */
    public function check_privilege_escalation($user_id, $role, $old_roles) {
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['enable_role_guard']) || $role !== 'administrator') {
            return;
        }

        if (!$this->is_promotion_authorized()) {
            if (class_exists('Tegatai_Logger')) {
                Tegatai_Logger::log('SEC-WARN', "Blockierter Rechte-Upgrade-Versuch für User ID: $user_id auf $role");
            }

            // set_user_role fires after the role was saved: restore the previous roles before aborting.
            $user = new WP_User($user_id);
            $user->set_role('');
            foreach ((array)$old_roles as $old_role) {
                if ($old_role !== 'administrator') $user->add_role($old_role);
            }
            
            // Sofortiger Abbruch (inkl. 403 Header)
            wp_die(
                esc_html__('Unauthorized privilege escalation attempt detected and blocked.', 'tegatai-secure'), 
                esc_html__('Security Alert', 'tegatai-secure'), 
                ['response' => 403]
            );
        }
    }

    /**
     * Same guard for WP_User::add_role('administrator'), which does not fire set_user_role.
     */
    private $removed_roles = [];

    public function remember_removed_role($user_id, $role) {
        $this->removed_roles[(int)$user_id][] = $role;
    }

    public function check_added_role($user_id, $role) {
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['enable_role_guard']) || $role !== 'administrator' || $this->is_promotion_authorized()) {
            return;
        }
        if (class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('SEC-WARN', "Blockierter Rechte-Upgrade-Versuch für User ID: $user_id auf $role");
        }
        $user = new WP_User($user_id);
        $user->remove_role('administrator');
        foreach (array_unique($this->removed_roles[(int)$user_id] ?? []) as $old_role) {
            if ($old_role !== 'administrator') $user->add_role($old_role);
        }
        wp_die(
            esc_html__('Unauthorized privilege escalation attempt detected and blocked.', 'tegatai-secure'), 
            esc_html__('Security Alert', 'tegatai-secure'), 
            ['response' => 403]
        );
    }

    // Promotions by a user allowed to manage roles (any context incl. REST) or via WP-CLI are legitimate.
    private function is_promotion_authorized() {
        if (defined('WP_CLI') && WP_CLI) return true;
        return current_user_can('promote_users');
    }
}
