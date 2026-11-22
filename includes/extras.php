<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */
/* TEGATAI_EXTRAS_SAFE_REDIRECT_V1 applied */

if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Extras {
    
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');

        // 1. REST API Guard
        if (!empty($ops['disable_rest_api'])) {
            add_filter('rest_authentication_errors', [$this, 'restrict_rest_api']);
        }

        // 2. Content Protection (Frontend JS/CSS)
        if (!empty($ops['enable_copy_protection']) || !empty($ops['enable_rightclick_disable'])) {
            add_action('wp_enqueue_scripts', [$this, 'inject_protection_scripts'], 100);
        }

        // Temporary support accounts are no longer created by Tegatai (no user creation, no login links).
        // Accounts that older versions created keep expiring and are removed by the daily cleanup.
        add_action('tegatai_daily_maintenance', [$this, 'cleanup_temp_admins']);
        add_filter('authenticate', [$this, 'reject_expired_temp_admin'], 99);
        add_filter('determine_current_user', [$this, 'reject_expired_temp_admin_session'], 99);
    }

    public function restrict_rest_api($result) {
        if (!empty($result)) return $result;
        
        // TEGATAI_FIX: Blockiere nur sensible Endpunkte (User Enum), erlaube Gutenberg & Frontend-APIs
        // REST routes are matched case-insensitively by WP, so compare in lower case.
        $route = strtolower(untrailingslashit($GLOBALS['wp']->query_vars['rest_route'] ?? ''));
        if (empty($route) || strpos($route, '/wp/v2/users') !== false || strpos($route, '/wp/v2/settings') !== false) {
            if (!is_user_logged_in()) {
                return new WP_Error('rest_forbidden', 'Restricted Endpoint.', ['status' => 401]);
            }
        }
        return $result;
    }

    // Enqueued through the WordPress script/style API (inline, no extra request), frontend only.
    public function inject_protection_scripts() {
        if (current_user_can('manage_options')) return;
        $ops = tegatai_get_setting('tegatai_options');

        $js = "document.addEventListener('DOMContentLoaded', function() {\n";
        if (!empty($ops['enable_rightclick_disable'])) {
            $js .= "  document.addEventListener('contextmenu', function(e) { e.preventDefault(); }, false);\n";
        }
        if (!empty($ops['enable_copy_protection'])) {
            $js .= "  document.addEventListener('copy', function(e) { e.preventDefault(); }, false);\n";
            $js .= "  document.addEventListener('cut', function(e) { e.preventDefault(); }, false);\n";
            $js .= "  document.addEventListener('dragstart', function(e) { e.preventDefault(); }, false);\n";
            $js .= "  document.addEventListener('selectstart', function(e) { e.preventDefault(); }, false);\n";
            $js .= "  document.addEventListener('keydown', function(e) {\n";
            $js .= "      if (e.ctrlKey || e.metaKey) {\n";
            $js .= "          var k = (e.key || '').toLowerCase();\n";
            $js .= "          if(k === 'c' || k === 'x' || k === 'u' || k === 's' || k === 'p') { e.preventDefault(); }\n";
            $js .= "      }\n";
            $js .= "  });\n";
        }
        $js .= "});\n";

        wp_register_script('tegatai-content-protection', false, [], TEGATAI_VERSION, ['in_footer' => true]);
        wp_enqueue_script('tegatai-content-protection');
        wp_add_inline_script('tegatai-content-protection', $js);

        if (!empty($ops['enable_copy_protection'])) {
            // Form fields stay selectable and images stay clickable (links, galleries, lightboxes).
            wp_register_style('tegatai-content-protection', false, [], TEGATAI_VERSION);
            wp_enqueue_style('tegatai-content-protection');
            wp_add_inline_style('tegatai-content-protection', 'body, html, div, p, span, a, li, td, h1, h2, h3, h4, h5, h6 { -webkit-user-select: none !important; user-select: none !important; } input, textarea, [contenteditable] { -webkit-user-select: text !important; user-select: text !important; } img { -webkit-user-drag: none !important; }');
        }
    }

    public function cleanup_temp_admins() {
        // Suche alle User, die ein festgelegtes Ablaufdatum besitzen
        $args = [
            'meta_key' => 'tegatai_temp_admin_expiry', // phpcs:ignore WordPress.DB.SlowDBQuery.slow_db_query_meta_key -- daily cron job, only finds the few temporary admins
            'meta_compare' => 'EXISTS'
        ];
        
        $temp_users = get_users($args);

        foreach ($temp_users as $user) {
            if (!$this->is_expired_temp_admin($user->ID)) continue;

            require_once(ABSPATH . 'wp-admin/includes/user.php');
            wp_delete_user($user->ID, $this->get_reassign_target($user->ID));
            
            if (class_exists('Tegatai_Logger')) {
                Tegatai_Logger::log('AUDIT', "Temporärer Admin automatisch gelöscht: " . $user->user_email);
            }
        }
    }

    // Content of a deleted temp admin goes to the admin who created it, or to another regular admin.
    private function get_reassign_target($user_id) {
        $creator = intval(get_user_meta($user_id, 'tegatai_temp_admin_creator', true));
        if ($creator && $creator !== $user_id && user_can($creator, 'manage_options') && !get_user_meta($creator, 'tegatai_temp_admin_expiry', true)) {
            return $creator;
        }
        $admins = get_users(['role' => 'administrator', 'exclude' => [$user_id], 'fields' => 'ID', 'orderby' => 'ID']);
        foreach ($admins as $admin_id) {
            if (!get_user_meta($admin_id, 'tegatai_temp_admin_expiry', true)) return intval($admin_id);
        }
        return null;
    }

    private function is_expired_temp_admin($user_id) {
        $expiry = get_user_meta($user_id, 'tegatai_temp_admin_expiry', true);
        return $expiry && time() > intval($expiry);
    }

    // Login with an expired temp admin account is refused even before the daily cleanup ran.
    public function reject_expired_temp_admin($user) {
        if ($user instanceof WP_User && $this->is_expired_temp_admin($user->ID)) {
            return new WP_Error('tegatai_temp_expired', esc_html__('This temporary access has expired.', 'tegatai-secure'));
        }
        return $user;
    }

    // Existing sessions of an expired temp admin are no longer accepted.
    public function reject_expired_temp_admin_session($user_id) {
        if ($user_id && $this->is_expired_temp_admin($user_id)) return false;
        return $user_id;
    }

}
