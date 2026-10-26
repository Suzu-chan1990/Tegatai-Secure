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
            add_action('wp_footer', [$this, 'inject_protection_scripts'], 100);
        }

        // --- TEGATAI: Temporäre Support-Zugänge ---
        add_action('admin_post_tegatai_create_temp_admin', [$this, 'create_temp_admin']);
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

    public function inject_protection_scripts() {
        if (current_user_can('manage_options')) return;
        $ops = tegatai_get_setting('tegatai_options');
        
        echo "<script type='text/javascript'>\ndocument.addEventListener('DOMContentLoaded', function() {\n";
        
        if (!empty($ops['enable_rightclick_disable'])) {
            echo "  document.addEventListener('contextmenu', function(e) { e.preventDefault(); }, false);\n";
        }

        if (!empty($ops['enable_copy_protection'])) {
            echo "  document.addEventListener('copy', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('cut', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('dragstart', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('selectstart', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('keydown', function(e) {\n";
            echo "      if (e.ctrlKey || e.metaKey) {\n";
            echo "          var k = (e.key || '').toLowerCase();\n";
            echo "          if(k === 'c' || k === 'x' || k === 'u' || k === 's' || k === 'p') { e.preventDefault(); }\n";
            echo "      }\n";
            echo "  });\n";
        }
        echo "});\n</script>\n";

        if (!empty($ops['enable_copy_protection'])) {
            // Form fields stay selectable and images stay clickable (links, galleries, lightboxes).
            echo "<style>body, html, div, p, span, a, li, td, h1, h2, h3, h4, h5, h6 { -webkit-user-select: none !important; user-select: none !important; } input, textarea, [contenteditable] { -webkit-user-select: text !important; user-select: text !important; } img { -webkit-user-drag: none !important; }</style>\n";
        }
    }

    public function create_temp_admin() {
        if (!current_user_can('manage_options')) {
            wp_die('Access Denied');
        }
        
        check_admin_referer('teg_temp_admin_nonce');

        $email = sanitize_email($_POST['temp_email'] ?? '');
        $hours = intval($_POST['temp_hours'] ?? 0);

        if (!is_email($email) || $hours < 1) {
            wp_die(esc_html__('Invalid inputs.', 'tegatai-secure'));
        }

        $username = 'support_' . wp_generate_password(6, false);
        $password = wp_generate_password(24, true, true);

        $user_id = wp_create_user($username, $password, $email);

        if (is_wp_error($user_id)) {
            wp_die($user_id->get_error_message());
        }

        $user = new WP_User($user_id);
        $user->set_role('administrator');

        // Ablaufzeitpunkt in der Datenbank abspeichern
        $expiry_timestamp = time() + ($hours * 3600);
        update_user_meta($user_id, 'teg_temp_admin_expiry', $expiry_timestamp);
        update_user_meta($user_id, 'teg_temp_admin_creator', get_current_user_id());

        // Sicheren Magic-Link generieren (für passwortlosen Login)
        $token = bin2hex(random_bytes(32));
        $hash = hash('sha256', $token);
        
        // Transient speichern
        set_transient('teg_magic_' . $hash, $user_id, $hours * 3600); 
        $link = add_query_arg(['teg_magic_login' => 1, 'token' => $token], site_url());

        // E-Mail Formatierung & Versand
        $blog_name = get_bloginfo('name');
        $subject = sprintf(esc_html__('Temporary Admin Access: %s', 'tegatai-secure'), $blog_name);
        $message = sprintf(esc_html__("Hello,\n\nA temporary admin access has been created for you.\nThis access is valid for %d hour(s).\n\nClick here to log in securely:\n%s\n\nAfter the time expires, this account will be automatically and completely deleted.", 'tegatai-secure'), $hours, $link);
        
        $domain = parse_url(home_url(), PHP_URL_HOST);
        if (!$domain) {
            $domain = 'localhost';
        }
        if (substr($domain, 0, 4) == 'www.') {
            $domain = substr($domain, 4);
        }
        
        $from_email = 'wordpress@' . $domain; 
        $headers = ["From: \"$blog_name Security\" <$from_email>", "Content-Type: text/plain; charset=UTF-8"];
        
        wp_mail($email, $subject, $message, $headers);

        if (class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('AUDIT', "Temporärer Admin erstellt: $email ($hours Stunden)");
        }

        // BEST PRACTICE: Open Redirect Schutz
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=extras&msg=temp_created'));
        exit;
    }

    public function cleanup_temp_admins() {
        // Suche alle User, die ein festgelegtes Ablaufdatum besitzen
        $args = [
            'meta_key' => 'teg_temp_admin_expiry',
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
        $creator = intval(get_user_meta($user_id, 'teg_temp_admin_creator', true));
        if ($creator && $creator !== $user_id && user_can($creator, 'manage_options') && !get_user_meta($creator, 'teg_temp_admin_expiry', true)) {
            return $creator;
        }
        $admins = get_users(['role' => 'administrator', 'exclude' => [$user_id], 'fields' => 'ID', 'orderby' => 'ID']);
        foreach ($admins as $admin_id) {
            if (!get_user_meta($admin_id, 'teg_temp_admin_expiry', true)) return intval($admin_id);
        }
        return null;
    }

    private function is_expired_temp_admin($user_id) {
        $expiry = get_user_meta($user_id, 'teg_temp_admin_expiry', true);
        return $expiry && time() > intval($expiry);
    }

    // Login with an expired temp admin account is refused even before the daily cleanup ran.
    public function reject_expired_temp_admin($user) {
        if ($user instanceof WP_User && $this->is_expired_temp_admin($user->ID)) {
            return new WP_Error('teg_temp_expired', esc_html__('This temporary access has expired.', 'tegatai-secure'));
        }
        return $user;
    }

    // Existing sessions (cookies, magic-link logins) of an expired temp admin are no longer accepted.
    public function reject_expired_temp_admin_session($user_id) {
        if ($user_id && $this->is_expired_temp_admin($user_id)) return false;
        return $user_id;
    }

}
