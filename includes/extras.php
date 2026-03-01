<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */

if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Extras {
    
    public function __construct() {
        $ops = get_option('tegatai_options');

        // 1. REST API Guard
        if (!empty($ops['disable_rest_api'])) {
            add_filter('rest_authentication_errors', [$this, 'restrict_rest_api']);
        }

        // 2. Content Protection (Frontend JS/CSS)
        if (!empty($ops['enable_copy_protection']) || !empty($ops['enable_rightclick_disable'])) {
            add_action('wp_footer', [$this, 'inject_protection_scripts'], 100);
        }

        // --- TEGATAI PRO: Temporäre Support-Zugänge ---
        add_action('admin_post_tegatai_create_temp_admin', [$this, 'create_temp_admin']);
        add_action('admin_init', [$this, 'cleanup_temp_admins']);
    }

    public function restrict_rest_api($result) {
        if (!empty($result)) return $result;
        
        // TEGATAI_FIX: Blockiere nur sensible Endpunkte (User Enum), erlaube Gutenberg & Frontend-APIs
        $route = untrailingslashit($GLOBALS['wp']->query_vars['rest_route'] ?? '');
        if (empty($route) || strpos($route, '/wp/v2/users') !== false || strpos($route, '/wp/v2/settings') !== false) {
            if (!is_user_logged_in()) {
                return new WP_Error('rest_forbidden', 'Restricted Endpoint.', ['status' => 401]);
            }
        }
        return $result;
    }

    public function inject_protection_scripts() {
        if (current_user_can('manage_options')) return;
        $ops = get_option('tegatai_options');
        
        echo "<script type='text/javascript'>\ndocument.addEventListener('DOMContentLoaded', function() {\n";
        
        if (!empty($ops['enable_rightclick_disable'])) {
            echo "  document.addEventListener('contextmenu', function(e) { e.preventDefault(); }, false);\n";
        }

        if (!empty($ops['enable_copy_protection'])) {
            echo "  document.addEventListener('copy', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('cut', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('paste', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('dragstart', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('selectstart', function(e) { e.preventDefault(); }, false);\n";
            echo "  document.addEventListener('keydown', function(e) {\n";
            echo "      if (e.ctrlKey || e.metaKey) {\n";
            echo "          var k = e.key.toLowerCase();\n";
            echo "          if(k === 'c' || k === 'x' || k === 'u' || k === 's' || k === 'p') { e.preventDefault(); }\n";
            echo "      }\n";
            echo "  });\n";
        }
        echo "});\n</script>\n";

        if (!empty($ops['enable_copy_protection'])) {
            echo "<style>body, html, div, p, span, a, li, td, h1, h2, h3, h4, h5, h6 { -webkit-user-select: none !important; user-select: none !important; } img { -webkit-user-drag: none !important; pointer-events: none !important; }</style>\n";
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

        Tegatai_Logger::log('AUDIT', "Temporärer Admin erstellt: $email ($hours Stunden)");

        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=extras&msg=temp_created'));
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
            $expiry = get_user_meta($user->ID, 'teg_temp_admin_expiry', true);
            
            // Lösche den Nutzer, wenn die Zeit abgelaufen ist
            if ($expiry && time() > intval($expiry)) {
                require_once(ABSPATH . 'wp-admin/includes/user.php');
                wp_delete_user($user->ID);
                Tegatai_Logger::log('AUDIT', "Temporärer Admin automatisch gelöscht: " . $user->user_email);
            }
        }
    }

}
