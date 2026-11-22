<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- one-time cleanup of old meta keys

/**
 * Ends a login session when its IP address or browser changes.
 *
 * Uses the session data WordPress itself stores for every login (WP_Session_Tokens). WordPress
 * records 'ua'; Tegatai adds the client IP as resolved by Tegatai (trusted proxies such as
 * Cloudflare) through the core filter 'attach_session_information'. Tegatai never reads or
 * stores anything derived from the authentication cookie or the session token.
 */
class Tegatai_SessionGuard {
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');
        add_filter('attach_session_information', [$this, 'attach_ip'], 10, 2);

        if (!empty($ops['enable_ip_guard']) || !empty($ops['enable_browser_guard'])) {
            add_action('init', [$this, 'validate_session']);
        }
        // Older versions kept their own copy per session in user meta; it is no longer used.
        add_action('tegatai_daily_maintenance', [__CLASS__, 'cleanup_legacy_meta']);
    }

    // Stored by WordPress together with the session (user meta "session_tokens").
    public function attach_ip($session, $user_id) {
        $ip = Tegatai_Logger::get_ip();
        if (filter_var($ip, FILTER_VALIDATE_IP)) $session['tegatai_ip'] = $ip;
        return $session;
    }

    public function validate_session() {
        if (!is_user_logged_in()) return;

        $ops = tegatai_get_setting('tegatai_options');
        $uid = get_current_user_id();
        $token = wp_get_session_token();
        if (!$token) return;

        $session = WP_Session_Tokens::get_instance($uid)->get($token);
        if (!is_array($session)) return;

        // IP Guard: compare with the IP recorded at login
        if (!empty($ops['enable_ip_guard']) && !empty($session['tegatai_ip'])) {
            $ip = Tegatai_Logger::get_ip();
            if ($ip !== '' && $ip !== (string) $session['tegatai_ip']) {
                $this->kill('IP Change');
            }
        }

        // Browser Guard: compare with the user agent WordPress recorded at login
        if (!empty($ops['enable_browser_guard']) && isset($session['ua'])) {
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_text_field(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '';
            if ($ua !== sanitize_text_field((string) $session['ua'])) {
                $this->kill('Browser Change');
            }
        }
    }

    private function kill($r) {
        if (class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('SESSION', "Killed: $r");
        }

        wp_destroy_current_session();
        wp_logout();

        wp_safe_redirect(add_query_arg(['logged_out' => 'true', 'reason' => 'sec'], wp_login_url()));
        exit;
    }

    // Removes the per-session meta keys written by Tegatai 2.2.1 and older.
    public static function cleanup_legacy_meta() {
        global $wpdb;
        $wpdb->query($wpdb->prepare(
            "DELETE FROM {$wpdb->usermeta} WHERE meta_key LIKE %s OR meta_key LIKE %s",
            $wpdb->esc_like('tegatai_sess_ip_') . '%',
            $wpdb->esc_like('tegatai_sess_ua_') . '%'
        ));
    }
}
