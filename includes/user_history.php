<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_UserHistory {
    public function __construct() {
        add_action('wp_login', [$this, 'log_login'], 10, 2);
        add_filter('auth_cookie_expiration', [$this, 'custom_cookie_expiration'], 99, 3);
        add_action('admin_post_tegatai_clear_history', [$this, 'clear_history']);
    }
    public function log_login($user_login, $user) {
        $history = get_option('tegatai_login_history', []);
        $entry = ['time' => current_time('mysql'), 'user' => $user_login, 'role' => reset($user->roles), 'ip' => $_SERVER['REMOTE_ADDR'], 'ua' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'];
        array_unshift($history, $entry); if (count($history) > 100) $history = array_slice($history, 0, 100);
        update_option('tegatai_login_history', $history, false);
    }
    public function custom_cookie_expiration($expiration, $user_id, $remember) {
        $ops = get_option('tegatai_options');
        if (!empty($ops['session_max_lifetime']) && intval($ops['session_max_lifetime']) > 0) return intval($ops['session_max_lifetime']) * 60;
        return $expiration;
    }
    public function clear_history() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_hist_nonce');
        update_option('tegatai_login_history', []);
        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=sessions&msg=hist_cleared')); exit;
    }
    public static function get_history() { return get_option('tegatai_login_history', []); }
}
