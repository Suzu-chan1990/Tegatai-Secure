<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_SessionGuard {
    public function __construct() {
        $ops = get_option('tegatai_options');
        add_action('set_logged_in_cookie', [$this, 'save_session_data'], 10, 4);
        if (!empty($ops['enable_ip_guard']) || !empty($ops['enable_browser_guard'])) add_action('init', [$this, 'validate_session']);
    }
    public function save_session_data($logged_in_cookie, $expire, $expiration, $user_id) {
        $token = wp_get_session_token();
        if ($token) {
            update_user_meta($user_id, 'teg_sess_ip_' . md5($token), $_SERVER['REMOTE_ADDR']);
            update_user_meta($user_id, 'teg_sess_ua_' . md5($token), md5($_SERVER['HTTP_USER_AGENT']??''));
        }
    }
    public function validate_session() {
        if (!is_user_logged_in()) return; $ops = get_option('tegatai_options'); $uid = get_current_user_id();
        $token = wp_get_session_token();
        if (!$token) return;
        if (!empty($ops['enable_ip_guard'])) { $s = get_user_meta($uid, 'teg_sess_ip_' . md5($token), true); if ($s && $s !== $_SERVER['REMOTE_ADDR']) $this->kill('IP Change'); }
        if (!empty($ops['enable_browser_guard'])) { $s = get_user_meta($uid, 'teg_sess_ua_' . md5($token), true); if ($s && $s !== md5($_SERVER['HTTP_USER_AGENT']??'')) $this->kill('Browser Change'); }
    }
    private function kill($r) { Tegatai_Logger::log('SESSION', "Killed: $r"); wp_destroy_current_session(); wp_logout(); wp_redirect(wp_login_url().'?logged_out=true&reason=sec'); exit; }
}
