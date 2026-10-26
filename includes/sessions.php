<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */
/* TEGATAI_SESSIONS_SAFE_REDIRECT_V1 applied */

class Tegatai_SessionManager {
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');
        if (!empty($ops['enable_single_session'])) {
            // set_logged_in_cookie passes the new session token; wp_get_session_token() only sees the old request cookie
            add_action('set_logged_in_cookie', [$this, 'destroy_other_sessions'], 10, 6);
        }
        add_action('admin_post_tegatai_kill_session', [$this, 'kill_session']);
    }

    public function destroy_other_sessions($logged_in_cookie, $expire, $expiration, $user_id, $scheme = 'logged_in', $token = '') {
        // Without the new token we cannot keep the current session, so leave everything alone
        if (empty($token) || empty($user_id)) return;
        WP_Session_Tokens::get_instance((int) $user_id)->destroy_others($token);
    }

    public function kill_session() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_session_nonce');
        
        $u = intval($_POST['user_id'] ?? 0);
        $v = isset($_POST['verifier']) && is_string($_POST['verifier']) ? sanitize_text_field(wp_unslash($_POST['verifier'])) : '';

        // The verifier is the sha256 key of the session_tokens meta; destroy() would hash it again
        if ($u && preg_match('/^[a-f0-9]{64}$/', $v)) {
            $sessions = get_user_meta($u, 'session_tokens', true);
            if (is_array($sessions) && isset($sessions[$v])) {
                unset($sessions[$v]);
                if ($sessions) update_user_meta($u, 'session_tokens', $sessions);
                else delete_user_meta($u, 'session_tokens');

                if (class_exists('Tegatai_Logger')) {
                    Tegatai_Logger::log('SESSION', "Admin killed session $u");
                }
            }
        }
        
        // BEST PRACTICE: Open Redirect Schutz
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=sessions&msg=killed')); 
        exit;
    }

    public static function get_all_sessions() {
        $us = get_users(['number'=>50,'meta_key'=>'session_tokens']); 
        $as = [];
        
        foreach($us as $u) {
            // Raw meta keeps the verifiers as keys (get_all() re-indexes them to 0..n)
            $ss = get_user_meta($u->ID, 'session_tokens', true);
            if (!is_array($ss)) continue;
            foreach($ss as $v => $s) {
                if (!is_array($s) || (int) ($s['expiration'] ?? 0) < time()) continue;
                $as[] = [
                    'user_id'  => $u->ID,
                    'username' => $u->user_login,
                    'role'     => implode(', ', $u->roles),
                    'verifier' => $v,
                    'ip'       => $s['ip'] ?? '?',
                    'ua'       => $s['ua'] ?? '?',
                    'login'    => $s['login'] ?? 0
                ];
            }
        }
        
        usort($as, function($a, $b) { return $b['login'] - $a['login']; }); 
        return $as;
    }
}
