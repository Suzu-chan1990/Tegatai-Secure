<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */

if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_SessionManager {
    public function __construct() {
        $ops = get_option('tegatai_options');
        if (!empty($ops['enable_single_session'])) add_action('wp_login', [$this, 'destroy_other_sessions'], 10, 2);
        add_action('admin_post_tegatai_kill_session', [$this, 'kill_session']);
    }
    public function destroy_other_sessions($l, $u) {
        $mgr = WP_Session_Tokens::get_instance($u->ID);
        $token = function_exists('wp_get_session_token') ? wp_get_session_token() : '';
        if (!empty($token) && method_exists($mgr, 'destroy_others')) {
            $mgr->destroy_others($token);
        } else {
            $mgr->destroy_all();
        }
    }
    public function kill_session() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_session_nonce');
        $u=intval($_POST['user_id'] ?? 0); $v=sanitize_text_field($_POST['verifier'] ?? '');
        if ($u && $v) { WP_Session_Tokens::get_instance($u)->destroy($v); Tegatai_Logger::log('SESSION', "Admin killed session $u"); }
        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=sessions&msg=killed')); exit;
    }
    public static function get_all_sessions() {
        $us = get_users(['number'=>50,'meta_key'=>'session_tokens']); $as=[];
        foreach($us as $u) {
            $ss = WP_Session_Tokens::get_instance($u->ID)->get_all();
            foreach($ss as $v=>$s) $as[]=['user_id'=>$u->ID,'username'=>$u->user_login,'role'=>implode(', ',$u->roles),'verifier'=>$v,'ip'=>$s['ip']??'?','ua'=>$s['ua']??'?','login'=>$s['login']??0];
        }
        usort($as, function($a,$b){return $b['login']-$a['login'];}); return $as;
    }
}
