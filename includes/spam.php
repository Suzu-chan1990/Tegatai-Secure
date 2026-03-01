<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
class Tegatai_Spam {
    private $trash_domains = ['yopmail.com', 'mailinator.com', 'guerrillamail.com', 'sharklasers.com', 'trashmail.com', '10minutemail.com', 'temp-mail.org', 'throwawaymail.com'];
    public function __construct() {
        $ops = get_option('tegatai_options');
        if (!empty($ops['enable_honeypot'])) { add_action('comment_form_default_fields', [$this, 'add_honeypot_field']); add_filter('preprocess_comment', [$this, 'check_honeypot']); }
        if (!empty($ops['enable_bot_timer'])) { add_action('comment_form_default_fields', [$this, 'add_timestamp_field']); add_filter('preprocess_comment', [$this, 'check_timestamp']); }
        if (!empty($ops['spam_max_links']) && intval($ops['spam_max_links']) > 0) add_filter('preprocess_comment', [$this, 'check_link_limit']);
        if (!empty($ops['spam_block_trashmail'])) { add_filter('preprocess_comment', [$this, 'check_email_domain']); add_filter('registration_errors', [$this, 'check_registration_email'], 10, 3); }
        if (!empty($ops['spam_check_referrer'])) add_filter('preprocess_comment', [$this, 'check_referrer']);
        
        // TURNSTILE
        if (!empty($ops['enable_turnstile'])) {
            add_action('wp_enqueue_scripts', [$this, 'turnstile_script']);
            add_action('comment_form_after_fields', [$this, 'turnstile_field']);
            add_action('comment_form_logged_in_after', [$this, 'turnstile_field']);
            add_filter('preprocess_comment', [$this, 'turnstile_verify_comment']);
        }
    }

    // --- TURNSTILE LOGIC ---
    public function turnstile_script() { if (is_single() || is_page()) wp_enqueue_script('cf-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, true); }
    public function turnstile_field() { $ops = get_option('tegatai_options'); if(!empty($ops['turnstile_site_key'])) echo '<div class="cf-turnstile" data-sitekey="'.esc_attr($ops['turnstile_site_key']).'" style="margin-bottom:15px;"></div>'; }
    public function turnstile_verify_comment($commentdata) {
        if (current_user_can('moderate_comments')) return $commentdata;
        $ops = get_option('tegatai_options');
        if (empty($ops['turnstile_secret_key'])) return $commentdata;
        $response = $_POST['cf-turnstile-response'] ?? '';
        $verify = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', ['body' => ['secret' => $ops['turnstile_secret_key'], 'response' => $response]]);
        if (!is_wp_error($verify)) {
            $body = json_decode(wp_remote_retrieve_body($verify), true);
            if (!empty($body['success'])) return $commentdata;
        }
        Tegatai_Logger::log('SPAM-BOT', 'Turnstile failed (Comment)');
        wp_die('Captcha Überprüfung fehlgeschlagen. Bitte lade die Seite neu.', 'Spam', ['response'=>403]);
    }
    public function check_email_domain($d) { if (current_user_can('moderate_comments')) return $d; if ($this->is_trash_mail($d['comment_author_email'])) wp_die('Disposable email not allowed.', 'Spam', ['response'=>403]); return $d; }
    public function check_registration_email($e, $u, $em) { if ($this->is_trash_mail($em)) $e->add('invalid_email', 'Disposable email not allowed.'); return $e; }
    private function is_trash_mail($e) { $p=explode('@',$e); return count($p)===2 && in_array($p[1], $this->trash_domains); }
    public function check_referrer($d) { if (current_user_can('moderate_comments')) return $d; $r=$_SERVER['HTTP_REFERER']??''; if(empty($r)||strpos($r,home_url())===false) wp_die('Invalid Referrer.', 'Spam', ['response'=>403]); return $d; }
    public function add_honeypot_field($f) { $f['teg_hp'] = '<p style="display:none;"><label>Leave empty:</label><input type="text" name="teg_hp_check" value="" /></p>'; return $f; }
    public function check_honeypot($d) { if (current_user_can('moderate_comments')) return $d; if (!empty($_POST['teg_hp_check'])) { Tegatai_Logger::log('SPAM', "Honeypot"); wp_die('Spam detected.', 'Spam', ['response'=>403]); } return $d; }
    public function add_timestamp_field($f) { $ts=time(); $h=wp_hash($ts.'teg_salt'); $f['teg_ts']='<input type="hidden" name="teg_ts_val" value="'.$ts.'"/><input type="hidden" name="teg_ts_hash" value="'.$h.'"/>'; return $f; }
    public function check_timestamp($d) {
        if (current_user_can('moderate_comments')) return $d;
        $ts = $_POST['teg_ts_val'] ?? 0;
        $h  = $_POST['teg_ts_hash'] ?? '';
        if (empty($ts) || empty($h) || wp_hash($ts.'teg_salt') !== $h) {
            Tegatai_Logger::log('SPAM', 'Bot Timer missing/invalid');
            wp_die('Spam detected.', 'Spam', ['response'=>403]);
        }
        if ((time() - $ts) < 3) {
            Tegatai_Logger::log('SPAM', 'Bot Timer');
            wp_die('Too fast.', 'Spam', ['response'=>403]);
        }
        return $d;
    }
    public function check_link_limit($d) {
        if (current_user_can('moderate_comments')) return $d;
        $ops = get_option('tegatai_options');
        $m = intval($ops['spam_max_links'] ?? 0);
        if ($m > 0 && preg_match_all('/(http|https|ftp):\/\//i', $d['comment_content'], $x) > $m) {
            Tegatai_Logger::log('SPAM', 'Link Limit');
            wp_die('Too many links.', 'Spam', ['response'=>403]);
        }
        return $d;
    }
}
