<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_TWOFA_UNIFICATION_V1 applied */
/* TEGATAI_TWOFA_UX_REFINEMENT_V1 applied */
class Tegatai_TwoFactor {
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');
        if (!empty($ops['enable_2fa'])) {
            add_filter('authenticate', [$this, 'check_login'], 100, 3);
            add_action('login_form_tegatai_2fa', [$this, 'render_form']);
            add_action('admin_post_nopriv_tegatai_2fa_verify', [$this, 'verify_code']);
            add_action('show_user_profile', [$this, 'user_profile_totp']);
            add_action('edit_user_profile', [$this, 'user_profile_totp']);
        }
    }

    // DRY: Unified IP Handling
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    public function user_profile_totp($user) {
        if (!current_user_can('edit_user', $user->ID)) return;
        $secret = get_user_meta($user->ID, 'teg_totp_secret', true);
        if (empty($secret)) {
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $secret = '';
            for($i=0;$i<16;$i++) $secret .= $chars[random_int(0,31)];
            update_user_meta($user->ID, 'teg_totp_secret', $secret);
        }
        $name = rawurlencode(get_bloginfo('name') . ':' . $user->user_login);
        $issuer = rawurlencode(get_bloginfo('name'));
        $url = "otpauth://totp/$name?secret=$secret&issuer=$issuer";
        
        echo '<h3>🛡️ ' . esc_html__('Tegatai Authenticator (2FA)', 'tegatai-Secure') . '</h3>';
        echo '<table class="form-table"><tr><th>' . esc_html__('QR Code scannen', 'tegatai-Secure') . '</th><td>';
        echo '<p>' . esc_html__('Scanne diesen Code mit Google Authenticator, Authy oder einer anderen TOTP-App, falls du "Authenticator App" als 2FA Methode im Tegatai Dashboard gewählt hast.', 'tegatai-Secure') . '</p>';
        echo '<p><strong>' . esc_html__('QR-Code Hinweis:', 'tegatai-Secure') . '</strong> ' . esc_html__('Aus Sicherheitsgründen wird kein externer QR-Code-Dienst verwendet.', 'tegatai-Secure') . '</p>';
        echo '<p>' . esc_html__('Du kannst den folgenden otpauth://-Link in vielen Authenticator-Apps hinzufügen (oder nutze den manuellen Code unten):', 'tegatai-Secure') . '</p>';
        echo '<p style="word-break:break-all;"><code>'.esc_html($url).'</code></p>';
        echo '<p>' . esc_html__('Manueller Eingabe-Code:', 'tegatai-Secure') . ' <code>'.$secret.'</code></p>';
        echo '</td></tr></table>';
    }

    public function check_login($user, $username, $password) {
        if (is_wp_error($user) || !is_a($user, 'WP_User')) return $user;
        $ops = tegatai_get_setting('tegatai_options');
        $mode = isset($ops['twofa_mode']) ? $ops['twofa_mode'] : 'both';
        
        $token = bin2hex(random_bytes(32));
        $data = ['uid' => $user->ID, 'fails' => 0, 'mode' => $mode];
        
        if ($mode === 'email' || $mode === 'both') {
            $code = rand(100000, 999999);
            $data['hash'] = wp_hash_password($code);
            $msg = esc_html__('Dein Tegatai 2FA Code lautet:', 'tegatai-Secure') . " $code";
            if ($mode === 'both') $msg .= "\n\n" . esc_html__('Hinweis: Du kannst alternativ auch den Code aus deiner Authenticator App eingeben.', 'tegatai-Secure');
            wp_mail($user->user_email, '2FA Code', $msg);
        }
        
        set_transient('teg_2fa_tok_' . $token, $data, 600);
        setcookie('teg_2fa_token', $token, time()+600, COOKIEPATH, COOKIE_DOMAIN, true, true);
        wp_redirect(wp_login_url() . '?action=tegatai_2fa'); exit;
    }

    public function render_form() {
        if (!isset($_COOKIE['teg_2fa_token'])) { wp_redirect(wp_login_url()); exit; }
        
        $token = sanitize_text_field($_COOKIE['teg_2fa_token']);
        $data = get_transient('teg_2fa_tok_' . $token);
        $mode = isset($data['mode']) ? $data['mode'] : 'both';
        
        $prompt = esc_html__('Code eingeben:', 'tegatai-Secure');
        if ($mode === 'both') {
            $prompt = esc_html__('Bitte E-Mail-Code oder Authenticator-App-Code eingeben:', 'tegatai-Secure');
        } elseif ($mode === 'app') {
            $prompt = esc_html__('Bitte Authenticator-App-Code eingeben:', 'tegatai-Secure');
        } elseif ($mode === 'email') {
            $prompt = esc_html__('Bitte den per E-Mail gesendeten Code eingeben:', 'tegatai-Secure');
        }

        login_header('2FA', '<p style="font-weight:600; font-size:14px; margin-bottom:15px; color:#3c434a;">' . $prompt . '</p>');
        echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';
        echo '<input type="hidden" name="action" value="tegatai_2fa_verify">';
        echo '<input name="teg_code" type="text" autocomplete="one-time-code" style="font-size: 22px; letter-spacing: 6px; font-family: monospace; text-align: center; width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #8c8f94;" autofocus required>';
        echo '<input type="submit" value="' . esc_attr__('Verifizieren', 'tegatai-Secure') . '" class="button button-primary button-large" style="width: 100%;">';
        echo '</form>';
        login_footer(); exit;
    }

    private function verify_totp($secret, $code) {
        if (!$secret || strlen($code) !== 6) return false;
        $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
        $key = '';
        foreach(str_split(strtoupper($secret)) as $c) {
            if(isset($map[$c])) $key .= sprintf('%05b', $map[$c]);
        }
        if (empty($key)) return false;
        $key = implode('', array_map('chr', array_map('bindec', str_split($key, 8))));
        $time = floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            $t = pack('N2', 0, $time + $i);
            $hash = hash_hmac('sha1', $t, $key, true);
            $offset = ord(substr($hash, -1)) & 0x0F;
            $otp = (((ord($hash[$offset+0]) & 0x7F) << 24) | ((ord($hash[$offset+1]) & 0xFF) << 16) | ((ord($hash[$offset+2]) & 0xFF) << 8) | (ord($hash[$offset+3]) & 0xFF)) % 1000000;
            if (str_pad($otp, 6, '0', STR_PAD_LEFT) === $code) return true;
        }
        return false;
    }

    public function verify_code() {
        $token = $_COOKIE['teg_2fa_token'] ?? '';
        $data = get_transient('teg_2fa_tok_' . $token);
        if ($data) {
            $uid = $data['uid'];
            $mode = $data['mode'] ?? 'both';
            $code = sanitize_text_field($_POST['teg_code'] ?? '');
            $code = preg_replace('/[^0-9]/', '', $code); // Whitespaces entfernen
            $valid = false;
            
            $secret = get_user_meta($uid, 'teg_totp_secret', true);
            
            if (($mode === 'email' || $mode === 'both') && isset($data['hash'])) {
                if (wp_check_password($code, $data['hash'])) $valid = true;
            }
            if (($mode === 'app' || $mode === 'both') && !$valid) {
                if ($this->verify_totp($secret, $code)) {
                    // TEGATAI_FIX: Verhindert TOTP Replay Attacken
                    $last_used = get_user_meta($uid, 'teg_totp_last_code', true);
                    if ($last_used !== $code) {
                        $valid = true;
                        update_user_meta($uid, 'teg_totp_last_code', $code);
                    }
                }
            }
            
            $ip = $this->get_client_ip();

            if ($valid) {
                delete_transient('teg_2fa_tok_' . $token);
                setcookie('teg_2fa_token', '', time()-3600, COOKIEPATH, COOKIE_DOMAIN, true, true);
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-2FA', "2FA successful for User ID $uid ($ip)");
                wp_set_auth_cookie($uid, true); wp_redirect(admin_url()); exit;
            } else {
                $data['fails']++;
                if ($data['fails'] >= 3) {
                    delete_transient('teg_2fa_tok_' . $token);
                    setcookie('teg_2fa_token', '', time()-3600, COOKIEPATH, COOKIE_DOMAIN, true, true);
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-LOCK', "2FA blocked after 3 failed attempts ($ip)");
                    wp_die(esc_html__('Too many failed attempts. Login locked.', 'tegatai-Secure'), 'Security', ['response' => 403]);
                } else {
                    set_transient('teg_2fa_tok_' . $token, $data, 600);
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-FAIL', "2FA Code wrong. Attempt " . $data['fails'] . " ($ip)");
                    wp_die(esc_html(sprintf(__('Code falsch. Versuch %d von 3.', 'tegatai-Secure'), $data['fails'])));
                }
            }
        } else {
            wp_die(esc_html__('Session abgelaufen oder ungültig.', 'tegatai-Secure'), esc_html__('Fehler', 'tegatai-Secure'), ['response' => 403]);
        }
    }
}
