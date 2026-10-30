<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_TWOFA_UNIFICATION_V1 applied */
/* TEGATAI_TWOFA_UX_REFINEMENT_V1 applied */
/* TEGATAI_LOCAL_SVG_QRCODE_V2 applied */
class Tegatai_TwoFactor {
    public function __construct() {
        $ops = tegatai_get_setting('tegatai_options');
        // Always show profile setup so admins can enroll before/while enabling 2FA
        add_action('show_user_profile', [$this, 'user_profile_totp']);
        add_action('edit_user_profile', [$this, 'user_profile_totp']);
        add_action('admin_post_tegatai_2fa_profile_action', [$this, 'handle_profile_action']);

        if (!empty($ops['enable_2fa'])) {
            add_filter('authenticate', [$this, 'check_login'], 100, 3);
            add_action('login_form_tegatai_2fa', [$this, 'render_form']);
            add_action('admin_post_nopriv_tegatai_2fa_verify', [$this, 'verify_code']);
            add_action('admin_post_tegatai_2fa_verify', [$this, 'verify_code']);
        }
    }

    public static function is_enabled() {
        $ops = tegatai_get_setting('tegatai_options');
        return !empty($ops['enable_2fa']);
    }

    // DRY: Unified IP Handling
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    public function handle_profile_action() {
        if (!is_user_logged_in()) wp_die('Forbidden');
        check_admin_referer('teg_2fa_profile_nonce');
        $uid = get_current_user_id();
        $sub = isset($_POST['teg_2fa_subaction']) ? sanitize_key($_POST['teg_2fa_subaction']) : '';

        $return_url = admin_url('profile.php');
        if (!empty($_POST['teg_return_to']) && is_string($_POST['teg_return_to'])) {
            $candidate = wp_validate_redirect(wp_unslash($_POST['teg_return_to']), $return_url);
            if ($candidate) {
                $return_url = remove_query_arg('teg_2fa_msg', $candidate);
            }
        } elseif (wp_get_referer()) {
            $candidate = wp_validate_redirect(wp_get_referer(), $return_url);
            if ($candidate) {
                $return_url = remove_query_arg('teg_2fa_msg', $candidate);
            }
        }

        if ($sub === 'reset') {
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $secret = '';
            for ($i = 0; $i < 16; $i++) {
                $secret .= $chars[random_int(0, 31)];
            }
            update_user_meta($uid, 'teg_totp_secret', $secret);
            delete_user_meta($uid, 'teg_totp_confirmed');
            delete_user_meta($uid, 'teg_totp_last_code');
            wp_safe_redirect(add_query_arg('teg_2fa_msg', 'reset', $return_url) . '#tegatai-2fa-section');
            exit;
        }

        if ($sub === 'verify') {
            $secret = get_user_meta($uid, 'teg_totp_secret', true);
            $code = isset($_POST['teg_test_code']) ? preg_replace('/[^0-9]/', '', (string) wp_unslash($_POST['teg_test_code'])) : '';
            if (self::verify_totp_code($secret, $code)) {
                update_user_meta($uid, 'teg_totp_confirmed', 1);
                update_user_meta($uid, 'teg_totp_last_code', $code);
                wp_safe_redirect(add_query_arg('teg_2fa_msg', 'verified', $return_url) . '#tegatai-2fa-section');
                exit;
            } else {
                wp_safe_redirect(add_query_arg('teg_2fa_msg', 'invalid', $return_url) . '#tegatai-2fa-section');
                exit;
            }
        }

        wp_safe_redirect($return_url . '#tegatai-2fa-section');
        exit;
    }

    public static function ensure_user_secret($uid) {
        $uid = (int) $uid;
        if ($uid <= 0) return '';
        $secret = get_user_meta($uid, 'teg_totp_secret', true);
        if (empty($secret) || !is_string($secret)) {
            $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
            $secret = '';
            for ($i = 0; $i < 16; $i++) {
                $secret .= $chars[random_int(0, 31)];
            }
            update_user_meta($uid, 'teg_totp_secret', $secret);
            delete_user_meta($uid, 'teg_totp_confirmed');
        }
        return $secret;
    }

    public static function build_otpauth_url($user, $secret) {
        $host = parse_url(home_url(), PHP_URL_HOST) ?: 'WordPress';
        $raw_blog = wp_specialchars_decode((string) get_bloginfo('name'), ENT_QUOTES);
        $raw_blog = trim(preg_replace('/[\r\n:]+/', ' ', $raw_blog));
        if ($raw_blog === '' || strlen(rawurlencode($raw_blog)) > 36) {
            $raw_blog = $host;
        }
        $login = ($user instanceof WP_User && !empty($user->user_login)) ? $user->user_login : 'admin';
        $label = rawurlencode($raw_blog . ':' . $login);
        $issuer = rawurlencode($raw_blog);
        return "otpauth://totp/{$label}?secret={$secret}&issuer={$issuer}";
    }

    public static function render_enrollment_box($uid = 0, $compact = false) {
        if (!$uid) {
            $uid = get_current_user_id();
        }
        $user = get_userdata((int) $uid);
        if (!($user instanceof WP_User) || get_current_user_id() !== (int) $user->ID) {
            return;
        }

        $secret = self::ensure_user_secret($user->ID);
        $confirmed = (bool) get_user_meta($user->ID, 'teg_totp_confirmed', true);
        $url = self::build_otpauth_url($user, $secret);
        $svg_qr = Tegatai_QR_SVG::render($url, 4, 2);

        $instance_id = 'teg2fa_' . substr(md5((string) $user->ID . '_' . ($compact ? 'c' : 'p')), 0, 8);
        $current_url = (is_ssl() ? 'https://' : 'http://') . ($_SERVER['HTTP_HOST'] ?? 'localhost') . ($_SERVER['REQUEST_URI'] ?? '/wp-admin/profile.php');

        echo '<div id="tegatai-2fa-section" style="margin-top:' . ($compact ? '16px' : '8px') . ';">';

        if (isset($_GET['teg_2fa_msg'])) {
            $m = sanitize_key($_GET['teg_2fa_msg']);
            if ($m === 'verified') {
                echo '<div style="padding:10px 12px; background:#dcfce7; border:1px solid #bbf7d0; color:#166534; border-radius:6px; margin-bottom:12px; font-size:12px; font-weight:600;">✓ ' . esc_html__('Authenticator app successfully verified and confirmed!', 'tegatai-secure') . '</div>';
            } elseif ($m === 'invalid') {
                echo '<div style="padding:10px 12px; background:#fef2f2; border:1px solid #fecaca; color:#991b1b; border-radius:6px; margin-bottom:12px; font-size:12px; font-weight:600;">✖ ' . esc_html__('Invalid 6-digit code. Please check your device time and try again.', 'tegatai-secure') . '</div>';
            } elseif ($m === 'reset') {
                echo '<div style="padding:10px 12px; background:#fffbeb; border:1px solid #fde68a; color:#92400e; border-radius:6px; margin-bottom:12px; font-size:12px; font-weight:600;">↻ ' . esc_html__('New 2FA secret generated. Please scan the new QR code.', 'tegatai-secure') . '</div>';
            }
        }

        echo '<div style="display:flex; flex-wrap:wrap; gap:18px; align-items:flex-start; background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:16px; max-width:100%; box-sizing:border-box;">';
        echo '<div style="background:#ffffff !important; padding:10px; border:1px solid #cbd5e1; border-radius:8px; line-height:0; flex:0 0 auto; width:176px; height:176px; box-sizing:content-box; display:flex; align-items:center; justify-content:center; box-shadow:0 1px 2px rgba(0,0,0,0.04);">' . $svg_qr . '</div>';
        echo '<div style="flex:1; min-width:220px;">';

        echo '<div style="margin-bottom:10px; font-size:13px;"><strong>' . esc_html__('Status:', 'tegatai-secure') . '</strong> ';
        if ($confirmed) {
            echo '<span style="display:inline-block; background:#dcfce7; color:#166534; font-weight:700; font-size:11px; padding:3px 9px; border-radius:999px;">✓ ' . esc_html__('Confirmed & Active', 'tegatai-secure') . '</span>';
        } else {
            echo '<span style="display:inline-block; background:#fef3c7; color:#92400e; font-weight:700; font-size:11px; padding:3px 9px; border-radius:999px;">● ' . esc_html__('Pending Confirmation', 'tegatai-secure') . '</span>';
        }
        echo '</div>';

        echo '<p style="margin:0 0 8px 0; font-size:12px; color:#475569; line-height:1.45;">' . esc_html__('Scan this QR code with Google Authenticator, Authy, 2FAS, or any compatible TOTP app.', 'tegatai-secure') . '</p>';

        echo '<p style="margin:0 0 8px 0; font-size:12px;"><strong>' . esc_html__('Manual Setup Key:', 'tegatai-secure') . '</strong><br><code style="font-size:13px; letter-spacing:1.5px; padding:4px 8px; background:#f1f5f9; border:1px solid #e2e8f0; border-radius:4px; display:inline-block; margin-top:4px; user-select:all; color:#0f172a;">' . esc_html($secret) . '</code></p>';
        echo '<details style="margin:6px 0 12px 0; font-size:11px; color:#64748b;"><summary style="cursor:pointer;">' . esc_html__('Show raw otpauth:// URI', 'tegatai-secure') . '</summary><code style="word-break:break-all; display:block; margin-top:6px; padding:6px; background:#f8fafc; border:1px solid #e2e8f0; border-radius:4px;">' . esc_html($url) . '</code></details>';

        echo '<div style="padding-top:12px; border-top:1px solid #e2e8f0; display:flex; flex-wrap:wrap; gap:8px; align-items:center;">';
        echo '<input type="text" id="' . esc_attr($instance_id) . '_input" placeholder="123456" maxlength="6" pattern="[0-9]{6}" inputmode="numeric" style="width:105px; font-family:monospace; font-size:15px; letter-spacing:3px; text-align:center; padding:5px 8px; border:1px solid #cbd5e1; border-radius:6px; margin:0;" />';
        echo '<button type="button" class="button button-primary" onclick="tegSubmit2faAction(\'verify\', \'' . esc_js($instance_id) . '\')">' . esc_html__('Verify Code', 'tegatai-secure') . '</button>';
        echo '<button type="button" class="button button-secondary" onclick="if(confirm(\'' . esc_js(__('Generate a new secret key? Your previous authenticator entry will stop working.', 'tegatai-secure')) . '\')) tegSubmit2faAction(\'reset\', \'' . esc_js($instance_id) . '\');">' . esc_html__('Reset Secret', 'tegatai-secure') . '</button>';
        echo '</div>';

        echo '</div></div></div>';

        $nonce = wp_create_nonce('teg_2fa_profile_nonce');
        $post_url = esc_url(admin_url('admin-post.php'));
        echo '<script>
        if (typeof window.tegSubmit2faAction !== "function") {
            window.tegSubmit2faAction = function(subaction, instId) {
                var inpEl = document.getElementById(instId + "_input");
                var f = document.createElement("form");
                f.method = "POST";
                f.action = "' . $post_url . '";
                var fields = {
                    action: "tegatai_2fa_profile_action",
                    _wpnonce: "' . esc_js($nonce) . '",
                    teg_2fa_subaction: subaction,
                    teg_test_code: inpEl ? inpEl.value : "",
                    teg_return_to: "' . esc_js($current_url) . '"
                };
                for (var k in fields) {
                    var inp = document.createElement("input");
                    inp.type = "hidden";
                    inp.name = k;
                    inp.value = fields[k];
                    f.appendChild(inp);
                }
                document.body.appendChild(f);
                f.submit();
            };
        }
        </script>';
    }

    public function user_profile_totp($user) {
        if (!($user instanceof WP_User) || get_current_user_id() !== (int) $user->ID) return;
        echo '<h3>🛡️ ' . esc_html__('Tegatai Authenticator (2FA)', 'tegatai-secure') . '</h3>';
        echo '<table class="form-table"><tr><th>' . esc_html__('Scan QR Code', 'tegatai-secure') . '</th><td>';
        self::render_enrollment_box($user->ID, false);
        echo '</td></tr></table>';
    }

    /**
     * Mode actually used for a user. Users without a (confirmed) authenticator fall back to
     * e-mail, otherwise "app" mode would lock out everyone who has not enrolled yet.
     */
    private static function effective_mode($uid) {
        $ops = tegatai_get_setting('tegatai_options');
        $mode = isset($ops['twofa_mode']) && in_array($ops['twofa_mode'], ['email', 'app', 'both'], true) ? $ops['twofa_mode'] : 'both';
        if ($mode === 'email') return 'email';

        $secret = get_user_meta($uid, 'teg_totp_secret', true);
        if (empty($secret)) return 'email';
        if ($mode === 'app' && !get_user_meta($uid, 'teg_totp_confirmed', true)) return 'both';
        return $mode;
    }

    public function check_login($user, $username, $password) {
        if (is_wp_error($user) || !($user instanceof WP_User)) return $user;

        // Cookie re-authentication (e.g. wp-login.php while logged in) is not a fresh password login
        if (empty($password)) return $user;

        // Application passwords are separate, revocable API credentials
        if (did_action('application_password_did_authenticate')) return $user;

        // Non-interactive requests cannot complete the 2FA step, so a plain password is not enough there
        if ((defined('XMLRPC_REQUEST') && XMLRPC_REQUEST) || (defined('REST_REQUEST') && REST_REQUEST) || wp_doing_ajax()) {
            return new WP_Error('teg_2fa_required', __('Two-factor authentication required. Please use an application password.', 'tegatai-secure'));
        }

        $remember = !empty($_POST['rememberme']);
        $redirect_to = isset($_REQUEST['redirect_to']) && is_string($_REQUEST['redirect_to']) ? wp_unslash($_REQUEST['redirect_to']) : '';
        self::start_challenge($user, $remember, $redirect_to);
    }

    /**
     * Starts the 2FA step for an already identified user and redirects to the code form.
     * Also used by the magic link login. Never returns.
     */
    public static function start_challenge($user, $remember = false, $redirect_to = '') {
        $mode = self::effective_mode($user->ID);

        $token = bin2hex(random_bytes(32));
        $data = ['uid' => $user->ID, 'fails' => 0, 'mode' => $mode, 'remember' => (bool) $remember, 'redirect_to' => (string) $redirect_to];

        if ($mode === 'email' || $mode === 'both') {
            $code = str_pad((string) random_int(0, 999999), 6, '0', STR_PAD_LEFT);
            $data['hash'] = wp_hash_password($code);
            $msg = esc_html__('Your Tegatai 2FA code is:', 'tegatai-secure') . " $code";
            if ($mode === 'both') $msg .= "\n\n" . esc_html__('Note: You can alternatively enter the code from your Authenticator app.', 'tegatai-secure');
            wp_mail($user->user_email, '2FA Code', $msg);
        }

        set_transient('teg_2fa_tok_' . $token, $data, 600);
        $cookie_paths = array_unique(array_filter([COOKIEPATH, defined('SITECOOKIEPATH') ? SITECOOKIEPATH : '', defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '', '/']));
        foreach ($cookie_paths as $cp) {
            setcookie('teg_2fa_token', $token, time() + 600, $cp, COOKIE_DOMAIN, is_ssl(), true);
        }
        wp_safe_redirect(add_query_arg('action', 'tegatai_2fa', wp_login_url())); exit;
    }

    private static function get_token_from_cookie() {
        $token = isset($_COOKIE['teg_2fa_token']) && is_string($_COOKIE['teg_2fa_token']) ? $_COOKIE['teg_2fa_token'] : '';
        return preg_match('/^[a-f0-9]{64}$/', $token) ? $token : '';
    }

    public function render_form() {
        $token = self::get_token_from_cookie();
        $data = $token ? get_transient('teg_2fa_tok_' . $token) : false;
        if (!is_array($data)) { wp_safe_redirect(wp_login_url()); exit; }

        $mode = isset($data['mode']) ? $data['mode'] : 'both';

        $prompt = esc_html__('Enter code:', 'tegatai-secure');
        if ($mode === 'both') {
            $prompt = esc_html__('Please enter your email code or Authenticator app code:', 'tegatai-secure');
        } elseif ($mode === 'app') {
            $prompt = esc_html__('Please enter your Authenticator app code:', 'tegatai-secure');
        } elseif ($mode === 'email') {
            $prompt = esc_html__('Please enter the code sent via email:', 'tegatai-secure');
        }

        login_header('2FA', '<p style="font-weight:600; font-size:14px; margin-bottom:15px; color:#3c434a;">' . $prompt . '</p>');
        echo '<form action="'.esc_url(admin_url('admin-post.php')).'" method="post">';
        echo '<input type="hidden" name="action" value="tegatai_2fa_verify">';
        echo '<input name="teg_code" type="text" autocomplete="one-time-code" style="font-size: 22px; letter-spacing: 6px; font-family: monospace; text-align: center; width: 100%; padding: 12px; margin-bottom: 20px; border-radius: 4px; border: 1px solid #8c8f94;" autofocus required>';
        echo '<input type="submit" value="' . esc_attr__('Verify', 'tegatai-secure') . '" class="button button-primary button-large" style="width: 100%;">';
        echo '</form>';
        login_footer(); exit;
    }

    public static function verify_totp_code($secret, $code) {
        if (!$secret || strlen($code) !== 6) return false;
        $map = array_flip(str_split('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'));
        $key = '';
        foreach(str_split(strtoupper($secret)) as $c) {
            if(isset($map[$c])) $key .= sprintf('%05b', $map[$c]);
        }
        if (empty($key)) return false;
        $key = implode('', array_map('chr', array_map('bindec', str_split($key, 8))));
        $time = (int) floor(time() / 30);
        for ($i = -1; $i <= 1; $i++) {
            $t = pack('N2', 0, $time + $i);
            $hash = hash_hmac('sha1', $t, $key, true);
            $offset = ord(substr($hash, -1)) & 0x0F;
            $otp = (((ord($hash[$offset+0]) & 0x7F) << 24) | ((ord($hash[$offset+1]) & 0xFF) << 16) | ((ord($hash[$offset+2]) & 0xFF) << 8) | (ord($hash[$offset+3]) & 0xFF)) % 1000000;
            if (hash_equals(str_pad((string) $otp, 6, '0', STR_PAD_LEFT), $code)) return true;
        }
        return false;
    }

    private function verify_totp($secret, $code) {
        return self::verify_totp_code($secret, $code);
    }

    public function verify_code() {
        $token = self::get_token_from_cookie();
        $data = $token ? get_transient('teg_2fa_tok_' . $token) : false;
        $user = is_array($data) && !empty($data['uid']) ? get_userdata((int) $data['uid']) : false;
        if ($user) {
            $uid = $user->ID;
            $mode = $data['mode'] ?? 'both';
            $code = isset($_POST['teg_code']) && is_string($_POST['teg_code']) ? sanitize_text_field(wp_unslash($_POST['teg_code'])) : '';
            $code = preg_replace('/[^0-9]/', '', $code);
            $valid = false;

            $secret = get_user_meta($uid, 'teg_totp_secret', true);

            if (($mode === 'email' || $mode === 'both') && isset($data['hash'])) {
                if (wp_check_password($code, $data['hash'])) $valid = true;
            }
            if (($mode === 'app' || $mode === 'both') && !$valid) {
                if ($this->verify_totp($secret, $code)) {
                    // Prevent TOTP replay attacks
                    $last_used = (string) get_user_meta($uid, 'teg_totp_last_code', true);
                    if (!hash_equals($last_used, $code)) {
                        $valid = true;
                        update_user_meta($uid, 'teg_totp_last_code', $code);
                        // First successful TOTP confirms enrollment, "app" mode then stops offering e-mail codes
                        update_user_meta($uid, 'teg_totp_confirmed', 1);
                    }
                }
            }

            $ip = $this->get_client_ip();

            if ($valid) {
                delete_transient('teg_2fa_tok_' . $token);
                $cookie_paths = array_unique(array_filter([COOKIEPATH, defined('SITECOOKIEPATH') ? SITECOOKIEPATH : '', defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '', '/']));
                foreach ($cookie_paths as $cp) {
                    setcookie('teg_2fa_token', '', time() - 3600, $cp, COOKIE_DOMAIN, is_ssl(), true);
                }
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-2FA', "2FA successful for User ID $uid ($ip)");

                $ua = isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '';
                update_user_meta($uid, 'teg_sess_ip', $ip);
                update_user_meta($uid, 'teg_sess_ua', $ua);
                update_user_meta($uid, 'teg_last_activity', time());

                wp_set_current_user($uid);
                wp_set_auth_cookie($uid, !empty($data['remember']));
                do_action('wp_login', $user->user_login, $user);

                $raw_redirect = trim((string) ($data['redirect_to'] ?? ''));
                $redirect = wp_validate_redirect($raw_redirect, admin_url());
                $home_unslashed = untrailingslashit(home_url());
                $red_unslashed  = untrailingslashit((string) $redirect);
                if (empty($redirect) || $redirect === '/' || $red_unslashed === $home_unslashed || strpos($redirect, 'logged_out=true') !== false || strpos($redirect, 'action=tegatai_2fa') !== false) {
                    $redirect = admin_url();
                }
                wp_safe_redirect($redirect); exit;
            } else {
                do_action('wp_login_failed', $user->user_login, new WP_Error('teg_2fa_failed', 'Wrong 2FA code'));
                $data['fails']++;
                if ($data['fails'] >= 3) {
                    delete_transient('teg_2fa_tok_' . $token);
                    $cookie_paths = array_unique(array_filter([COOKIEPATH, defined('SITECOOKIEPATH') ? SITECOOKIEPATH : '', defined('ADMIN_COOKIE_PATH') ? ADMIN_COOKIE_PATH : '', '/']));
                    foreach ($cookie_paths as $cp) {
                        setcookie('teg_2fa_token', '', time() - 3600, $cp, COOKIE_DOMAIN, is_ssl(), true);
                    }
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-LOCK', "2FA blocked after 3 failed attempts ($ip)");
                    wp_die(esc_html__('Too many failed attempts. Login locked.', 'tegatai-secure'), 'Security', ['response' => 403]);
                } else {
                    set_transient('teg_2fa_tok_' . $token, $data, 600);
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-FAIL', "2FA Code wrong. Attempt " . $data['fails'] . " ($ip)");
                    wp_die(esc_html(sprintf(__('Invalid code. Attempt %d of 3.', 'tegatai-secure'), $data['fails'])), '2FA', ['response' => 403]);
                }
            }
        } else {
            wp_die(esc_html__('Session expired or invalid.', 'tegatai-secure'), esc_html__('Error', 'tegatai-secure'), ['response' => 403]);
        }
    }
}

/**
 * Self-contained pure-PHP ISO/IEC 18004 QR Code SVG Generator (Byte Mode, ECC Level L, Versions 1-10).
 * Zero external requests, zero JS dependencies, CSP-safe inline SVG output with explicit CSS sizing.
 */
class Tegatai_QR_SVG {
    private static $versions = [
        1  => [19,  7,  1, 19, 0, 0, []],
        2  => [34,  10, 1, 34, 0, 0, [6, 18]],
        3  => [55,  15, 1, 55, 0, 0, [6, 22]],
        4  => [80,  20, 1, 80, 0, 0, [6, 26]],
        5  => [108, 26, 1, 108, 0, 0, [6, 30]],
        6  => [136, 18, 2, 68, 0, 0, [6, 34]],
        7  => [156, 20, 2, 78, 0, 0, [6, 22, 38]],
        8  => [194, 24, 2, 97, 0, 0, [6, 24, 42]],
        9  => [232, 30, 2, 116, 0, 0, [6, 26, 46]],
        10 => [274, 18, 2, 68, 2, 69, [6, 28, 50]],
    ];

    // 18-bit Version Information strings for versions 7..10 (ISO/IEC 18004 Table D.1)
    private static $version_info = [
        7  => 0x07C94,
        8  => 0x085BC,
        9  => 0x09A99,
        10 => 0x0A4D3,
    ];

    public static function render($text, $scale = 4, $margin = 2) {
        $bytes = array_values(unpack('C*', (string) $text));
        $len = count($bytes);

        $ver = 10;
        foreach (self::$versions as $v => $info) {
            $len_bits = ($v <= 9) ? 8 : 16;
            $max_bytes = (int) floor(($info[0] * 8 - 4 - $len_bits) / 8);
            if ($len <= $max_bytes) {
                $ver = $v;
                break;
            }
        }

        $vinfo = self::$versions[$ver];
        $len_bits = ($ver <= 9) ? 8 : 16;
        $max_bytes = (int) floor(($vinfo[0] * 8 - 4 - $len_bits) / 8);
        if ($len > $max_bytes) {
            $bytes = array_slice($bytes, 0, $max_bytes);
            $len = count($bytes);
        }

        $total_data = $vinfo[0];
        $bits = [];

        self::push_bits($bits, 0b0100, 4);
        self::push_bits($bits, $len, $len_bits);
        foreach ($bytes as $b) {
            self::push_bits($bits, $b, 8);
        }

        $max_bits = $total_data * 8;
        $term = min(4, $max_bits - count($bits));
        self::push_bits($bits, 0, $term);

        while (count($bits) % 8 !== 0) {
            $bits[] = 0;
        }

        $pad_bytes = [0xEC, 0x11];
        $p_idx = 0;
        while (count($bits) < $max_bits) {
            self::push_bits($bits, $pad_bytes[$p_idx % 2], 8);
            $p_idx++;
        }

        $data_cw = [];
        for ($i = 0; $i < $total_data; $i++) {
            $val = 0;
            for ($b = 0; $b < 8; $b++) {
                $val = ($val << 1) | $bits[$i * 8 + $b];
            }
            $data_cw[] = $val;
        }

        $ec_len = $vinfo[1];
        $blocks_data = [];
        $blocks_ec = [];
        $offset = 0;
        for ($i = 0; $i < $vinfo[2]; $i++) {
            $blk = array_slice($data_cw, $offset, $vinfo[3]);
            $offset += $vinfo[3];
            $blocks_data[] = $blk;
            $blocks_ec[] = self::rs_encode($blk, $ec_len);
        }
        for ($i = 0; $i < $vinfo[4]; $i++) {
            $blk = array_slice($data_cw, $offset, $vinfo[5]);
            $offset += $vinfo[5];
            $blocks_data[] = $blk;
            $blocks_ec[] = self::rs_encode($blk, $ec_len);
        }

        $final_cw = [];
        $max_d_len = max($vinfo[3], $vinfo[5]);
        for ($i = 0; $i < $max_d_len; $i++) {
            foreach ($blocks_data as $blk) {
                if (isset($blk[$i])) $final_cw[] = $blk[$i];
            }
        }
        for ($i = 0; $i < $ec_len; $i++) {
            foreach ($blocks_ec as $blk) {
                if (isset($blk[$i])) $final_cw[] = $blk[$i];
            }
        }

        $final_bits = [];
        foreach ($final_cw as $cw) {
            self::push_bits($final_bits, $cw, 8);
        }
        if ($ver >= 2 && $ver <= 6) {
            self::push_bits($final_bits, 0, 7);
        }

        $size = 17 + 4 * $ver;
        $matrix = array_fill(0, $size, array_fill(0, $size, null));
        $reserved = array_fill(0, $size, array_fill(0, $size, false));

        self::place_finder($matrix, $reserved, 0, 0, $size);
        self::place_finder($matrix, $reserved, $size - 7, 0, $size);
        self::place_finder($matrix, $reserved, 0, $size - 7, $size);

        $centers = $vinfo[6];
        $c_count = count($centers);
        for ($i = 0; $i < $c_count; $i++) {
            for ($j = 0; $j < $c_count; $j++) {
                if (($i === 0 && $j === 0) || ($i === 0 && $j === $c_count - 1) || ($i === $c_count - 1 && $j === 0)) {
                    continue;
                }
                self::place_alignment($matrix, $reserved, $centers[$i], $centers[$j]);
            }
        }

        for ($i = 8; $i < $size - 8; $i++) {
            $bit = ($i % 2 === 0) ? 1 : 0;
            if (!$reserved[6][$i]) { $matrix[6][$i] = $bit; $reserved[6][$i] = true; }
            if (!$reserved[$i][6]) { $matrix[$i][6] = $bit; $reserved[$i][6] = true; }
        }

        $matrix[4 * $ver + 9][8] = 1;
        $reserved[4 * $ver + 9][8] = true;
        for ($i = 0; $i < 9; $i++) {
            if ($i < $size) {
                $reserved[8][$i] = true;
                $reserved[$i][8] = true;
            }
        }
        for ($i = 0; $i < 8; $i++) {
            $reserved[8][$size - 1 - $i] = true;
            $reserved[$size - 1 - $i][8] = true;
        }

        // Reserve & write 6x3 Version Information blocks for versions 7..10
        if ($ver >= 7 && isset(self::$version_info[$ver])) {
            $vbits = self::$version_info[$ver];
            for ($i = 0; $i < 18; $i++) {
                $bit = ($vbits >> $i) & 1;
                $r = (int) floor($i / 3);
                $c = ($size - 11) + ($i % 3);
                $matrix[$r][$c] = $bit;
                $reserved[$r][$c] = true;
                $matrix[$c][$r] = $bit;
                $reserved[$c][$r] = true;
            }
        }

        $bit_idx = 0;
        $up = true;
        for ($col = $size - 1; $col > 0; $col -= 2) {
            if ($col === 6) $col--;
            for ($step = 0; $step < $size; $step++) {
                $row = $up ? ($size - 1 - $step) : $step;
                for ($c = 0; $c < 2; $c++) {
                    $cc = $col - $c;
                    if (!$reserved[$row][$cc]) {
                        $matrix[$row][$cc] = $final_bits[$bit_idx] ?? 0;
                        $bit_idx++;
                    }
                }
            }
            $up = !$up;
        }

        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if (!$reserved[$r][$c] && (($r + $c) % 2 === 0)) {
                    $matrix[$r][$c] ^= 1;
                }
            }
        }

        $fmt = 0x77C4;
        $f_bits = [];
        for ($i = 0; $i < 15; $i++) {
            $f_bits[$i] = ($fmt >> $i) & 1;
        }
        $tl_coords = [
            [8,0],[8,1],[8,2],[8,3],[8,4],[8,5],[8,7],[8,8],
            [7,8],[5,8],[4,8],[3,8],[2,8],[1,8],[0,8]
        ];
        for ($i = 0; $i < 15; $i++) {
            $matrix[$tl_coords[$i][0]][$tl_coords[$i][1]] = $f_bits[14 - $i];
        }
        for ($i = 0; $i < 7; $i++) {
            $matrix[$size - 1 - $i][8] = $f_bits[14 - $i];
        }
        for ($i = 7; $i < 15; $i++) {
            $matrix[8][$size - 15 + $i] = $f_bits[14 - $i];
        }

        $total_dim = (int) (($size + $margin * 2) * $scale);
        $path = '';
        for ($r = 0; $r < $size; $r++) {
            for ($c = 0; $c < $size; $c++) {
                if (!empty($matrix[$r][$c])) {
                    $x = ($c + $margin) * $scale;
                    $y = ($r + $margin) * $scale;
                    $path .= "M{$x},{$y}h{$scale}v{$scale}h-{$scale}z";
                }
            }
        }

        return '<svg xmlns="http://www.w3.org/2000/svg" width="176" height="176" viewBox="0 0 ' . $total_dim . ' ' . $total_dim . '" shape-rendering="crispEdges" role="img" aria-label="2FA QR Code" style="display:block !important; width:176px !important; height:176px !important; min-width:176px !important; min-height:176px !important; max-width:none !important; background:#ffffff !important; margin:0;"><rect x="0" y="0" width="' . $total_dim . '" height="' . $total_dim . '" fill="#ffffff" style="fill:#ffffff !important;"/><path d="' . $path . '" fill="#000000" style="fill:#000000 !important;"/></svg>';
    }

    private static function push_bits(&$arr, $val, $len) {
        for ($i = $len - 1; $i >= 0; $i--) {
            $arr[] = ($val >> $i) & 1;
        }
    }

    private static function place_finder(&$matrix, &$reserved, $row, $col, $size) {
        for ($r = -1; $r <= 7; $r++) {
            for ($c = -1; $c <= 7; $c++) {
                $rr = $row + $r;
                $cc = $col + $c;
                if ($rr < 0 || $rr >= $size || $cc < 0 || $cc >= $size) continue;
                $in_outer = ($r >= 0 && $r <= 6 && $c >= 0 && $c <= 6);
                $on_border = ($r === 0 || $r === 6 || $c === 0 || $c === 6);
                $in_inner = ($r >= 2 && $r <= 4 && $c >= 2 && $c <= 4);
                $matrix[$rr][$cc] = ($in_outer && ($on_border || $in_inner)) ? 1 : 0;
                $reserved[$rr][$cc] = true;
            }
        }
    }

    private static function place_alignment(&$matrix, &$reserved, $row, $col) {
        for ($r = -2; $r <= 2; $r++) {
            for ($c = -2; $c <= 2; $c++) {
                $rr = $row + $r;
                $cc = $col + $c;
                $matrix[$rr][$cc] = (max(abs($r), abs($c)) === 2 || ($r === 0 && $c === 0)) ? 1 : 0;
                $reserved[$rr][$cc] = true;
            }
        }
    }

    private static function rs_encode($data, $ec_len) {
        $exp = array_fill(0, 512, 0);
        $log = array_fill(0, 256, 0);
        $x = 1;
        for ($i = 0; $i < 255; $i++) {
            $exp[$i] = $x;
            $log[$x] = $i;
            $x <<= 1;
            if ($x & 0x100) $x ^= 0x11D;
        }
        for ($i = 255; $i < 512; $i++) {
            $exp[$i] = $exp[$i - 255];
        }

        $gen = [1];
        for ($i = 0; $i < $ec_len; $i++) {
            $next = array_fill(0, count($gen) + 1, 0);
            for ($j = 0; $j < count($gen); $j++) {
                $next[$j] ^= $gen[$j];
                $next[$j + 1] ^= ($gen[$j] === 0) ? 0 : $exp[$log[$gen[$j]] + $i];
            }
            $gen = $next;
        }

        $res = array_fill(0, $ec_len, 0);
        foreach ($data as $b) {
            $factor = $b ^ array_shift($res);
            $res[] = 0;
            if ($factor !== 0) {
                for ($j = 0; $j < $ec_len; $j++) {
                    $res[$j] ^= $exp[$log[$gen[$j + 1]] + $log[$factor]];
                }
            }
        }
        return $res;
    }
}
