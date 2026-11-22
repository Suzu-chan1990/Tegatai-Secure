<?php

/* TEGATAI_TRUSTED_DEVICES_PATCH_V2 */
/* TEGATAI_SAFE_PATCH_ENGINE_V2 applied 2026-02-26 16:52:05 */
/* TEGATAI_LOGIN_UNIFICATION_V1 applied */
/* TEGATAI_LOGIN_REFINEMENT_V1 applied */
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Request headers (IP, user agent, URI) are read raw for fingerprints and comparisons; output is escaped and SQL is prepared
// phpcs:disable WordPress.Security.NonceVerification -- Public forms (login, 2FA, comments, anti-spam) have no logged-in user; they are protected by signed tokens, cookies or a captcha (Turnstile / reCAPTCHA) instead of nonces

class Tegatai_LoginGuard {
    public function __construct() {
        $ops = $this->sync_options();

        // Hooks & Logic
        if (!empty($ops['enable_email_alerts'])) {
            add_action('wp_login', [$this, 'alert_admin_login'], 10, 2);
        }
        if (!empty($ops['enable_trusted_devices']) || !empty($ops['trusted_devices'])) {
            add_action('wp_login', [$this, 'check_trusted_device'], 20, 2);
        }
        
        if (!empty($ops['custom_login_slug'])) {
            add_action('init', [$this, 'check_custom_slug']);
            add_filter('site_url', [$this, 'rewrite_login_link'], 10, 2);
            add_filter('network_site_url', [$this, 'rewrite_login_link'], 10, 2);
            add_filter('wp_redirect', [$this, 'filter_redirects'], 10, 2);
            if (!empty($ops['block_default_login'])) add_action('wp_loaded', [$this, 'block_wp_login_direct']);
        }
        add_filter('authenticate', [$this, 'check_admin_attempts'], 10, 3);
        if (!empty($ops['enable_login_limit'])) {
            add_filter('authenticate', [$this, 'check_login_attempts'], 20, 3);
            add_action('wp_login_failed', [$this, 'log_failed_attempt'], 10, 2);
        }
        if (!empty($ops['disable_app_passwords'])) add_filter('wp_is_application_passwords_available', '__return_false');
        if (!empty($ops['block_wp_admin_hide'])) add_action('init', [$this, 'hide_wp_admin_access']);
        if (!empty($ops['block_dash_access'])) add_action('admin_init', [$this, 'restrict_admin']);
        if (!empty($ops['enable_idle_logout'])) {
            add_action('init', [$this, 'check_idle_timeout']);
            // Every new auth cookie starts a fresh activity window (otherwise a stale value logs out right after login)
            add_action('set_logged_in_cookie', [$this, 'reset_idle_timer'], 10, 4);
        }

        // GEOIP LOGIK
        add_action('login_init', [$this, 'enforce_geoip_blocking']);
        add_action('wp', [$this, 'enforce_geoip_blocking']);
        // XML-RPC and REST never fire login_init / wp, so check their logins directly
        add_filter('authenticate', [$this, 'geoip_verify_login'], 25, 3);
        add_action('wp_authenticate_application_password_errors', [$this, 'geoip_verify_app_password'], 10, 2);

        // CAPTCHA: Cloudflare Turnstile or Google reCAPTCHA, never both (reCAPTCHA wins, see Tegatai_Captcha)
        $captcha = class_exists('Tegatai_Captcha') ? Tegatai_Captcha::provider($ops) : (!empty($ops['enable_turnstile']) ? 'turnstile' : '');
        if ($captcha === 'turnstile') {
            add_action('login_enqueue_scripts', [$this, 'turnstile_script']);
            add_action('login_form', [$this, 'turnstile_field']);
        } elseif ($captcha === 'recaptcha') {
            add_action('login_enqueue_scripts', ['Tegatai_Captcha', 'recaptcha_login_script']);
            add_action('login_form', [$this, 'recaptcha_field']);
        }
        if ($captcha !== '') {
            // After core's password check (20), otherwise a valid password overwrites the error.
            // The captcha is checked for right and wrong passwords alike (see captcha_verify_login).
            add_filter('authenticate', [$this, 'captcha_verify_login'], 25, 3);
        }
    }

    // --- OPTIONS SYNC ---
    private function sync_options() {
        $ops = tegatai_get_setting('tegatai_options');
        if (!is_array($ops)) { $ops = []; }
        
        $td_a = array_key_exists('enable_trusted_devices', $ops) ? $ops['enable_trusted_devices'] : null;
        $td_b = array_key_exists('trusted_devices', $ops) ? $ops['trusted_devices'] : null;

        $is_truthy = function($v) {
            if ($v === true || $v === 1 || $v === '1') return true;
            if (is_string($v)) {
                $vv = strtolower(trim($v));
                return in_array($vv, ['on','true','yes','enabled'], true);
            }
            return false;
        };

        $a_on = $is_truthy($td_a);
        $b_on = $is_truthy($td_b);

        if ($a_on || $b_on) {
            if (!$a_on) { $ops['enable_trusted_devices'] = 1; }
            if (!$b_on) { $ops['trusted_devices'] = 1; }
        }

        if (($td_a === null && $td_b !== null) || ($td_b === null && $td_a !== null)) {
            tegatai_update_setting('tegatai_options', $ops);
        }
        return $ops;
    }

    // DRY: Unified IP Handling
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
    }

    // --- TURNSTILE LOGIC ---
    // Cloudflare Turnstile can only be loaded from Cloudflare (service script, no self-hosting possible)
    public function turnstile_script() { wp_enqueue_script('cf-turnstile', 'https://challenges.cloudflare.com/turnstile/v0/api.js', [], null, ['in_footer' => false, 'strategy' => 'async']); } // phpcs:ignore WordPress.WP.EnqueuedResourceParameters.MissingVersion, PluginCheck.CodeAnalysis.EnqueuedResourceOffloading.OffloadedContent -- external service script (Cloudflare Turnstile cannot be self-hosted)
    public function turnstile_field() { $ops = tegatai_get_setting('tegatai_options'); if(!empty($ops['turnstile_site_key'])) echo '<div class="cf-turnstile" data-sitekey="'.esc_attr($ops['turnstile_site_key']).'" style="margin-bottom:15px; display:flex; justify-content:center;"></div>'; }
    /**
     * Checks a Turnstile token with Cloudflare (also used for comments).
     *
     * reason: '' (ok) | 'missing' (no token in the form: the widget did not load or was not solved)
     *         | 'rejected' (Cloudflare refused the token or the secret key)
     *         | 'unreachable' (no usable answer from Cloudflare).
     * detail is written to the log, e.g. Cloudflare's error codes (invalid-input-secret, timeout-or-duplicate ...).
     *
     * @return array{ok: bool, reason: string, detail: string}
     */
    public static function turnstile_check($secret, $token) {
        $token = is_string($token) ? trim($token) : '';
        if ($token === '') {
            // Nothing to ask Cloudflare about; without this check an empty token costs a round trip
            // and comes back as an unspecific failure.
            return ['ok' => false, 'reason' => 'missing', 'detail' => 'no token in the form (widget not loaded or not solved)'];
        }

        // Server-side token check against the Turnstile API (not a loaded resource)
        $verify = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', // phpcs:ignore PluginCheck.CodeAnalysis.Offloading.OffloadedContent
            ['timeout' => 10, 'body' => ['secret' => (string) $secret, 'response' => $token]]);
        if (is_wp_error($verify)) {
            return ['ok' => false, 'reason' => 'unreachable', 'detail' => $verify->get_error_message()];
        }

        $body = json_decode(wp_remote_retrieve_body($verify), true);
        if (!is_array($body)) {
            return ['ok' => false, 'reason' => 'unreachable', 'detail' => 'HTTP ' . (int) wp_remote_retrieve_response_code($verify) . ', no JSON answer'];
        }
        if (!empty($body['success'])) {
            return ['ok' => true, 'reason' => '', 'detail' => ''];
        }

        $codes = isset($body['error-codes']) && is_array($body['error-codes']) ? array_map('sanitize_key', $body['error-codes']) : [];
        // internal-error is Cloudflare's own failure, not a wrong token
        $reason = in_array('internal-error', $codes, true) ? 'unreachable' : 'rejected';
        return ['ok' => false, 'reason' => $reason, 'detail' => $codes ? implode(', ', $codes) : 'no error code'];
    }

    /**
     * The captcha decides before the password result is revealed.
     *
     * The check runs for every login attempt on the login form, whether the password was right
     * or wrong, and a failed captcha always gives the same answer. If it only ran after a correct
     * password, passwords could be tried without solving a captcha, and the captcha error itself
     * would tell an attacker that a password is correct.
     *
     * It stays on priority 25 (after core's password check on 20): an error returned earlier
     * would be replaced by core when the password is valid.
     */
    public function captcha_verify_login($user, $username, $password) {
        if (empty($username) || empty($password)) return $user;
        // The widget is only rendered on wp-login.php; other login endpoints cannot send a token
        if (!did_action('login_init')) return $user;
        $ops = tegatai_get_setting('tegatai_options');
        $provider = class_exists('Tegatai_Captcha') ? Tegatai_Captcha::provider($ops) : 'turnstile';
        $secret = $provider === 'recaptcha' ? tegatai_secret('TEGATAI_RECAPTCHA_SECRET') : tegatai_secret('TEGATAI_TURNSTILE_SECRET');
        if ($provider === '' || empty($secret)) return $user;

        // A token is valid once: remember the result if the filter runs again in this request
        static $result = null;
        if ($result === null) {
            $result = class_exists('Tegatai_Captcha')
                ? Tegatai_Captcha::check($provider, $ops, 'login')
                : self::turnstile_check($secret, isset($_POST['cf-turnstile-response']) && is_string($_POST['cf-turnstile-response']) ? wp_unslash($_POST['cf-turnstile-response']) : '');
        }
        if ($result['ok']) return $user;

        // The reason is logged, so a login that fails at the captcha is not mistaken for a wrong password or 2FA code
        $label = $provider === 'recaptcha' ? 'reCAPTCHA' : 'Turnstile';
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-BOT', $label . ' failed (' . $result['reason'] . ': ' . $result['detail'] . ')');

        if ($result['reason'] === 'unreachable') {
            return new WP_Error('tegatai_captcha_unreachable', __('The captcha service could not be reached. Please try again in a moment.', 'tegatai-secure'));
        }
        if ($result['reason'] === 'missing') {
            return new WP_Error('tegatai_captcha', __('The captcha was not completed. Please reload the page and solve the captcha before logging in.', 'tegatai-secure'));
        }
        return new WP_Error('tegatai_captcha', __('Captcha verification failed. Please reload the page and try again.', 'tegatai-secure'));
    }

    /** Google reCAPTCHA on wp-login.php (v2 is scaled to fit the 272px login form). */
    public function recaptcha_field() {
        Tegatai_Captcha::recaptcha_field('login', 'transform:scale(0.89); transform-origin:0 0; margin-bottom:6px;');
    }

    // --- GEOIP LOGIC (MIT TOGGLE SUPPORT) ---
    public function enforce_geoip_blocking() {
        global $pagenow;
        $is_login = in_array($pagenow, ['wp-login.php', 'wp-register.php']);
        
        // Custom Slug Check
        $request_uri = tegatai_server_raw('REQUEST_URI');
        if (!$is_login && $request_uri !== '') {
            $ops = tegatai_get_setting('tegatai_options');
            if (!empty($ops['custom_login_slug']) && strpos($request_uri, $ops['custom_login_slug']) !== false) {
                $is_login = true;
            }
        }

        $ops = tegatai_get_setting('tegatai_options');
        $only_protect_login = !empty($ops['geoip_login_only']); 
        
        if (!$is_login) {
            if ($only_protect_login) {
                return;
            }
        }

        if (!Tegatai_GeoIP::enabled($ops)) return;

        $ip = $this->get_client_ip();
        $country = $this->get_country_code($ip);

        if ($this->is_country_blocked($ops, $country)) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEO-BLK', "Blocked IP $ip (Country: $country)");
            // Stealth 404
            status_header(404);
            nocache_headers();
            echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">' . "\n";
            echo '<html><head><title>404 Not Found</title></head><body>' . "\n";
            echo '<h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
            exit;
        }
    }

    private function is_country_blocked($ops, $country) {
        return Tegatai_GeoIP::is_blocked($ops, $country);
    }

    private function is_ip_geo_blocked($ip) {
        $ops = tegatai_get_setting('tegatai_options');
        if (!Tegatai_GeoIP::enabled($ops)) return false;
        return $this->is_country_blocked($ops, $this->get_country_code($ip));
    }

    public function geoip_verify_login($user, $username, $password) {
        if (empty($username) || is_wp_error($user)) return $user;
        $ip = $this->get_client_ip();
        if ($this->is_ip_geo_blocked($ip)) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEO-BLK', "Blocked login from IP $ip");
            return new WP_Error('tegatai_geo_blocked', __('Login not allowed from your location.', 'tegatai-secure'));
        }
        return $user;
    }

    public function geoip_verify_app_password($error, $user) {
        $ip = $this->get_client_ip();
        if ($this->is_ip_geo_blocked($ip)) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEO-BLK', "Blocked application password login from IP $ip");
            $error->add('tegatai_geo_blocked', __('Login not allowed from your location.', 'tegatai-secure'));
        }
    }

    private function get_country_code($ip) {
        // Local, private and reserved addresses cannot be located
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return 'LO';

        // Country header from a configured proxy (e.g. Cloudflare) is used when present
        if (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'is_trusted_proxy_request') && Tegatai_Logger::is_trusted_proxy_request()) {
            $hdr = strtoupper(tegatai_server('HTTP_CF_IPCOUNTRY', 2));
            if (preg_match('/^[A-Z]{2}$/', $hdr) && $hdr !== 'XX') return $hdr;
        }

        // Local database lookup, the IP never leaves the server
        return Tegatai_GeoIP::country($ip);
    }

    // Standard Helpers
    public function check_custom_slug() { $s = ((tegatai_get_setting('tegatai_options') ?: [])['custom_login_slug'] ?? ''); $path = trim((string) wp_parse_url(tegatai_server_raw('REQUEST_URI'), PHP_URL_PATH), '/');
        // Subdirectory installs: compare relative to the home path ("blog/slug" -> "slug")
        $home_path = trim((string) wp_parse_url(home_url(), PHP_URL_PATH), '/');
        if ($home_path !== '' && strpos($path . '/', $home_path . '/') === 0) $path = trim(substr($path, strlen($home_path)), '/');
        if ($s && $path === $s) { if (!defined('TEGATAI_LOGIN_PAGE')) define('TEGATAI_LOGIN_PAGE', true); global $user_login, $error, $action; if (!isset($user_login)) $user_login = ''; if (!isset($error)) $error = ''; if (!isset($action)) $action = 'login'; require_once ABSPATH.'wp-login.php'; exit; } }
    
    public function alert_admin_login($user_login, $user) { 
        if (in_array('administrator', (array) $user->roles)) {
            $this->send_alert("Admin Login: $user_login", "IP: " . $this->get_client_ip()); 
        }
    }

    public function check_trusted_device($user_login, $user) {
        if (!in_array('administrator', (array) $user->roles)) {
            return;
        }

        $ip = $this->get_client_ip();
        $ua = tegatai_server('HTTP_USER_AGENT', 255) ?: 'Unknown';
        
        // TEGATAI ENTERPRISE: Advanced Fingerprinting with Client Hints
        $sec_ua = tegatai_server('HTTP_SEC_CH_UA', 255);
        $sec_plat = tegatai_server('HTTP_SEC_CH_UA_PLATFORM', 64);
        $fingerprint = md5($ip . $ua . $sec_ua . $sec_plat);
        
        $known_devices = get_user_meta($user->ID, 'tegatai_known_devices', true);
        if (!is_array($known_devices)) {
            $known_devices = [];
        }

        if (!in_array($fingerprint, $known_devices)) {
            $blog_name = get_bloginfo('name');
            $subject = "Sicherheitswarnung: Neuer Login erkannt auf $blog_name";
            
            $message = "Hallo $user_login,\n\nEs wurde ein neuer Login mit einem bisher unbekannten Gerät oder einer neuen IP-Adresse erkannt:\n\n";
            $message .= "IP-Adresse: $ip\n";
            $message .= "Browser: $ua\n";
            $message .= "Zeitpunkt: " . current_time('mysql') . "\n\n";
            $message .= "Wenn du das warst, kannst du diese E-Mail ignorieren. Das Gerät wurde nun als vertrauenswürdig markiert.\n\n";
            $message .= "Warst du das NICHT? Bitte logge dich umgehend in dein Dashboard ein und ändere dein Passwort!";
            
            $domain = wp_parse_url(home_url(), PHP_URL_HOST);
            if (!$domain) $domain = 'localhost';
            if (substr($domain, 0, 4) == 'www.') $domain = substr($domain, 4);
            
            $from_email = 'wordpress@' . $domain; 
            $headers = ["From: \"Tegatai Alert\" <$from_email>", "Content-Type: text/plain; charset=UTF-8"];
            
            wp_mail($user->user_email, $subject, $message, $headers);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', "Unbekanntes Gerät Login: $user_login ($ip)");

            $known_devices[] = $fingerprint;
            if (count($known_devices) > 20) array_shift($known_devices);
            update_user_meta($user->ID, 'tegatai_known_devices', $known_devices);
        }
    }

    private function send_alert($subj, $msg) { $ops=tegatai_get_setting('tegatai_options'); $to=!empty($ops['alert_email'])?$ops['alert_email']:get_option('admin_email'); $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        if (!$domain) $domain = 'localhost'; if (substr($domain, 0, 4) == 'www.') $domain = substr($domain, 4); $headers = [ "From: Tegatai Security <wordpress@$domain>" ]; wp_mail($to,"[Tegatai] $subj", $msg, $headers); }
    
    public function check_login_attempts($u, $n, $p) { if(get_transient('tegatai_login_lock_'.md5($this->get_client_ip()))){ if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-LOCK',"Locked IP"); return new WP_Error('tegatai_locked','IP Locked (60min)'); } return $u; }
    
    public function log_failed_attempt($u, $error = null) {
        // An outage of the captcha service is not a failed guess and must not lock the IP
        if ($error instanceof WP_Error && $error->get_error_code() === 'tegatai_captcha_unreachable') return;
        $ip=$this->get_client_ip(); $k='tegatai_login_count_'.md5($ip); $c=get_transient($k); if($c===false) set_transient($k,1,900); else { $c++; set_transient($k,$c,900); if($c>=5) { set_transient('tegatai_login_lock_'.md5($ip),1,3600); if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('AUTH-BAN',"IP Banned 60m"); $ops=tegatai_get_setting('tegatai_options'); if(!empty($ops['enable_email_alerts'])) $this->send_alert("IP Blockiert: $ip", "5 Fehlversuche."); } } }
    
    public function hide_wp_admin_access() { if(is_user_logged_in()||(defined('DOING_AJAX')&&DOING_AJAX)) return;
        // Only the path counts. The query string can mention wp-admin legitimately: the login page
        // gets ?redirect_to=.../wp-admin/ whenever a logged-out visitor opens /wp-admin/.
        $path = (string) wp_parse_url(tegatai_server_raw('REQUEST_URI'), PHP_URL_PATH);
        $admin_path = (string) wp_parse_url(admin_url('/'), PHP_URL_PATH);
        $admin_base = rtrim($admin_path, '/');
        if ($admin_base === '' || ($path !== $admin_base && strpos($path, $admin_base . '/') !== 0)) return;
        // Public endpoints below wp-admin: form handlers (2FA) and admin-ajax
        if (in_array(basename($path), ['admin-post.php', 'admin-ajax.php'], true)) return;
        { if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIDE-ADMIN',"Blocked wp-admin"); global $wp_query; $wp_query->set_404(); status_header(404); nocache_headers(); if(defined('TEGATAI_PATH')&&file_exists(TEGATAI_PATH.'templates/404.php')) include(TEGATAI_PATH.'templates/404.php'); else echo "<h1>404</h1>"; exit; } }
    
    public function rewrite_login_link($u,$p) { $s=((tegatai_get_setting('tegatai_options') ?: [])['custom_login_slug'] ?? ''); return ($s&&strpos($u,'wp-login.php')!==false)?str_replace('wp-login.php',$s,$u):$u; }
    
    public function filter_redirects($l,$s) { $sl=((tegatai_get_setting('tegatai_options') ?: [])['custom_login_slug'] ?? ''); return ($sl&&strpos($l,'wp-login.php')!==false)?str_replace('wp-login.php',$sl,$l):$l; }
    
    public function block_wp_login_direct() { global $pagenow; if($pagenow!=='wp-login.php'||defined('TEGATAI_LOGIN_PAGE')) return; if(in_array(isset($_GET['action']) ? sanitize_key(wp_unslash($_GET['action'])) : '',['postpass','logout','lostpassword','rp','resetpass','tegatai_2fa','tegatai_2fa_verify'])) return; if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIDE-LOGIN',"Blocked wp-login.php"); wp_die('404 Not Found','Not Found',['response'=>404]); }
    
    public function restrict_admin() {
        if ((defined('DOING_AJAX') && DOING_AJAX) || strpos(tegatai_server_raw('REQUEST_URI'), 'admin-post.php') !== false) return;
        if (!is_user_logged_in()) return;
        $u = wp_get_current_user();
        if ($u && $u->ID > 0 && !in_array('administrator', (array)$u->roles, true) && !in_array('editor', (array)$u->roles, true)) {
            wp_safe_redirect(home_url());
            exit;
        }
    }
    
    public function check_idle_timeout() { if(!is_user_logged_in()) return; $uid=get_current_user_id(); $l=(int)get_user_meta($uid,'tegatai_last_activity',true); if($l&&(time()-$l>3600)) { wp_logout(); wp_safe_redirect(home_url()); exit; }
        // Throttled: one write per minute instead of one per request
        if(time()-$l>=60) update_user_meta($uid,'tegatai_last_activity',time()); }

    public function reset_idle_timer($logged_in_cookie, $expire, $expiration, $user_id) { update_user_meta((int)$user_id,'tegatai_last_activity',time()); }
    
    /**
     * TEGATAI ENTERPRISE: Admin Honeypot
     * Blockiert Bots sofort permanent, die versuchen sich als 'admin' einzuloggen.
     */
    public function check_admin_attempts($user, $username, $password) {
        if (empty($username)) return $user;

        $ops = tegatai_get_setting('tegatai_options');
        $forbidden_names = ['admin', 'administrator', 'root', 'webmaster'];
        
        if (!empty($ops['enable_admin_honeypot'])) {
            // Only a trap if no such account exists, otherwise the real "admin" user would ban itself.
            if (is_string($username) && in_array(strtolower($username), $forbidden_names, true) && !username_exists($username)) {
                $ip = $this->get_client_ip();
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BAN-TRAP', "Honeypot Login-Versuch: $username von $ip");
                
                // Expiring ban instead of a permanent, autoloaded transient per IP
                Tegatai_Bans::ban_and_broadcast($ip, DAY_IN_SECONDS, "Admin username honeypot: $username", 'critical');
                
                wp_die('Access Denied.', 'Security Block', ['response' => 403]);
            }
        }
        return $user;
    }
}
