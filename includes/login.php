<?php

/* TEGATAI_TRUSTED_DEVICES_PATCH_V2 */


/* TEGATAI_SAFE_PATCH_ENGINE_V2 applied 2026-02-26 16:52:05 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_LoginGuard {
    public function __construct() {
        $ops = get_option('tegatai_options');
        
        
        /* TD_COMPAT_SYNC */
        // Backward/forward compatibility: some builds store this setting under different keys.
        // Keep both keys in sync so the admin UI and runtime logic stay consistent.
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

        // If either key is enabled, treat the feature as enabled and sync both keys.
        if ($a_on || $b_on) {
            if (!$a_on) { $ops['enable_trusted_devices'] = 1; }
            if (!$b_on) { $ops['trusted_devices'] = 1; }
        }

        // If keys disagree (one set, the other missing), persist the synced state once.
        if (($td_a === null && $td_b !== null) || ($td_b === null && $td_a !== null)) {
            update_option('tegatai_options', $ops);
        }

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
            add_action('wp_login_failed', [$this, 'log_failed_attempt']);
        }
        if (!empty($ops['disable_app_passwords'])) add_filter('wp_is_application_passwords_available', '__return_false');
        if (!empty($ops['block_wp_admin_hide'])) add_action('init', [$this, 'hide_wp_admin_access']);
        if (!empty($ops['block_dash_access'])) add_action('admin_init', [$this, 'restrict_admin']);
        if (!empty($ops['enable_idle_logout'])) add_action('init', [$this, 'check_idle_timeout']);

        // GEOIP LOGIK
        add_action('login_init', [$this, 'enforce_geoip_blocking']);
        add_action('wp', [$this, 'enforce_geoip_blocking']);

        // MAGIC LINKS
        if (!empty($ops['enable_magic_links'])) {
            add_action('login_footer', [$this, 'render_magic_link_form']);
            add_action('login_form_teg_magic_send', [$this, 'process_magic_link_request']);
            add_action('init', [$this, 'process_magic_link_login']);
        }

        // TURNSTILE
        if (!empty($ops['enable_turnstile'])) {
            add_action('login_enqueue_scripts', [$this, 'turnstile_script']);
            add_action('login_form', [$this, 'turnstile_field']);
            add_filter('authenticate', [$this, 'turnstile_verify_login'], 15, 3);
        }
    }

    // --- TURNSTILE LOGIC ---
    public function turnstile_script() { echo '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'; }
    public function turnstile_field() { $ops = get_option('tegatai_options'); if(!empty($ops['turnstile_site_key'])) echo '<div class="cf-turnstile" data-sitekey="'.esc_attr($ops['turnstile_site_key']).'" style="margin-bottom:15px; display:flex; justify-content:center;"></div>'; }
    public function turnstile_verify_login($user, $username, $password) {
        if (empty($username) || empty($password)) return $user;
        $ops = get_option('tegatai_options');
        if (empty($ops['turnstile_secret_key'])) return $user;
        $response = $_POST['cf-turnstile-response'] ?? '';
        $verify = wp_remote_post('https://challenges.cloudflare.com/turnstile/v0/siteverify', ['body' => ['secret' => $ops['turnstile_secret_key'], 'response' => $response]]);
        if (!is_wp_error($verify)) {
            $body = json_decode(wp_remote_retrieve_body($verify), true);
            if (!empty($body['success'])) return $user;
        }
        Tegatai_Logger::log('AUTH-BOT', 'Turnstile failed');
        return new WP_Error('teg_turnstile', '<strong>FEHLER</strong>: Captcha Überprüfung fehlgeschlagen.');
    }

    // --- GEOIP LOGIC (MIT TOGGLE SUPPORT) ---
    
    public function enforce_geoip_blocking() {
        global $pagenow;
        $is_login = in_array($pagenow, ['wp-login.php', 'wp-register.php']);
        
        // Custom Slug Check
        if (!$is_login && isset($_SERVER['REQUEST_URI'])) {
            $ops = get_option('tegatai_options');
            if (!empty($ops['custom_login_slug']) && strpos($_SERVER['REQUEST_URI'], $ops['custom_login_slug']) !== false) {
                $is_login = true;
            }
        }

        // --- HIER IST DIE ÄNDERUNG ---
        $ops = get_option('tegatai_options');
        $only_protect_login = !empty($ops['geoip_login_only']); // 1 wenn AN, 0 wenn AUS
        
        // 1. Wenn wir NICHT auf der Login-Seite sind...
        if (!$is_login && !isset($_GET['teg_magic_login'])) {
            // ... und wir NUR Login schützen wollen -> ABBRUCH (User darf rein)
            if ($only_protect_login) {
                return;
            }
            // Wenn $only_protect_login FALSE ist, läuft der Code weiter -> GLOBALE SPERRE
        }

        if (empty($ops['geoip_mode']) || $ops['geoip_mode'] === 'off') return;

        $ip = $this->get_real_ip();
        $country = $this->get_country_code($ip);

        if ($country === 'LO') return;
        if ($country === 'XX') return; // Fail Open

        $list_raw = isset($ops['geoip_list']) ? strtoupper($ops['geoip_list']) : '';
        $countries = array_filter(array_map('trim', explode(',', $list_raw)));
        $blocked = false;

        if ($ops['geoip_mode'] === 'blacklist') {
            if (in_array($country, $countries)) $blocked = true;
        } elseif ($ops['geoip_mode'] === 'whitelist') {
            if (empty($countries) || !in_array($country, $countries)) $blocked = true;
        }

        if ($blocked) {
            Tegatai_Logger::log('GEO-BLK', "Blocked IP $ip (Country: $country)");
            // Stealth 404
            status_header(404);
            nocache_headers();
            echo '<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">' . "\n";
            echo '<html><head><title>404 Not Found</title></head><body>' . "\n";
            echo '<h1>Not Found</h1><p>The requested URL was not found on this server.</p></body></html>';
            exit;
        }
    }

    private function get_real_ip() {
        // TEGATAI_FIX: IP Spoofing verhindern. Wir vertrauen nur Cloudflare oder der echten Remote-IP.
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) return $_SERVER['HTTP_CF_CONNECTING_IP'];
        // X-Forwarded-For blind zu vertrauen, erlaubt GeoIP-Bypass.
        return $_SERVER['REMOTE_ADDR'];
    }

    private function get_country_code($ip) {
        if (in_array($ip, ['127.0.0.1', '::1'])) return 'LO';
        $cache_key = 'teg_geo_v2_' . md5($ip);
        $cached = get_transient($cache_key);
        if ($cached) return $cached;
        
        $response = wp_remote_get("https://get.geojs.io/v1/ip/country/{$ip}.json", ['timeout' => 3]);
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $cc = isset($body['countryCode']) ? strtoupper($body['countryCode']) : 'XX';
            set_transient($cache_key, $cc, 3600); 
            return $cc;
        }
        return 'XX';
    }

    // Standard Helpers (unverändert)
    public function check_custom_slug() { $s = ((get_option('tegatai_options') ?: [])['custom_login_slug'] ?? ''); $path = trim(parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH), '/'); if ($s && $path === $s) { if (!defined('TEGATAI_LOGIN_PAGE')) define('TEGATAI_LOGIN_PAGE', true); global $user_login, $error, $action; if (!isset($user_login)) $user_login = ''; if (!isset($error)) $error = ''; if (!isset($action)) $action = 'login'; require_once ABSPATH.'wp-login.php'; exit; } }
    public function alert_admin_login($user_login, $user) { 
        if (in_array('administrator', (array) $user->roles)) {
            $this->send_alert("Admin Login: $user_login", "IP: " . $_SERVER['REMOTE_ADDR']); 
        }
    }

    public function check_trusted_device($user_login, $user) {
        if (!in_array('administrator', (array) $user->roles)) {
            return;
        }

        $ip = $_SERVER['REMOTE_ADDR'];
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        
        // Erzeuge einen einfachen Geräte-Fingerprint
        $fingerprint = md5($ip . $ua);
        
        // Lade bisher bekannte Geräte des Nutzers
        $known_devices = get_user_meta($user->ID, 'teg_known_devices', true);
        if (!is_array($known_devices)) {
            $known_devices = [];
        }

        if (!in_array($fingerprint, $known_devices)) {
            // Unbekanntes Gerät! Alarm auslösen.
            $blog_name = get_bloginfo('name');
            $subject = "Sicherheitswarnung: Neuer Login erkannt auf $blog_name";
            
            $message = "Hallo $user_login,\n\nEs wurde ein neuer Login mit einem bisher unbekannten Gerät oder einer neuen IP-Adresse erkannt:\n\n";
            $message .= "IP-Adresse: $ip\n";
            $message .= "Browser: $ua\n";
            $message .= "Zeitpunkt: " . current_time('mysql') . "\n\n";
            $message .= "Wenn du das warst, kannst du diese E-Mail ignorieren. Das Gerät wurde nun als vertrauenswürdig markiert.\n\n";
            $message .= "Warst du das NICHT? Bitte logge dich umgehend in dein Dashboard ein und ändere dein Passwort!";
            
            $domain = parse_url(home_url(), PHP_URL_HOST);
            if (!$domain) {
                $domain = 'localhost';
            }
            if (substr($domain, 0, 4) == 'www.') {
                $domain = substr($domain, 4);
            }
            
            $from_email = 'wordpress@' . $domain; 
            $headers = ["From: \"Tegatai Alert\" <$from_email>", "Content-Type: text/plain; charset=UTF-8"];
            
            wp_mail($user->user_email, $subject, $message, $headers);
            Tegatai_Logger::log('SEC-WARN', "Unbekanntes Gerät Login: $user_login ($ip)");

            // Gerät zur Whitelist hinzufügen (max 20 aufbewahren, um die DB sauber zu halten)
            $known_devices[] = $fingerprint;
            if (count($known_devices) > 20) {
                array_shift($known_devices);
            }
            update_user_meta($user->ID, 'teg_known_devices', $known_devices);
        }
    }
    private function send_alert($subj, $msg) { $ops=get_option('tegatai_options'); $to=!empty($ops['alert_email'])?$ops['alert_email']:get_option('admin_email'); $domain = parse_url(home_url(), PHP_URL_HOST);
        if (!$domain) $domain = 'localhost'; if (substr($domain, 0, 4) == 'www.') $domain = substr($domain, 4); $headers = [ "From: Tegatai Security <wordpress@$domain>" ]; wp_mail($to,"[Tegatai] $subj", $msg, $headers); }
    public function check_login_attempts($u, $n, $p) { if(get_transient('teg_login_lock_'.md5($_SERVER['REMOTE_ADDR']))){ Tegatai_Logger::log('AUTH-LOCK',"Locked IP"); return new WP_Error('teg_locked','IP Locked (60min)'); } return $u; }
    public function log_failed_attempt($u) { $ip=$_SERVER['REMOTE_ADDR']; $k='teg_login_count_'.md5($ip); $c=get_transient($k); if($c===false) set_transient($k,1,900); else { $c++; set_transient($k,$c,900); if($c>=5) { set_transient('teg_login_lock_'.md5($ip),1,3600); Tegatai_Logger::log('AUTH-BAN',"IP Banned 60m"); $ops=get_option('tegatai_options'); if(!empty($ops['enable_email_alerts'])) $this->send_alert("IP Blockiert: $ip", "5 Fehlversuche."); } } }
    public function hide_wp_admin_access() { if(is_user_logged_in()||(defined('DOING_AJAX')&&DOING_AJAX)) return; if(strpos($_SERVER['REQUEST_URI'], 'admin-post.php') !== false) return; if(strpos($_SERVER['REQUEST_URI'],'wp-admin')!==false) { Tegatai_Logger::log('HIDE-ADMIN',"Blocked wp-admin"); global $wp_query; $wp_query->set_404(); status_header(404); nocache_headers(); if(defined('TEGATAI_PATH')&&file_exists(TEGATAI_PATH.'templates/404.php')) include(TEGATAI_PATH.'templates/404.php'); else echo "<h1>404</h1>"; exit; } }
    public function rewrite_login_link($u,$p) { $s=((get_option('tegatai_options') ?: [])['custom_login_slug'] ?? ''); return ($s&&strpos($u,'wp-login.php')!==false)?str_replace('wp-login.php',$s,$u):$u; }
    public function filter_redirects($l,$s) { $sl=((get_option('tegatai_options') ?: [])['custom_login_slug'] ?? ''); return ($sl&&strpos($l,'wp-login.php')!==false)?str_replace('wp-login.php',$sl,$l):$l; }
    public function block_wp_login_direct() { global $pagenow; if($pagenow!=='wp-login.php'||defined('TEGATAI_LOGIN_PAGE')) return; if(in_array($_GET['action']??'',['postpass','logout','lostpassword','rp','resetpass','teg_magic_send'])) return; Tegatai_Logger::log('HIDE-LOGIN',"Blocked wp-login.php"); wp_die('404 Not Found','Not Found',['response'=>404]); }
    public function restrict_admin() { if(defined('DOING_AJAX')&&DOING_AJAX) return; $u=wp_get_current_user(); if(!empty($u)&&!in_array('administrator',(array)$u->roles)&&!in_array('editor',(array)$u->roles)) { wp_redirect(home_url()); exit; } }
    public function check_idle_timeout() { if(!is_user_logged_in()) return; $uid=get_current_user_id(); $l=get_user_meta($uid,'teg_last_activity',true); if($l&&(time()-$l>3600)) { wp_logout(); wp_redirect(home_url()); exit; } update_user_meta($uid,'teg_last_activity',time()); }
    public function render_magic_link_form() {
        ?>
        <style>.teg-magic-wrap{width:320px;margin:20px auto;padding:20px;background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.13);border-radius:4px;border:1px solid #c3c4c7}.teg-magic-wrap h4{margin:0 0 15px 0;text-align:center;color:#555;font-size:14px;text-transform:uppercase;letter-spacing:0.5px}.teg-or-divider{text-align:center;margin:15px 0;color:#72777c;font-size:12px;font-weight:600}</style>
        <script>document.addEventListener("DOMContentLoaded",function(){var l=document.getElementById('login');var m=document.getElementById('teg-magic-box');if(l&&m)l.appendChild(m);});</script>
        <div id="teg-magic-box" class="teg-magic-wrap"><div class="teg-or-divider">&mdash; ODER &mdash;</div><h4>Passwortlos anmelden</h4><form method="post" action="<?php echo esc_url(site_url('wp-login.php?action=teg_magic_send')); ?>"><label for="magic_user_email" style="font-size:14px;margin-bottom:5px;display:block;">Benutzername oder E-Mail</label><input type="text" name="magic_user_email" id="magic_user_email" class="input" style="width:100%;margin-bottom:15px;font-size:16px;" required><input type="submit" class="button button-secondary button-large" style="width:100%;" value="Sende Link"></form></div>
        <?php
    }
    public function process_magic_link_request() {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        $input = sanitize_text_field($_POST['magic_user_email'] ?? '');
        $user = is_email($input) ? get_user_by('email', $input) : get_user_by('login', $input);
        if ($user) {
            $token = bin2hex(random_bytes(32));
            $hash = hash('sha256', $token);
            set_transient('teg_magic_' . $hash, $user->ID, 900); 
            $link = add_query_arg([ 'teg_magic_login' => 1, 'token' => $token ], site_url());
            $blog_name = get_bloginfo('name');
            $subject = "Login Link: $blog_name";
            $message  = "Hallo " . $user->display_name . ",\r\n\r\nLogin Link:\r\n" . $link . "\r\n\r\n(15 Minuten gültig)";
            $domain = parse_url(home_url(), PHP_URL_HOST);
        if (!$domain) $domain = 'localhost';
            if (substr($domain, 0, 4) == 'www.') $domain = substr($domain, 4);
            $from_email = 'wordpress@' . $domain; 
            $headers = [ "From: \"$blog_name Login\" <$from_email>", "Content-Type: text/plain; charset=UTF-8" ];
            $sent = wp_mail($user->user_email, $subject, $message, $headers);
            if($sent) Tegatai_Logger::log('MAIL-OK', "Link sent to " . $user->user_email);
            else Tegatai_Logger::log('MAIL-ERR', "WP_Mail failed for " . $user->user_email);
        }
        wp_redirect(site_url('wp-login.php?checkemail=confirm'));
        exit;
    }
    public function process_magic_link_login() {
        if (!isset($_GET['teg_magic_login']) || !isset($_GET['token'])) return;
        $hash = hash('sha256', $_GET['token']);
        $user_id = get_transient('teg_magic_' . $hash);
        if ($user_id) {
            delete_transient('teg_magic_' . $hash);
            wp_set_auth_cookie($user_id);
            Tegatai_Logger::log('AUTH-MAGIC', "User ID $user_id logged in");
            wp_redirect(admin_url());
            exit;
        } else { wp_die(esc_html__('Invalid link.', 'tegatai-secure'), esc_html__('Error', 'tegatai-secure'), ['response' => 403]); }
    }

    /**
     * TEGATAI ENTERPRISE: Admin Honeypot
     * Blockiert Bots sofort permanent, die versuchen sich als 'admin' einzuloggen.
     */
    public function check_admin_attempts($user, $username, $password) {
        if (empty($username)) {
            return $user;
        }

        $ops = get_option('tegatai_options');
        $forbidden_names = ['admin', 'administrator', 'root', 'webmaster'];
        
        if (!empty($ops['enable_admin_honeypot'])) {
            if (in_array(strtolower($username), $forbidden_names)) {
                $ip = $this->get_real_ip();
                Tegatai_Logger::log('BAN-TRAP', "Honeypot Login-Versuch: $username von $ip");
                
                // Permanente Sperre via Transient (Level 100 markiert Bot-Status)
                $k = 'teg_404_' . md5($ip);
                set_transient($k, 100, 0); // 0 = permanent (bis manueller Löschung)
                
                wp_die('Access Denied.', 'Security Block', ['response' => 403]);
            }
        }
        return $user;
    }

}
