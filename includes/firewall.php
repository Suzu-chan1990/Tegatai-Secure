<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */



/* TEGATAI_WAF_WHITELIST_SUPPORT_V1 */
// --- WAF Whitelist (IPs) ---
// Option key: tegatai_options['waf_whitelist_ips']
// Format: newline/space/comma-separated IPs (exact match).
if (function_exists('get_option')) {
    $teg_ops = get_option('tegatai_options', []);
    if (!is_array($teg_ops)) { $teg_ops = []; }
    $raw = isset($teg_ops['waf_whitelist_ips']) ? (string)$teg_ops['waf_whitelist_ips'] : '';
    if ($raw !== '') {
        $raw = str_replace(["\r", "\t", ","], ["\n", "\n", "\n"], $raw);
        $list = array_filter(array_map('trim', explode("\n", $raw)));
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
        if ($client_ip && in_array($client_ip, $list, true)) {
            // Whitelisted: bypass firewall logic
            return;
        }
    }
}


if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Firewall {
    private $patterns = ['/union\s+select/i', '/eval\s*\(/i', '/base64_decode/i', '/<script>/i', '/(\.\.\/)/', '/1=1/', '/javascript:/i', '/onload=/', '/wp-config\.php/i'];
    private $bad_agents = ['curl', 'wget', 'python-requests', 'libwww-perl', 'sqlmap', 'nikto', 'masscan'];
    private $ai_bots = ['gptbot', 'chatgpt-user', 'anthropic', 'claude', 'cohere', 'perplexity', 'omgili'];
    private $seo_bots = ['semrush', 'ahrefs', 'majestic', 'screaming frog', 'dotbot', 'rogerbot', 'bytespider'];
    private $sensitive_files = ['.env', '.git', 'wp-config.php.bak', 'debug.log', '.htaccess'];

    public function __construct() {
        add_action('init', [$this, 'run_checks']);
    }

    public function run_checks() {
        $ops = get_option('tegatai_options');

        // --- 🚨 PANIC BUTTON (LOCKDOWN MODUS) ---
        if (!empty($ops['enable_lockdown']) && !current_user_can('manage_options')) {
            status_header(503);
            nocache_headers();
            wp_die('<div style="text-align:center; padding:50px; font-family:sans-serif;"><h1>🚧 ' . esc_html__('Maintenance Mode', 'tegatai-secure') . '</h1><p>' . esc_html__('The website is currently locked for security maintenance.', 'tegatai-secure') . '</p></div>', __('503 Service Unavailable', 'tegatai-secure'), ['response' => 503]);
        }

        // Whitelist IPs (Vorrang)
        if (!empty($ops['whitelist_ips']) && $this->check_whitelist($ops['whitelist_ips'])) return;

        // 1. VIP SPUR: Echte Suchmaschinen durchwinken (Bypass für WAF & Rate Limit via rDNS)
        if ($this->verify_good_bot()) return;

        // 2. TÜRSTEHER: Ressourcen-Fresser blocken
        if (!empty($ops['block_ai_bots'])) $this->check_specific_bots($this->ai_bots, 'AI/LLM Bot');
        if (!empty($ops['block_seo_bots'])) $this->check_specific_bots($this->seo_bots, 'SEO Scraper');

        // Blacklist IPs
        if (!empty($ops['blacklist_ips'])) $this->check_blacklist($ops['blacklist_ips']);

        // GeoIP
        if (!empty($ops['geoip_mode']) && $ops['geoip_mode'] !== 'off') {
            $this->check_geoip($ops);
        }

        // Rate Limit
        if (!empty($ops['enable_rate_limit'])) $this->check_rate_limit();

        // WAF & Co
        if (!empty($ops['enable_404_block'])) add_action('template_redirect', [$this, 'monitor_404']);
        if (!empty($ops['enable_waf'])) $this->run_waf();
        if (!empty($ops['block_fake_bots'])) $this->check_bot();
        if (!empty($ops['enable_upload_guard'])) $this->check_uploads();
    }

    private function run_waf() { 
        $ops = get_option('tegatai_options');
        if(current_user_can('manage_options')) return;
        // CUSTOM RULES CHECK
        if (!empty($ops['custom_waf_blocklist'])) {
            $custom_rules = explode("\n", $ops['custom_waf_blocklist']);
            foreach ($custom_rules as $rule) {
                $rule = trim($rule);
                if (empty($rule)) continue;
                $check_target = $_SERVER['REQUEST_URI'] . ' ' . ($_SERVER['HTTP_USER_AGENT'] ?? '');
                // Falls es ein valider Regex ist
                if (@preg_match($rule, $check_target)) {
                    Tegatai_Logger::log('WAF-CUSTOM', "Rule matched: $rule");
                    wp_die('Blocked by Custom Rule', 'Firewall', ['response' => 403]);
                }
            }
        }


        // HONEYPOT TRAP CHECK
        if (strpos($_SERVER['REQUEST_URI'], '/secret-backup-db/') !== false) {
            Tegatai_Logger::log('BAN-TRAP', "Honeypot ausgelöst: secret-backup-db");
            // Setze Ban-Counter sofort auf Maximum (50) -> 24h Sperre
            $k = 'teg_404_'.md5($_SERVER['REMOTE_ADDR']);
            set_transient($k, 50, 86400);
            wp_die(esc_html__('System Error', 'tegatai-secure'), esc_html__('Trap', 'tegatai-secure'), ['response' => 403]);
        }
 
        
        // NEU v1.1: URL Whitelist
        $ops = get_option('tegatai_options');
        if (!empty($ops['waf_whitelist_urls'])) {
            $urls = explode("\n", $ops['waf_whitelist_urls']);
            foreach($urls as $w) {
                $w = trim($w);
                if(!empty($w) && strpos($_SERVER['REQUEST_URI'], $w) !== false) return; // Erlaubt
            }
        }

        $u=$_SERVER['REQUEST_URI']; 
        foreach($this->sensitive_files as $f) if(stripos($u,$f)!==false) { Tegatai_Logger::log('FW-FILE',$f); wp_die('Denied','403',['response'=>403]); } 
        $d=array_merge($_GET,$_POST,$_COOKIE); 
        $d['uri']=$u; 
        $d['ua']=$_SERVER['HTTP_USER_AGENT'] ?? ''; // TEGATAI_FIX: User-Agent in WAF-Scan einschliessen
        $this->recursive_scan($d); 
    }

    // ... Rest bleibt identisch (HTTPS GeoIP logic aus vorherigem Patch ist hier drin) ...
    private function check_geoip($ops) {
        if (!empty($ops['geoip_login_only'])) {
            global $pagenow;
            $is_login = ($pagenow === 'wp-login.php') || ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($_SERVER['REQUEST_URI'], 'xmlrpc.php') !== false);
            if (!$is_login) return; 
        }
        $country = $this->get_country_code();
        if ($country === 'XX') return; // Fail Open

        $list_raw = isset($ops['geoip_list']) ? strtoupper($ops['geoip_list']) : '';
        $countries = array_map('trim', explode(',', $list_raw));

        if ($ops['geoip_mode'] === 'blacklist') {
            if (in_array($country, $countries)) {
                Tegatai_Logger::log('GEO-BLK', "Blocked Country: $country");
                wp_die("Access from your country ($country) is not allowed.", "GeoIP Block", ['response' => 403]);
            }
        } elseif ($ops['geoip_mode'] === 'whitelist') {
            if (!empty($countries) && !in_array($country, $countries)) {
                Tegatai_Logger::log('GEO-BLK', "Blocked Country: $country (Not Whitelisted)");
                wp_die("Access from your country ($country) is not allowed.", "GeoIP Block", ['response' => 403]);
            }
        }
    }

    private function get_country_code() {
        if (isset($_SERVER['HTTP_CF_IPCOUNTRY'])) return strtoupper(sanitize_text_field($_SERVER['HTTP_CF_IPCOUNTRY']));
        $ip = $_SERVER['REMOTE_ADDR'];
        if (in_array($ip, ['127.0.0.1', '::1'])) return 'XX';
        $cache_key = 'teg_geo_' . md5($ip);
        $cached = get_transient($cache_key);
        if ($cached) return $cached;
        $response = wp_remote_get("https://get.geojs.io/v1/ip/country/{$ip}.json", ['timeout' => 2, 'sslverify' => true]);
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $cc = isset($body['countryCode']) ? strtoupper($body['countryCode']) : 'XX';
            set_transient($cache_key, $cc, 86400); return $cc;
        }
        return 'XX';
    }

    private function check_whitelist($l) { return in_array($_SERVER['REMOTE_ADDR'], array_map('trim', explode("\n", $l))); }
    // --- RAM-First Caching Engine (DDoS Protection) ---
    private function get_hit_count($key, $time_window) {
        if (function_exists('apcu_fetch')) return apcu_fetch($key);
        if (wp_using_ext_object_cache()) return wp_cache_get($key, 'tegatai');
        
        $dir = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/';
        $file = $dir . $key . '.txt';
        if (file_exists($file)) {
            $data = explode('|', @file_get_contents($file));
            if (isset($data[1]) && (time() - intval($data[0])) < $time_window) return intval($data[1]);
            @unlink($file);
        }
        return false;
    }

    private function set_hit_count($key, $count, $time_window) {
        if (function_exists('apcu_store')) { apcu_store($key, $count, $time_window); return; }
        if (wp_using_ext_object_cache()) { wp_cache_set($key, $count, 'tegatai', $time_window); return; }
        
        $dir = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/';
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        @file_put_contents($dir . $key . '.txt', time() . '|' . $count);
    }
    // --------------------------------------------------

    public function monitor_404() { 
        if (!is_404() || current_user_can('manage_options')) return; 
        $k = 'teg_404_' . md5($_SERVER['REMOTE_ADDR']);

        $uri = $_SERVER['REQUEST_URI'];
        $instant_ban_triggers = ['phpmyadmin', '.env', 'actuator/health', 'wp-config.php.bak', 'shell.php', 'phpunit'];
        foreach ($instant_ban_triggers as $trigger) {
            if (stripos($uri, $trigger) !== false) {
                Tegatai_Logger::log('BAN-404', "Instant Ban: $trigger");
                $this->set_hit_count($k, 50, 86400);
                set_transient($k, 50, 86400); // Einmalig für Admin UI
                wp_die('Denied', 'Block', ['response' => 403]);
            }
        }

        $c = $this->get_hit_count($k, 300); 
        if ($c === false) {
            $this->set_hit_count($k, 1, 300); 
        } elseif ($c >= 20) { 
            if ($c == 20) {
                Tegatai_Logger::log('BAN-404', "Scan (20)");
                $this->set_hit_count($k, 21, 300); // Hochzählen, um erneute DB-Writes zu verhindern
                set_transient($k, 21, 300); // Einmalig für Admin UI eintragen
            }
            wp_die('Denied','Block',['response'=>403]); 
        } else {
            $this->set_hit_count($k, $c + 1, 300); 
        }
    }
    private function check_blacklist($l) { if(in_array($_SERVER['REMOTE_ADDR'], array_map('trim',explode("\n",$l)))) wp_die('Banned','403',['response'=>403]); }
    private function check_rate_limit() { 
        if(current_user_can('manage_options')) return; 
        
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $is_api = (strpos($uri, '/wp-json/') !== false || strpos($uri, 'admin-ajax.php') !== false);
        $limit = $is_api ? 30 : 120; // Strengeres Limit für API/AJAX
        
        $k = 'teg_rl_' . md5($_SERVER['REMOTE_ADDR'] . ($is_api ? '_api' : '')); 
        $c = $this->get_hit_count($k, 60); 
        
        if ($c === false) {
            $this->set_hit_count($k, 1, 60); 
        } elseif ($c >= $limit) { 
            if ($c == $limit) {
                Tegatai_Logger::log('FLOOD', "Limit ($limit) " . ($is_api ? 'API' : 'Global'));
                $this->set_hit_count($k, $limit + 1, 60);
                set_transient($k, $limit + 1, 60);
            }
            wp_die('Slow down','429',['response'=>429]); 
        } else {
            $this->set_hit_count($k, $c + 1, 60); 
        }
    }
    private function recursive_scan($d) { foreach($d as $v) if(is_array($v)) $this->recursive_scan($v); else foreach($this->patterns as $p) if(preg_match($p,(string)$v)) { Tegatai_Logger::log('WAF',$p); wp_die('Blocked','403',['response'=>403]); } }
    private function check_bot() { $u=strtolower($_SERVER['HTTP_USER_AGENT']??''); if(strlen($u)<5) wp_die('Bot','403',['response'=>403]); foreach($this->bad_agents as $b) if(strpos($u,$b)!==false) wp_die('Bot','403',['response'=>403]); }
    private function check_uploads() { if(!empty($_FILES)) foreach($_FILES as $f) if(is_array($f['name'])) foreach($f['name'] as $n) $this->chk($n); else $this->chk($f['name']); }
    private function chk($n) { if(in_array(strtolower(pathinfo($n,PATHINFO_EXTENSION)),['php','exe','pl','py'])) wp_die('No scripts','403',['response'=>403]); }

    // --- SMART BOT ROUTING ---
    private function verify_good_bot() {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        $ip = $_SERVER['REMOTE_ADDR'];
        
        $bots = [
            'googlebot' => ['.googlebot.com', '.google.com'],
            'bingbot' => ['.search.msn.com'],
            'applebot' => ['.apple.com'],
            'yandexbot' => ['.yandex.com', '.yandex.ru', '.yandex.net']
        ];
        
        $matched_bot = '';
        $valid_domains = [];
        
        foreach ($bots as $bot_name => $domains) {
            if (strpos($ua, $bot_name) !== false) {
                $matched_bot = $bot_name;
                $valid_domains = $domains;
                break;
            }
        }
        
        if (!$matched_bot) return false;

        $hostname = @gethostbyaddr($ip);
        if ($hostname === $ip || $hostname === false) {
            Tegatai_Logger::log('FW-FAKEBOT', "Fake $matched_bot (No rDNS): $ip");
            wp_die('Fake Bot Detected', 'Security', ['response' => 403]);
        }
        
        $domain_match = false;
        foreach ($valid_domains as $domain) {
            if (substr($hostname, -strlen($domain)) === $domain) {
                $domain_match = true;
                break;
            }
        }
        
        if (!$domain_match) {
            Tegatai_Logger::log('FW-FAKEBOT', "Fake $matched_bot (Bad Domain $hostname): $ip");
            wp_die('Fake Bot Detected', 'Security', ['response' => 403]); 
        }
        
        if (@gethostbyname($hostname) === $ip) {
            return true; // Echter Bot! Bypass gewährt.
        }
        
        return false;
    }

    private function check_specific_bots($bot_list, $type_name) {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        foreach ($bot_list as $b) {
            if (strpos($ua, $b) !== false) {
                // Lautloser Block: Wir sparen uns den DB-Eintrag, um das Log nicht mit Spam zu fluten.
                // Bunseki Pro übernimmt das Tracking dieser Bots.
                wp_die("Access Denied: $type_name not allowed.", 'Firewall', ['response' => 403]);
            }
        }
    }
}
