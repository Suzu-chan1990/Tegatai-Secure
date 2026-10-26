<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Firewall {
    // Word boundaries keep normal prose ("medieval (", "Retrieval (", "javascript: tips") from matching.
    private $patterns = ['/\bunion\s+(all\s+)?select\b/i', '/\beval\s*\(/i', '/\bbase64_decode\s*\(/i', '/<script\b/i', '/(\.\.\/)/', '/\b(or|and)\s+[\'"]?1[\'"]?\s*=\s*[\'"]?1\b/i', '/\bjavascript:(?!\s)/i', '/\bonload\s*=/i', '/wp-config\.php/i'];
    // curl/wget are not listed: system cron jobs (wget -q -O - .../wp-cron.php) and uptime monitors use them.
    private $bad_agents = ['python-requests', 'libwww-perl', 'sqlmap', 'nikto', 'masscan'];
    private $ai_bots = ['gptbot', 'chatgpt-user', 'anthropic', 'claude', 'cohere', 'perplexity', 'omgili'];
    private $seo_bots = ['semrush', 'ahrefs', 'majestic', 'screaming frog', 'dotbot', 'rogerbot', 'bytespider'];
    private $sensitive_files = ['.env', '.git', 'wp-config.php.bak', 'debug.log', '.htaccess'];
    
    // Unified Cache Engine
    private $redis = null;

    private $redis_tried = false;

    public function __construct() {
        // Priority 1: Die Firewall muss vor allem anderen (Plugins, Themes) feuern
        add_action('init', [$this, 'run_checks'], 1);
    }

    // Lazy: only connect when a feature actually needs the cache.
    private function get_redis() {
        if ($this->redis_tried) return $this->redis;
        $this->redis_tried = true;
        if (class_exists('Redis')) {
            try {
                $this->redis = new Redis();
                // Standardport 6379, 1s Timeout um Seitenaufbau nicht zu blocken
                if (!@$this->redis->connect('127.0.0.1', 6379, 1)) {
                    $this->redis = null;
                }
            } catch (Exception $e) { $this->redis = null; }
        }
        return $this->redis;
    }

    // Login page (wp-login.php or the custom login slug), must stay reachable during lockdown.
    private function is_login_request() {
        global $pagenow;
        if ($pagenow === 'wp-login.php' || defined('TEGATAI_LOGIN_PAGE')) return true;
        $ops = tegatai_get_setting('tegatai_options', []);
        $slug = is_array($ops) ? ($ops['custom_login_slug'] ?? '') : '';
        if (!is_string($slug) || $slug === '') return false;
        $path = trim((string)wp_parse_url($_SERVER['REQUEST_URI'] ?? '', PHP_URL_PATH), '/');
        // Subdirectory installs: compare relative to the home path
        $home = trim((string)wp_parse_url(home_url(), PHP_URL_PATH), '/');
        if ($home !== '' && strpos($path . '/', $home . '/') === 0) $path = trim(substr($path, strlen($home)), '/');
        return $path === trim($slug, '/');
    }

    // DRY: Zentrale Client-IP Ermittlung
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
    }

    // DRY: Zentrale Immunitäts-Prüfung
    private function is_protected_ip($ip = null) {
        if ($ip === null) $ip = $this->get_client_ip();
        $server_ip = $_SERVER['SERVER_ADDR'] ?? '';
        return in_array($ip, ['127.0.0.1', '::1', $server_ip], true);
    }

    public function run_checks() {
        // UNIVERSAL IMMUNITY: CLI, Cron & Server Loopback
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) return;
        if ($this->is_protected_ip()) return;

        $ops = tegatai_get_setting('tegatai_options', []);

        // Whitelist IPs (Vorrang, inklusive des v1 Patches für WAF Whitelists)
        // Checked before the lockdown so whitelisted admins are never locked out.
        if (!empty($ops['whitelist_ips']) && $this->check_whitelist($ops['whitelist_ips'])) return;
        if (!empty($ops['waf_whitelist_ips']) && $this->check_whitelist($ops['waf_whitelist_ips'])) return;

        // --- 🚨 PANIC BUTTON (LOCKDOWN MODUS) ---
        // The login page stays reachable, otherwise a logged-out admin could never disable it again.
        // Logged-in admins (incl. their admin-ajax/REST calls, cookie auth is resolved here) pass.
        if (!empty($ops['enable_lockdown']) && !current_user_can('manage_options') && !$this->is_login_request()) {
            status_header(503);
            nocache_headers();
            wp_die('<div style="text-align:center; padding:50px; font-family:sans-serif;"><h1>🚧 ' . esc_html__('Maintenance Mode', 'tegatai-secure') . '</h1><p>' . esc_html__('The website is currently locked for security maintenance.', 'tegatai-secure') . '</p></div>', __('503 Service Unavailable', 'tegatai-secure'), ['response' => 503]);
        }

        // 1. VIP SPUR: Echte Suchmaschinen durchwinken (Bypass für WAF & Rate Limit via rDNS)
        if ($this->verify_good_bot()) return;

        // 2. TÜRSTEHER: Ressourcen-Fresser blocken
        if (!empty($ops['block_ai_bots'])) $this->check_specific_bots($this->ai_bots, 'AI/LLM Bot');
        if (!empty($ops['block_seo_bots'])) $this->check_specific_bots($this->seo_bots, 'SEO Scraper');

        // Blacklist IPs
        if (!empty($ops['blacklist_ips'])) $this->check_blacklist($ops['blacklist_ips']);

        // Expiring bans (firewall traps, login honeypots, Hive peers)
        if (Tegatai_Bans::is_banned($this->get_client_ip())) {
            status_header(403);
            wp_die('Banned', '403', ['response' => 403]);
        }

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
        $ops = tegatai_get_setting('tegatai_options');
        // Content authors (edit_posts) legitimately submit markup, scripts and relative links.
        // Guests, subscribers and customers (self-registered accounts) are still inspected.
        if(current_user_can('edit_posts')) return;
        
        // CUSTOM RULES CHECK with ReDoS Shield
        if (!empty($ops['custom_waf_blocklist'])) {
            $custom_rules = explode("\n", $ops['custom_waf_blocklist']);
            $check_target = ($_SERVER['REQUEST_URI'] ?? '') . ' ' . ($_SERVER['HTTP_USER_AGENT'] ?? '');
            
            foreach ($custom_rules as $rule) {
                $rule = trim($rule);
                if (empty($rule)) continue;
                
                // ReDoS Shield & Validation
                if (strlen($rule) > 255 || preg_match('/(\\(.*?\\)[\\*\\+])/', $rule)) {
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('WAF-ERROR', "Skipped potentially unsafe ReDoS rule: $rule");
                    continue;
                }
                
                $matched = @preg_match($rule, $check_target);
                if ($matched === false) {
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('WAF-ERROR', "Regex failed (PCRE Err: " . preg_last_error() . ") for rule: $rule");
                } elseif ($matched) {
                    if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('WAF-CUSTOM', "Rule matched: $rule");
                    wp_die('Blocked by Custom Rule', 'Firewall', ['response' => 403]);
                }
            }
        }

        // HONEYPOT TRAP CHECK
        if (strpos($_SERVER['REQUEST_URI'] ?? '', '/secret-backup-db/') !== false) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BAN-TRAP', "Honeypot ausgelöst: secret-backup-db");
            // Setze Ban-Counter sofort auf Maximum (50) -> 24h Sperre
            Tegatai_Bans::ban_and_broadcast($this->get_client_ip(), DAY_IN_SECONDS, 'Honeypot URL', 'critical');
            wp_die(esc_html__('System Error', 'tegatai-secure'), esc_html__('Trap', 'tegatai-secure'), ['response' => 403]);
        }
        
        // NEU v1.1: URL Whitelist
        if (!empty($ops['waf_whitelist_urls'])) {
            $urls = explode("\n", $ops['waf_whitelist_urls']);
            foreach($urls as $w) {
                $w = trim($w);
                if(!empty($w) && strpos($_SERVER['REQUEST_URI'] ?? '', $w) !== false) return; // Erlaubt
            }
        }

        $u = $_SERVER['REQUEST_URI'] ?? ''; 
        foreach($this->sensitive_files as $f) {
            if(stripos($u,$f)!==false) { 
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('FW-FILE',$f); 
                wp_die('Denied','403',['response'=>403]); 
            } 
        }
        
        $d = array_merge($_GET, $_POST, $_COOKIE); 
        $d['uri'] = $u; 
        $d['ua']  = $_SERVER['HTTP_USER_AGENT'] ?? ''; 
        $this->recursive_scan($d); 
    }

    private function check_geoip($ops) {
        if (!empty($ops['geoip_login_only'])) {
            global $pagenow;
            $is_login = ($pagenow === 'wp-login.php') || ($_SERVER['REQUEST_METHOD'] === 'POST' && strpos($_SERVER['REQUEST_URI'] ?? '', 'xmlrpc.php') !== false);
            if (!$is_login) return; 
        }
        $country = $this->get_country_code();
        if ($country === 'XX') return; // Fail Open

        $list_raw = isset($ops['geoip_list']) ? strtoupper($ops['geoip_list']) : '';
        // Drop empty entries: an empty whitelist must not block every visitor (and every admin).
        $countries = array_values(array_filter(array_map('trim', explode(',', $list_raw)), 'strlen'));
        if (empty($countries)) return;

        if ($ops['geoip_mode'] === 'blacklist') {
            if (in_array($country, $countries, true)) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEO-BLK', "Blocked Country: $country");
                wp_die("Access from your country ($country) is not allowed.", "GeoIP Block", ['response' => 403]);
            }
        } elseif ($ops['geoip_mode'] === 'whitelist') {
            if (!in_array($country, $countries, true)) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEO-BLK', "Blocked Country: $country (Not Whitelisted)");
                wp_die("Access from your country ($country) is not allowed.", "GeoIP Block", ['response' => 403]);
            }
        }
    }

    private function get_country_code() {
        // The header is only meaningful when the request really comes through a configured proxy (e.g. Cloudflare),
        // otherwise any client could pick its own country.
        if (isset($_SERVER['HTTP_CF_IPCOUNTRY']) && class_exists('Tegatai_Logger') && Tegatai_Logger::is_trusted_proxy_request()) {
            $cc = strtoupper(sanitize_text_field($_SERVER['HTTP_CF_IPCOUNTRY']));
            if (preg_match('/^[A-Z]{2}$/', $cc)) return $cc;
        }

        $ip = $this->get_client_ip();
        if ($this->is_protected_ip($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) return 'XX';

        $cache_key = 'teg_geo_' . md5($ip);

        // Check Unified Cache first
        $cached = $this->get_hit_count($cache_key, 86400);
        if ($cached) return $cached;

        $response = wp_remote_get('https://get.geojs.io/v1/ip/country/' . rawurlencode($ip) . '.json', ['timeout' => 2, 'sslverify' => true]);
        if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) == 200) {
            $body = json_decode(wp_remote_retrieve_body($response), true);
            $cc = isset($body['countryCode']) ? strtoupper((string)$body['countryCode']) : 'XX';
            if (!preg_match('/^[A-Z]{2}$/', $cc)) $cc = 'XX';
            $this->set_hit_count($cache_key, $cc, 86400); // Speichere in Unified Cache
            return $cc;
        }
        // Cache failures briefly, otherwise an unreachable API adds the 2s timeout to every request.
        $this->set_hit_count($cache_key, 'XX', 600);
        return 'XX';
    }

    private function check_whitelist($l) { 
        $ip = $this->get_client_ip();
        if ($this->is_protected_ip($ip)) return true; // Server Loopbacks implicit whitelisted
        return in_array($ip, array_map('trim', explode("\n", $l))); 
    }

    private function check_blacklist($l) { 
        $ip = $this->get_client_ip();
        if ($this->is_protected_ip($ip)) return; // Verhindert versehentlichen Server-Ban durch Blacklist
        if(in_array($ip, array_map('trim',explode("\n",$l)))) wp_die('Banned','403',['response'=>403]); 
    }

    // --- Unified Cache Engine (RAM-First, DDoS Protection) ---
    // $time_window is kept for call compatibility; the file cache stores the absolute expiry written by set_hit_count().
    private function get_hit_count($key, $time_window) {
        $redis = $this->get_redis();
        if ($redis) return $redis->get('tegatai_' . $key);
        if (function_exists('apcu_fetch')) return apcu_fetch($key);
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) return wp_cache_get($key, 'tegatai');

        // Fallback auf File-Cache (Format: expiry|value). Stale files are removed by Tegatai_Logger::prune_logs().
        $ud = wp_upload_dir();
        $dir = $ud['basedir'] . '/tegatai-logs/cache/';
        $file = $dir . $key . '.txt';
        if (file_exists($file)) {
            $data = explode('|', (string)@file_get_contents($file), 2);
            if (isset($data[1]) && time() < intval($data[0])) return is_numeric($data[1]) ? intval($data[1]) : $data[1];
            @unlink($file);
        }
        return false;
    }

    private function set_hit_count($key, $val, $time_window) {
        $redis = $this->get_redis();
        if ($redis) { $redis->setex('tegatai_' . $key, $time_window, $val); return; }
        if (function_exists('apcu_store')) { apcu_store($key, $val, $time_window); return; }
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) { wp_cache_set($key, $val, 'tegatai', $time_window); return; }

        // No transients here: one row per visitor IP would turn every new visitor into a DB write.
        $ud = wp_upload_dir();
        $dir = $ud['basedir'] . '/tegatai-logs/cache/';
        if (!is_dir($dir)) @mkdir($dir, 0755, true);
        @file_put_contents($dir . $key . '.txt', (time() + (int)$time_window) . '|' . $val, LOCK_EX);
    }
    // --------------------------------------------------

    public function monitor_404() { 
        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) return;
        if ($this->is_protected_ip()) return;

        if (!is_404() || current_user_can('manage_options')) return; 
        
        $ip = $this->get_client_ip();
        $k = 'teg_404_' . md5($ip);

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $instant_ban_triggers = ['phpmyadmin', '.env', 'actuator/health', 'wp-config.php.bak', 'shell.php', 'phpunit'];
        foreach ($instant_ban_triggers as $trigger) {
            if (stripos($uri, $trigger) !== false) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BAN-404', "Instant Ban: $trigger");
                Tegatai_Bans::ban_and_broadcast($ip, DAY_IN_SECONDS, "404 instant ban: $trigger", 'critical');
                wp_die('Denied', 'Block', ['response' => 403]);
            }
        }

        $c = $this->get_hit_count($k, 300); 
        if ($c === false) {
            $this->set_hit_count($k, 1, 300); 
        } elseif ($c >= 20) { 
            if ($c == 20) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BAN-404', "Scan (20)");
                $this->set_hit_count($k, 21, 300); // Hochzählen, um erneute DB-Writes zu verhindern
                Tegatai_Bans::ban_and_broadcast($ip, HOUR_IN_SECONDS, '404 scan (20 hits)', 'high');
            }
            wp_die('Denied','Block',['response'=>403]); 
        } else {
            $this->set_hit_count($k, $c + 1, 300); 
        }
    }

    private function check_rate_limit() { 
        // Editors/authors: the block editor, heartbeat, autosave and media library easily exceed guest limits.
        if(current_user_can('edit_posts')) return;

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $is_api = (strpos($uri, '/wp-json/') !== false || strpos($uri, 'rest_route=') !== false || strpos($uri, 'admin-ajax.php') !== false);
        $limit = $is_api ? 60 : 180; // Strengeres Limit für API/AJAX (cart fragments, forms etc. need some headroom)
        
        $ip = $this->get_client_ip();
        $k = 'teg_rl_' . md5($ip . ($is_api ? '_api' : '')); 
        $c = $this->get_hit_count($k, 60); 
        
        if ($c === false) {
            $this->set_hit_count($k, 1, 60); 
        } elseif ($c >= $limit) { 
            if ($c == $limit) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('FLOOD', "Limit ($limit) " . ($is_api ? 'API' : 'Global'));
                $this->set_hit_count($k, $limit + 1, 60);
            }
            wp_die('Slow down','429',['response'=>429]); 
        } else {
            $this->set_hit_count($k, $c + 1, 60); 
        }
    }

    private function recursive_scan($d) { 
        foreach($d as $v) {
            if(is_array($v)) {
                $this->recursive_scan($v); 
            } else {
                $v_str = (string)$v;
                foreach($this->patterns as $p) {
                    // ReDoS Shield für native WAF Pattern Checks
                    $matched = @preg_match($p, $v_str);
                    if ($matched === false) {
                        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('WAF-ERROR', "Native Regex failed (PCRE Err: " . preg_last_error() . ") for pattern: $p");
                    } elseif ($matched) { 
                        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('WAF',$p); 
                        wp_die('Blocked','403',['response'=>403]); 
                    } 
                }
            }
        }
    }

    private function check_bot() { 
        $u=strtolower($_SERVER['HTTP_USER_AGENT']??''); 
        if(strlen($u)<5) wp_die('Bot','403',['response'=>403]); 
        foreach($this->bad_agents as $b) {
            if(strpos($u,$b)!==false) wp_die('Bot','403',['response'=>403]); 
        }
    }

    private function check_uploads() {
        if(!empty($_FILES)) {
            foreach($_FILES as $f) {
                if (isset($f['name'])) $this->chk($f['name']);
            }
        }
    }

    // Recursive: name[a][b] style uploads produce nested arrays.
    private function chk($n) {
        if (is_array($n)) {
            foreach ($n as $sub) $this->chk($sub);
            return;
        }
        if (preg_match('/\.(php[0-9]?|pht|phtml?|phps|phar|exe|pl|py)$/i', (string)$n)) {
            wp_die('No scripts','403',['response'=>403]);
        }
    }

    // --- SMART BOT ROUTING ---
    private function verify_good_bot() {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        $ip = $this->get_client_ip();
        
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

        // The DNS verdict is cached per IP and bot, so a flood with a spoofed UA does not cost two blocking lookups per request.
        $cache_key = 'teg_bot_' . md5($ip . '|' . $matched_bot);
        $verdict = $this->get_hit_count($cache_key, 86400);
        if ($verdict === false) {
            $verdict = $this->resolve_bot_verdict($ip, $matched_bot, $valid_domains);
            $this->set_hit_count($cache_key, $verdict, 86400);
        }

        if ($verdict === 'fake') {
            wp_die('Fake Bot Detected', 'Security', ['response' => 403]);
        }
        return $verdict === 'ok'; // Echter Bot! Bypass gewährt.
    }

    /**
     * @return string 'ok' (verified), 'fake' (rDNS missing or foreign domain) or 'unverified' (no forward match)
     */
    private function resolve_bot_verdict($ip, $matched_bot, array $valid_domains) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'unverified';

        $hostname = @gethostbyaddr($ip);
        if ($hostname === $ip || $hostname === false) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('FW-FAKEBOT', "Fake $matched_bot (No rDNS): $ip");
            return 'fake';
        }
        $hostname = strtolower(rtrim($hostname, '.'));

        $domain_match = false;
        foreach ($valid_domains as $domain) {
            if (substr($hostname, -strlen($domain)) === $domain) {
                $domain_match = true;
                break;
            }
        }

        if (!$domain_match) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('FW-FAKEBOT', "Fake $matched_bot (Bad Domain $hostname): $ip");
            return 'fake';
        }

        // Forward confirmation for IPv4 and IPv6 (gethostbyname() only knows A records).
        $ip_bin = @inet_pton($ip);
        $records = @dns_get_record($hostname, DNS_A | DNS_AAAA);
        if (is_array($records)) {
            foreach ($records as $r) {
                $addr = $r['ip'] ?? ($r['ipv6'] ?? '');
                if ($addr !== '' && @inet_pton($addr) === $ip_bin) return 'ok';
            }
        }

        return 'unverified';
    }

    private function check_specific_bots($bot_list, $type_name) {
        $ua = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        foreach ($bot_list as $b) {
            if (strpos($ua, $b) !== false) {
                wp_die("Access Denied: $type_name not allowed.", 'Firewall', ['response' => 403]);
            }
        }
    }
}
