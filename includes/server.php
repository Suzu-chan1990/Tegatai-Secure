<?php
/* TEGATAI_AUTOPATH_DETECTION_V1 applied */
/* TEGATAI_SERVER_FULL_MULTISTACK_FIX_V1 applied */
/* TEGATAI_NGINX_DYNAMIC_PATHS_AND_BOTS_V1 applied */
/* TEGATAI_DRY_BOTS_AND_LOOPBACK_V1 applied */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Server {
    
    // ZENTRALE BOT-DATENBANK (DRY-Prinzip)
    private static $bot_patterns = [
        'scanners' => 'acunetix|dirbuster|havij|masscan|nikto|nmap|sqlmap|wpscan|zgrab|cgichk|morfeus|netsparker|pangolin|sqli|zmeu',
        'ai_bots'  => 'anthropic|claude|gptbot|chatgpt-user|openai|cohere|omgili|perplexity|diffbot|amazonbot|bytespider|petalbot',
        'seo_spam' => 'ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|blexbot|megaindex|magpie-crawler|scrapy|python-requests|libwww-perl|wget|curl'
    ];

    /**
     * TEGATAI FIX: Dual-Engine Support für Apache & LiteSpeed
     */
    public static function write_apache_rules() {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        $ops = tegatai_get_setting('tegatai_options', []);
        
        $up_url = wp_parse_url(wp_upload_dir()['baseurl'], PHP_URL_PATH);
        $up_dir = ltrim($up_url, '/');
        if (empty($up_dir)) $up_dir = 'wp-content/uploads';

        $rules = [];
        $rules[] = '<IfModule mod_rewrite.c>';
        $rules[] = 'RewriteEngine On';
        
        $rules[] = '# Tegatai: Block PHP execution in Uploads';
        $rules[] = 'RewriteRule ^' . $up_dir . '/.*\.(php[1-8]?|pht|phtml?|phps|phar)$ - [F,L]';
        
        if (!empty($ops['block_dotfiles'])) {
            $rules[] = '# Tegatai: Block Dotfiles';
            $rules[] = 'RewriteRule ^\. - [F,L]';
        }

        if (!empty($ops['block_system_files'])) {
            $rules[] = '# Tegatai: Block System Files';
            $rules[] = 'RewriteRule ^(readme\.html|license\.txt|wp-config\.php) - [F,L]';
            $rules[] = 'RewriteRule \.(sql|bak|log)$ - [F,L]';
        }

        if (!empty($ops['block_bad_bots']) || !empty($ops['server_filter_bad_bots'])) {
            $rules[] = '# Tegatai: Enterprise Bad Bot & AI Scraper Protection';
            // Universal Immunity für Apache (IPv4 & IPv6 Loopback Bypass)
            $rules[] = 'RewriteCond %{REMOTE_ADDR} !^127\.0\.0\.1$';
            $rules[] = 'RewriteCond %{REMOTE_ADDR} !^::1$';
            // Kategorisierte Bot-Filter
            $rules[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['scanners'] . ') [NC,OR]';
            $rules[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['ai_bots'] . ') [NC,OR]';
            $rules[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['seo_spam'] . ') [NC]';
            $rules[] = 'RewriteRule ^ - [F,L]';
        }

        $rules[] = '</IfModule>';

        $rules[] = '<FilesMatch "^\.">';
        $rules[] = 'Require all denied';
        $rules[] = '</FilesMatch>';
        
        insert_with_markers(ABSPATH . '.htaccess', 'Tegatai-Secure', $rules);
    }

    private static function tegatai_sanitize_valid_referer_entry($entry) {
        $entry = trim((string)$entry);
        if ($entry === '') { return ''; }
        if (preg_match('/[^a-z0-9\.\-\*]/i', $entry)) { return ''; }
        if (strpos($entry, '..') !== false) { return ''; }
        if (strpos($entry, '/') !== false) { return ''; }
        if (strlen($entry) > 255) { return ''; }
        if (!preg_match('/^(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+$/i', $entry)) { return ''; }
        return strtolower($entry);
    }

    private static function get_rules_file_path() {
        $root = ABSPATH . 'tegatai-nginx.conf';
        $root_ok = (is_dir(ABSPATH) && is_writable(ABSPATH)) || (file_exists($root) && is_writable($root));
        if ($root_ok) return $root;

        $ud = wp_upload_dir();
        $up = trailingslashit($ud['basedir']) . 'tegatai-nginx.conf';
        return $up;
    }

    private static function get_rules_file_mode() {
        $path = self::get_rules_file_path();
        return (strpos($path, ABSPATH) === 0) ? 'root' : 'uploads';
    }

    public static function detect_server() { 
        $s = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '';
        if (stripos($s, 'apache') !== false || stripos($s, 'litespeed') !== false) return 'apache';
        if (stripos($s, 'nginx') !== false) return 'nginx';
        return 'unknown'; 
    }

    public static function force_update() {
        self::write_nginx_rules();
        self::write_apache_rules(); // BUGFIX: War vorher write_htaccess()
    }

    public static function remove_rules() {
        $root = ABSPATH . 'tegatai-nginx.conf';
        if (file_exists($root)) { @unlink($root); }

        $ud = wp_upload_dir();
        $up = trailingslashit($ud['basedir']) . 'tegatai-nginx.conf';
        if (file_exists($up)) { @unlink($up); }

        $root_file = ABSPATH . '.htaccess';
        if (file_exists($root_file)) {
            $begin = "# BEGIN TEGATAI";
            $end   = "# END TEGATAI";
            $cur = @file_get_contents($root_file);
            if ($cur !== false && strpos($cur, $begin) !== false && strpos($cur, $end) !== false) {
                $pat = "/".preg_quote($begin, "/").".*?".preg_quote($end, "/")."\s*/s";
                $cur = preg_replace($pat, "", $cur, 1);
                @file_put_contents($root_file, $cur);
            }
        }

        $uploads_ht = trailingslashit($ud['basedir']) . '.htaccess';
        if (file_exists($uploads_ht)) {
            $ubegin = "# BEGIN TEGATAI UPLOADS";
            $uend   = "# END TEGATAI UPLOADS";
            $ucur = @file_get_contents($uploads_ht);
            if ($ucur !== false && strpos($ucur, $ubegin) !== false && strpos($ucur, $uend) !== false) {
                $upat = "/".preg_quote($ubegin, "/").".*?".preg_quote($uend, "/")."\s*/s";
                $ucur = preg_replace($upat, "", $ucur, 1);
                @file_put_contents($uploads_ht, $ucur);
            }
        }
    }

    private static function write_nginx_rules() {
        $file_path = self::get_rules_file_path();
        $rules = self::generate_nginx_content();
        
        $end_marker = "# --- END TEGATAI RULES ---";
        $pos = strpos($rules, $end_marker);
        if ($pos !== false) {
            $rules = substr($rules, 0, $pos + strlen($end_marker)) . "\n";
        }

        @file_put_contents($file_path, $rules);
    }

    private static function generate_nginx_content() {
        $ops = tegatai_get_setting('tegatai_options');
        $date = current_time('mysql');
        
        $ud = wp_upload_dir();
        $up_dir = rtrim(wp_parse_url($ud['baseurl'], PHP_URL_PATH), '/');
        $pl_dir = rtrim(wp_parse_url(plugins_url(), PHP_URL_PATH), '/');
        $th_dir = rtrim(wp_parse_url(get_theme_root_uri(), PHP_URL_PATH), '/');
        $rel_uploads = str_replace(ABSPATH, '/', $ud['basedir']); 

        $lines = [];
        $lines[] = "# --- TEGATAI SECURITY RULES ($date) ---";
        $lines[] = "# Include this file in your Nginx server block:";
        $lines[] = "# include " . ABSPATH . "tegatai-nginx.conf;";
        $lines[] = "";

        if (!empty($ops['server_disable_indexing'])) {
            $lines[] = "# Disable indexing for admin/login cleanly without breaking PHP routing";
            $lines[] = 'set $tegatai_robots "";';
            $lines[] = 'if ($request_uri ~* "^/(wp-admin/|wp-login\.php)") {';
            $lines[] = '    set $tegatai_robots "noindex, nofollow";';
            $lines[] = '}';
            $lines[] = 'add_header X-Robots-Tag $tegatai_robots always;';
            $lines[] = "";
        }

        if (!empty($ops['server_protected_dirs'])) {
            $lines[] = "# Protected directories (Deny absolute access)";
            $raw = str_replace([',', ';'], "\n", $ops['server_protected_dirs']);
            $entries = explode("\n", $raw);
            $clean = [];
            foreach ($entries as $e) {
                $e = trim($e);
                if ($e === '') continue;
                $e = preg_replace('/[^a-zA-Z0-9_\-]/', '', $e);
                if ($e === '') continue;
                $clean[] = $e;
            }

            if (!empty($clean)) {
                $re = implode('|', $clean);
                $lines[] = "location ~* ^/($re)(/|$) {";
                $lines[] = "    deny all;";
                $lines[] = "}";
                $lines[] = "";
            }
        }

        if (!empty($ops['server_hotlink_protection'])) {
            $lines[] = "# Hotlink Protection";
            $lines[] = "location ~* \.(jpg|jpeg|png|gif|webp|svg|mp4|mp3)$ {";
            
            $valid_referers = "none blocked server_names";
            if (!empty($ops['server_hotlink_whitelist'])) {
                $raw = str_replace([',', ';'], "\n", $ops['server_hotlink_whitelist']);
                $entries = explode("\n", $raw);
                foreach ($entries as $entry) {
                    $entry = trim($entry);
                    if (empty($entry)) continue;
                    $clean = self::tegatai_sanitize_valid_referer_entry($entry);
                    if ($clean !== '') { $valid_referers .= " " . $clean; }
                }
            }

            $lines[] = "    valid_referers $valid_referers;";
            $lines[] = "    if (\$invalid_referer) { return 403; }";
            $lines[] = "}";
            $lines[] = "";
        }

        if (!empty($ops['server_protect_files'])) {
            $lines[] = "location ~* \.(log|ini|sql|env|sh|bak|old|git)$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        if (!empty($ops['server_hide_system_files'])) {
            $lines[] = "location ~* /(readme\.html|license\.txt|wp-config\.php|install\.php)$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        if (!empty($ops['server_block_dotfiles'])) {
            $lines[] = "location ~ /\. { deny all; access_log off; log_not_found off; return 403; }";
        }

        if (!empty($ops['server_block_xmlrpc'])) {
            $lines[] = "location = /xmlrpc.php { deny all; access_log off; log_not_found off; return 403; }";
        }

        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-backups/ { deny all; access_log off; log_not_found off; return 403; }";
        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-logs/ { deny all; access_log off; log_not_found off; return 403; }";
        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-quarantine/ { deny all; access_log off; log_not_found off; return 403; }";

        if (!empty($ops['server_disable_php_uploads'])) {
            $lines[] = "location ~ ^" . $rel_uploads . "/.+\.php$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        // ==========================================
        // TEGATAI ENTERPRISE BAD BOT RULES (NGINX)
        // ==========================================
        if (!empty($ops['server_filter_bad_bots'])) {
            $lines[] = "# Enterprise Bad Bot & AI Scraper Protection";
            $combined_bots = self::$bot_patterns['scanners'] . '|' . self::$bot_patterns['ai_bots'] . '|' . self::$bot_patterns['seo_spam'];
            $lines[] = "if (\$http_user_agent ~* \"($combined_bots)\") {";
            $lines[] = "    return 403;";
            $lines[] = "}";
            $lines[] = "";
        }

        if (!empty($ops['server_custom_files_list'])) {
            $lines[] = "# Custom Protected Files";
            $raw_cf = str_replace([',', ';'], "\n", $ops['server_custom_files_list']);
            $cf_entries = explode("\n", $raw_cf);
            foreach ($cf_entries as $cf) {
                $cf = trim($cf);
                if ($cf === '') continue;
                if (strpos($cf, '/') !== 0) { $cf = '/' . $cf; }
                $cf = preg_replace('/[^A-Za-z0-9_\-\.\/]/', '', $cf);
                if ($cf === '/' || $cf === '') continue;
                $lines[] = "location = " . $cf . " { deny all; access_log off; log_not_found off; return 403; }";
            }
        }

        $lines[] = "";
        
        // ==========================================
        // DYNAMIC PHP EXECUTION BLOCKS
        // ==========================================
		$lines[] = "# Dynamically resolved WP paths: Block PHP execution in content directories";
        $phpre = '(?:php[1-7]?|pht|phtml?|phps|phar)';
        if (!empty($up_dir)) {
            $lines[] = "location ~ ^" . $up_dir . "/.*\." . $phpre . "$ { deny all; }";
        }
        if (!empty($pl_dir)) {
            // FIX: Erlaubt Anzen die Ausfuehrung der serve.php, blockt alle anderen PHP-Dateien im Plugin-Ordner
            $lines[] = "location ~ ^" . $pl_dir . "/(?!anzen/serve\.php).*\." . $phpre . "$ { deny all; }";
        }
        if (!empty($th_dir)) {
            $lines[] = "location ~ ^" . $th_dir . "/.*\." . $phpre . "$ { deny all; }";
        }

        $lines[] = "";
        $lines[] = "# --- END TEGATAI RULES ---";

        return implode("\n", $lines);
    }
}
