<?php





/* TEGATAI_AUTOPATH_DETECTION_V1 applied 2026-02-26 21:54:52 */
/* TEGATAI_FORCE_RULES_TO_WP_ROOT_V1 applied 2026-02-26 21:43:03 */
/* TEGATAI_AUTOWRITE_RULES_AND_LOG_V1 applied 2026-02-26 21:27:35 */
/* TEGATAI_SERVER_FULL_MULTISTACK_FIX_V1 applied 2026-02-26 20:26:16 */
/* TEGATAI_APACHE_SUPPORT_PATCH_V1 applied 2026-02-26 19:55:34 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Server {
    /**
     * Strictly sanitize Nginx valid_referers entries.
     * Allows: example.com, *.example.com
     */
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
        // Prefer WP root if writable; fallback to uploads (supports custom wp-content paths).
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


    // WIEDERHERGESTELLT: Diese Funktion wird vom Dashboard benötigt
    public static function detect_server() { 
        $s = isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : '';
        if (stripos($s, 'apache') !== false || stripos($s, 'litespeed') !== false) return 'apache';
        if (stripos($s, 'nginx') !== false) return 'nginx';
        return 'unknown'; 
    }

    // Wird beim Klick auf "Regeln schreiben" ausgeführt
    public static function force_update() {
        self::write_nginx_rules();
        self::write_htaccess(); 
    }

    // Wird bei der Plugin-Deaktivierung aufgerufen
    public static function remove_rules() {
        // remove both possible locations
        $root = ABSPATH . 'tegatai-nginx.conf';
        if (file_exists($root)) { @unlink($root); }

        $ud = wp_upload_dir();
        $up = trailingslashit($ud['basedir']) . 'tegatai-nginx.conf';
        if (file_exists($up)) { @unlink($up); }

        // remove root .htaccess block
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

        // remove uploads .htaccess block
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

    // --- NGINX SCHREIBEN ---
    private static function write_nginx_rules() {
        $file_path = self::get_rules_file_path();
        $rules = self::generate_nginx_content();
        
        // Safety: ensure nothing is appended after END marker
        $end_marker = "# --- END TEGATAI RULES ---";
        $pos = strpos($rules, $end_marker);
        if ($pos !== false) {
            $rules = substr($rules, 0, $pos + strlen($end_marker)) . "
";
        }

@file_put_contents($file_path, $rules);
    }

    private static function generate_nginx_content() {
        $ops = get_option('tegatai_options');
        $date = current_time('mysql');
        $ud = wp_upload_dir();
        $rel_uploads = str_replace(ABSPATH, '/', $ud['basedir']); 

        $lines = [];
        $lines[] = "# --- TEGATAI SECURITY RULES ($date) ---";
        $lines[] = "# Include this file in your Nginx server block:";
        $lines[] = "# include " . ABSPATH . "tegatai-nginx.conf;";
        $lines[] = "";

        // 0. Disable Indexing (X-Robots-Tag)
        if (!empty($ops['server_disable_indexing'])) {
            $lines[] = "# Disable indexing";
            $lines[] = "add_header X-Robots-Tag \"noindex, nofollow, nosnippet, noarchive\" always;";
            $lines[] = "";
        }


        // 0b. Protected Directories (deny access)
        if (!empty($ops['server_protected_dirs'])) {
            $lines[] = "# Protected directories";
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

            // IMPORTANT:
            // Never "deny all" wp-content/plugins/mu-plugins/uploads equivalents – that breaks WP assets.
            // For those, block PHP execution only (safe hardening).
            $special = [
                'kontentsu' => true,            // wp-content (only block PHP in themes)
                'puraguin' => true,             // wp-content/plugins (block PHP execution)
                'kontentsumu-plugins' => true,  // wp-content/mu-plugins (block PHP execution)
                'appurodo' => true,             // uploads (block PHP execution)
            ];
            $php_only = [];

            $filtered = [];
            foreach ($clean as $dir) {
                if (isset($special[$dir])) {
                    $php_only[$dir] = true;
                    continue;
                }
                $filtered[] = $dir;
            }
            $clean = $filtered;

            // Regular protected dirs: deny access completely (ok for private folders like logs/backups)
            if (!empty($clean)) {
                $re = implode('|', $clean);
                $lines[] = "location ~* ^/($re)(/|$) {";
                $lines[] = "    deny all;";
                $lines[] = "}";
                $lines[] = "";
            }

            // PHP-only blocks for WP-content-like dirs (safe, does not block CSS/JS/images)
            if (!empty($php_only)) {
                $phpre = '(?:php[1-7]?|pht|phtml?|phps)';

                if (!empty($php_only['appurodo'])) {
                    $lines[] = "location ~ ^/appurodo/.*\\.{$phpre}$ { deny all; }";
                }
                if (!empty($php_only['puraguin'])) {
                    $lines[] = "location ~ ^/puraguin/.*\\.{$phpre}$ { deny all; }";
                }
                if (!empty($php_only['kontentsumu-plugins'])) {
                    $lines[] = "location ~ ^/kontentsumu-plugins/.*\\.{$phpre}$ { deny all; }";
                }
                if (!empty($php_only['kontentsu'])) {
                    // Keep theme PHP from being directly executed via URL
                    $lines[] = "location ~ ^/kontentsu/themes/.*\\.{$phpre}$ { deny all; }";
                }

                $lines[] = "";
            }
        }


        // 1. Hotlink Protection
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

        // 2. Sensitive Files Block
        if (!empty($ops['server_protect_files'])) {
            $lines[] = "location ~* \.(log|ini|sql|env|sh|bak|old|git)$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        // 3. System Files
        if (!empty($ops['server_hide_system_files'])) {
            $lines[] = "location ~* /(readme\.html|license\.txt|wp-config\.php|install\.php)$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        // 4. Dotfiles
        if (!empty($ops['server_block_dotfiles'])) {
            $lines[] = "location ~ /\. { deny all; access_log off; log_not_found off; return 403; }";
        }

        // 5. XMLRPC
        if (!empty($ops['server_block_xmlrpc'])) {
            $lines[] = "location = /xmlrpc.php { deny all; access_log off; log_not_found off; return 403; }";
        }

        // 5.5 Protect Tegatai Backups & Logs (TEGATAI_FIX)
        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-backups/ { deny all; access_log off; log_not_found off; return 403; }";
        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-logs/ { deny all; access_log off; log_not_found off; return 403; }";
        $lines[] = "location ~ ^" . $rel_uploads . "/tegatai-quarantine/ { deny all; access_log off; log_not_found off; return 403; }";

        // 6. PHP in Uploads
        if (!empty($ops['server_disable_php_uploads'])) {
            $lines[] = "location ~ ^" . $rel_uploads . "/.+\.php$ { deny all; access_log off; log_not_found off; return 403; }";
        }

        // 7. Bad Bots
        if (!empty($ops['server_filter_bad_bots'])) {
            $bots = "sqlmap|nikto|wpscan|python|curl|wget|libwww|acunetix|havij|winhttp|indy|mail.ru|scooter|mj12bot|ahrefs|semalt";
            $lines[] = "if (\$http_user_agent ~* \"($bots)\") { return 403; }";
        }

        // 8. Custom Protected Files
        if (!empty($ops['server_custom_files_list'])) {
            $lines[] = "# Custom Protected Files";
            $raw_cf = str_replace([',', ';'], "\n", $ops['server_custom_files_list']);
            $cf_entries = explode("\n", $raw_cf);
            foreach ($cf_entries as $cf) {
                $cf = trim($cf);
                if ($cf === '') continue;
                if (strpos($cf, '/') !== 0) { $cf = '/' . $cf; }
                
                // Bereinigung für Nginx-Sicherheit (erlaubt nur Alphanumerisch, Punkte, Striche, Slashes)
                $cf = preg_replace('/[^A-Za-z0-9_\-\.\/]/', '', $cf);
                if ($cf === '/' || $cf === '') continue;
                
                $lines[] = "location = " . $cf . " { deny all; access_log off; log_not_found off; return 403; }";
            }
        }

        $lines[] = "";
        $lines[] = "# --- END TEGATAI RULES ---";
            // Block PHP execution in sensitive content paths (PHP-only, do not break static assets)
            $lines[] = "location ~ ^/appurodo/.*\\.(?:(?:php[1-7]?|pht|phtml?|phps))$ { deny all; }";
            $lines[] = "location ~ ^/puraguin/.*\\.(?:(?:php[1-7]?|pht|phtml?|phps))$ { deny all; }";
            $lines[] = "location ~ ^/kontentsu/themes/.*\\.(?:(?:php[1-7]?|pht|phtml?|phps))$ { deny all; }";

        // Deduplicate lines (preserve order) to avoid duplicate nginx rules
        $seen = array();
        $deduped = array();
        foreach ($lines as $ln) {
            $k = (string)$ln;
            if (isset($seen[$k])) { continue; }
            $seen[$k] = true;
            $deduped[] = $ln;
        }
        $lines = $deduped;



        return implode("\n", $lines);
    }

    private static function write_htaccess() {
        $f = ABSPATH . '.htaccess';
        if (!file_exists($f)) @touch($f);
    }
}
