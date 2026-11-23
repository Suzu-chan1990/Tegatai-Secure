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
        // curl/wget are not listed: system cron jobs (wget -q -O - .../wp-cron.php) and uptime monitors use them.
        'seo_spam' => 'ahrefsbot|semrushbot|mj12bot|dotbot|rogerbot|blexbot|megaindex|magpie-crawler|scrapy|python-requests|libwww-perl'
    ];

    // URL path (no trailing slash) of a WordPress URL, e.g. "/blog/wp-content/uploads".
    private static function url_path($url) {
        return rtrim((string)wp_parse_url($url, PHP_URL_PATH), '/');
    }

    /**
     * TEGATAI FIX: Dual-Engine Support für Apache & LiteSpeed
     */
    // Files and folders in plugins / themes that may still be requested directly as PHP.
    // Plugins that ship their own web endpoint (tracking, guest mode, reporting UI) need them.
    const DEFAULT_PHP_EXCEPTIONS = "anzen/serve.php\nlitespeed-cache/guest.vary.php\nmatomo/app/index.php\nmatomo/app/matomo.php\nmatomo/app/piwik.php\nburst-statistics/endpoint.php\nburst-pro/endpoint.php";

    // Cleaned exception list: paths relative to the plugins or themes folder; a trailing "/"
    // allows a whole folder. Unset option = defaults, an empty field = no exceptions.
    public static function php_exceptions($ops = null) {
        if ($ops === null) $ops = tegatai_get_setting('tegatai_options', []);
        $raw = (is_array($ops) && isset($ops['server_php_exceptions']) && is_string($ops['server_php_exceptions']))
            ? $ops['server_php_exceptions'] : self::DEFAULT_PHP_EXCEPTIONS;
        $out = [];
        foreach (preg_split('/[\r\n,;]+/', $raw) as $e) {
            $e = ltrim(trim($e), '/');
            $e = preg_replace('#^wp-content/(plugins|themes)/#', '', $e);
            if ($e === '' || strpos($e, '..') !== false || !preg_match('#^[A-Za-z0-9_\-./]+$#', $e)) continue;
            $out[$e] = true;
        }
        return array_keys($out);
    }

    // "(?!(?:a/b\.php$|c/d/))" for the rules, or "" without exceptions.
    // Files must match exactly, folders (ending in "/") as a prefix.
    private static function php_exception_lookahead($list) {
        if (!$list) return '';
        $alt = [];
        foreach ($list as $e) {
            $alt[] = substr($e, -1) === '/' ? preg_quote($e, '#') : preg_quote($e, '#') . '$';
        }
        return '(?!(?:' . implode('|', $alt) . '))';
    }

    // Direct PHP requests in plugins and themes are blocked unless the administrator allowed them.
    public static function block_plugin_php($ops = null) {
        if ($ops === null) $ops = tegatai_get_setting('tegatai_options', []);
        return !(is_array($ops) && !empty($ops['server_allow_plugin_php']));
    }

    // Path of a WordPress URL relative to the directory of WordPress' .htaccess, as a RewriteRule
    // in that file sees it (no leading slash, home path of subdirectory installs stripped).
    // null: the URL lies outside that directory and cannot be matched from this .htaccess.
    private static function htaccess_rel_path($url) {
        $path = trim(self::url_path($url), '/');
        $home = trim(self::url_path(home_url()), '/');
        if ($home === '') return $path;
        if ($path === $home) return '';
        if (strpos($path, $home . '/') === 0) return substr($path, strlen($home) + 1);
        return null;
    }

    /**
     * Rules for Apache / LiteSpeed, same set as the nginx file. Only mod_rewrite is used
     * (needs the same AllowOverride as WordPress' own permalink rules), so a server that
     * forbids "Options" or "Require" in .htaccess does not answer with a 500 error.
     * The block is appended after WordPress' own block: requests for files and folders that
     * exist reach these rules directly, everything else ends in WordPress (404).
     */
    public static function generate_apache_rules() {
        $ops = tegatai_get_setting('tegatai_options', []);
        if (!is_array($ops)) $ops = [];
        $on = function ($key, $legacy = '') use ($ops) {
            return !empty($ops[$key]) || ($legacy !== '' && !empty($ops[$legacy]));
        };
        $q = function ($p) { return preg_quote($p, '#'); };

        $ud = wp_upload_dir(null, false);
        $up = self::htaccess_rel_path($ud['baseurl']);
        $pl = self::htaccess_rel_path(tegatai_plugins_url());
        $th = self::htaccess_rel_path(get_theme_root_uri());
        $ct = self::htaccess_rel_path(content_url());
        $phpre = '(php[1-8]?|pht|phtml?|phps|phar)';

        $r = [];
        $r[] = '<IfModule mod_rewrite.c>';
        $r[] = 'RewriteEngine On';

        // Always: Tegatai's data folder (logs, backups, server rules, GeoIP database) and the
        // folders of older versions. The folders also carry their own .htaccess.
        if ($up !== null) {
            $r[] = '# Tegatai: data folder';
            $r[] = 'RewriteRule ^' . ($up !== '' ? $q($up) . '/' : '') . '(' . implode('|', array_map($q, array_merge([tegatai_data_dir_name()], self::old_data_dir_names()))) . ')(/|$) - [F,L]';
        }
        if ($ct !== null) {
            $r[] = 'RewriteRule ^' . ($ct !== '' ? $q($ct) . '/' : '') . 'tegatai-quarantine(/|$) - [F,L]';
        }

        // Always (same as nginx): no PHP execution in uploads. Plugins and themes unless allowed,
        // with the exception list. PHP files that WordPress loads itself are not affected; only
        // direct requests are.
        $r[] = '# Tegatai: no direct PHP requests in uploads, plugins and themes';
        if ($up !== null && $up !== '') $r[] = 'RewriteRule ^' . $q($up) . '/.*\.' . $phpre . '$ - [F,L,NC]';
        if (self::block_plugin_php($ops)) {
            $la = self::php_exception_lookahead(self::php_exceptions($ops));
            if ($pl !== null && $pl !== '') $r[] = 'RewriteRule ^' . $q($pl) . '/' . $la . '.*\.' . $phpre . '$ - [F,L,NC]';
            if ($th !== null && $th !== '') $r[] = 'RewriteRule ^' . $q($th) . '/' . $la . '.*\.' . $phpre . '$ - [F,L,NC]';
        }

        if ($on('server_disable_indexing')) {
            $r[] = '# Tegatai: no directory listings (folders without an index file)';
            $r[] = 'RewriteCond %{REQUEST_FILENAME} -d';
            $r[] = 'RewriteCond %{REQUEST_FILENAME}/index.php !-f';
            $r[] = 'RewriteCond %{REQUEST_FILENAME}/index.html !-f';
            $r[] = 'RewriteCond %{REQUEST_FILENAME}/index.htm !-f';
            $r[] = 'RewriteRule ^ - [F,L]';
        }

        if ($on('server_protect_files')) {
            $r[] = '# Tegatai: sensitive files';
            $r[] = 'RewriteRule \.(log|ini|sql|env|sh|bak|old|git)$ - [F,L,NC]';
        }

        if ($on('server_hide_system_files', 'block_system_files')) {
            $r[] = '# Tegatai: system files';
            $r[] = 'RewriteRule (^|/)(readme\.html|license\.txt|wp-config\.php|install\.php)$ - [F,L,NC]';
        }

        // Dotfiles were always blocked on Apache by earlier versions; that stays.
        // /.well-known/ stays reachable (ACME HTTP-01, security.txt, app links).
        $r[] = '# Tegatai: dotfiles';
        $r[] = 'RewriteRule (^|/)\.(?!well-known(/|$)) - [F,L]';

        if ($on('server_block_xmlrpc')) {
            $r[] = '# Tegatai: XML-RPC';
            $r[] = 'RewriteRule ^xmlrpc\.php$ - [F,L,NC]';
        }

        if ($on('server_filter_bad_bots', 'block_bad_bots')) {
            $r[] = '# Tegatai: bad bots';
            $r[] = 'RewriteCond %{REMOTE_ADDR} !^127\.0\.0\.1$';
            $r[] = 'RewriteCond %{REMOTE_ADDR} !^::1$';
            $r[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['scanners'] . ') [NC,OR]';
            $r[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['ai_bots'] . ') [NC,OR]';
            $r[] = 'RewriteCond %{HTTP_USER_AGENT} (' . self::$bot_patterns['seo_spam'] . ') [NC]';
            $r[] = 'RewriteRule ^ - [F,L]';
        }

        if ($on('server_protected_dirs') && is_string($ops['server_protected_dirs'])) {
            $clean = [];
            foreach (explode("\n", str_replace([',', ';'], "\n", $ops['server_protected_dirs'])) as $e) {
                $e = preg_replace('/[^a-zA-Z0-9_\-]/', '', trim($e));
                if ($e !== '') $clean[] = $e;
            }
            if ($clean) {
                $r[] = '# Tegatai: protected directories';
                $r[] = 'RewriteRule ^(' . implode('|', $clean) . ')(/|$) - [F,L,NC]';
            }
        }

        if ($on('server_custom_files_list') && is_string($ops['server_custom_files_list'])) {
            $files = [];
            foreach (explode("\n", str_replace([',', ';'], "\n", $ops['server_custom_files_list'])) as $cf) {
                $cf = trim(preg_replace('/[^A-Za-z0-9_\-\.\/]/', '', trim($cf)), '/');
                if ($cf === '' || strpos($cf, '..') !== false) continue;
                $files[] = $q($cf);
            }
            if ($files) {
                $r[] = '# Tegatai: blocked files';
                $r[] = 'RewriteRule ^(' . implode('|', $files) . ')$ - [F,L]';
            }
        }

        if ($on('server_hotlink_protection')) {
            // Same as nginx "valid_referers none blocked server_names <whitelist>":
            // requests without a referrer or with a referrer that is not a URL stay allowed.
            $r[] = '# Tegatai: hotlink protection';
            $r[] = 'RewriteCond %{HTTP_REFERER} ^https?:// [NC]';
            $r[] = 'RewriteCond %{HTTP_HOST}@@%{HTTP_REFERER} !^([^@:]*)(:[0-9]+)?@@https?://\1(:[0-9]+)?(/|$) [NC]';
            $hosts = [];
            $home_host = (string) wp_parse_url(home_url(), PHP_URL_HOST);
            if ($home_host !== '') $hosts[] = strtolower($home_host);
            if (!empty($ops['server_hotlink_whitelist']) && is_string($ops['server_hotlink_whitelist'])) {
                foreach (explode("\n", str_replace([',', ';'], "\n", $ops['server_hotlink_whitelist'])) as $entry) {
                    $clean = self::tegatai_sanitize_valid_referer_entry($entry);
                    if ($clean !== '') $hosts[] = $clean;
                }
            }
            foreach (array_unique($hosts) as $h) {
                if (strpos($h, '*.') === 0) {
                    $re = '([^/@]+\.)?' . $q(substr($h, 2));
                } else {
                    $re = $q($h);
                }
                $r[] = 'RewriteCond %{HTTP_REFERER} !^https?://' . $re . '(:[0-9]+)?(/|$) [NC]';
            }
            $r[] = 'RewriteRule \.(jpe?g|png|gif|webp|svg|mp4|mp3)$ - [F,L,NC]';
        }

        // WP Masking comes last (after the blocks above), as in the nginx file.
        if (class_exists('Tegatai_Mask')) {
            $r = array_merge($r, Tegatai_Mask::apache_lines());
        }

        $r[] = '</IfModule>';

        // Security headers also for responses without PHP (page caches, static files, error pages).
        // Apache keeps two header tables: PHP-FPM (proxy_fcgi) puts its headers into the one that
        // "Header always" works on, mod_php into the normal one. "Header unset" clears the normal
        // copy and "Header always set" replaces the other, so every header is sent once - also
        // on error pages, which only get the "always" table.
        // Browsers ignore HSTS on plain HTTP responses, so it needs no HTTPS condition here.
        $headers = class_exists('Tegatai_Headers') ? Tegatai_Headers::enabled($ops, true) : [];
        if ($headers) {
            $r[] = '<IfModule mod_headers.c>';
            $r[] = '# Tegatai: security headers';
            foreach ($headers as $name => $value) {
                $r[] = 'Header unset ' . $name;
                $r[] = 'Header always set ' . $name . ' "' . str_replace('"', '\"', $value) . '"';
            }
            $r[] = '</IfModule>';
        }
        return $r;
    }

    // insert_with_markers() appends a new block at the end of the file. WordPress' own block ends
    // every request for a page with [L] (rewrite to index.php), so rules after it only ever see
    // static files. The Tegatai block is therefore moved directly in front of "# BEGIN WordPress";
    // other blocks keep their order, and later writes (by WordPress or Tegatai) replace the blocks
    // in place.
    private static function place_before_wordpress_block($file) {
        $c = @file_get_contents($file);
        if (!is_string($c)) return;
        $begin = '# BEGIN Tegatai-Secure';
        $end = '# END Tegatai-Secure';
        $a = strpos($c, $begin);
        $wp = strpos($c, '# BEGIN WordPress');
        if ($a === false || $wp === false || $wp > $a) return;
        $b = strpos($c, $end, $a);
        if ($b === false) return;
        $b += strlen($end);
        $block = substr($c, $a, $b - $a);
        $rest = substr($c, 0, $a) . substr($c, $b);
        $rest = rtrim($rest, "\r\n") . "\n";
        $wp = strpos($rest, '# BEGIN WordPress');
        $out = substr($rest, 0, $wp) . $block . "\n\n" . substr($rest, $wp);
        @file_put_contents($file, $out, LOCK_EX);
    }

    // Writes the Apache / LiteSpeed rules into WordPress' .htaccess and stores the result
    // (['ok' => bool, 'path' => string, 'error' => string, 'time' => int]).
    public static function write_apache_rules() {
        require_once ABSPATH . 'wp-admin/includes/misc.php';
        $file = self::htaccess_file();
        $rules = self::generate_apache_rules();
        $error = '';
        if (file_exists($file) ? !wp_is_writable($file) : !wp_is_writable(dirname($file))) {
            $error = file_exists($file) ? 'file is not writable' : 'directory is not writable';
        } elseif (!insert_with_markers($file, 'Tegatai-Secure', $rules)) {
            $error = 'write failed';
        } else {
            self::place_before_wordpress_block($file);
        }
        $status = ['ok' => $error === '', 'path' => $file, 'error' => $error === '' ? '' : $file . ': ' . $error, 'time' => time()];
        update_option('tegatai_htaccess_status', $status, false);
        if ($error !== '' && self::detect_server() === 'apache' && class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('INFO', '.htaccess rules could not be written: ' . $status['error']);
        }
        return $status;
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

    /**
     * nginx does not read any file on its own; the rules only become active through an
     * "include" line in the server block, which can point anywhere. The file is therefore
     * kept in Tegatai's protected data folder below the uploads directory
     * (uploads/tegatai-secure/server/tegatai-nginx.conf), never in the WordPress root.
     */
    public static function get_rules_file_path() {
        return trailingslashit(tegatai_server_dir()) . 'tegatai-nginx.conf';
    }

    // Locations used by older versions (WordPress root, uploads root). Only read, never written:
    // the admin is told to point the nginx include to the new file.
    public static function legacy_rules_files() {
        $out = [];
        $home = self::home_dir();
        if ($home !== '' && file_exists($home . 'tegatai-nginx.conf')) $out[] = $home . 'tegatai-nginx.conf';
        $ud = wp_upload_dir(null, false);
        $up = trailingslashit($ud['basedir']) . 'tegatai-nginx.conf';
        if (file_exists($up)) $out[] = $up;
        // 2.2.1
        $up = trailingslashit($ud['basedir']) . 'tegatai-server/tegatai-nginx.conf';
        if (file_exists($up)) $out[] = $up;
        return $out;
    }

    // Directory that holds WordPress' own .htaccess (same function core uses for it).
    private static function home_dir() {
        if (!function_exists('get_home_path')) require_once ABSPATH . 'wp-admin/includes/file.php';
        return trailingslashit(get_home_path());
    }

    private static function htaccess_file() {
        return self::home_dir() . '.htaccess';
    }

    public static function detect_server() { 
        $s = isset($_SERVER['SERVER_SOFTWARE']) ? sanitize_text_field(wp_unslash($_SERVER['SERVER_SOFTWARE'])) : '';
        if (stripos($s, 'apache') !== false || stripos($s, 'litespeed') !== false) return 'apache';
        if (stripos($s, 'nginx') !== false) return 'nginx';
        return 'unknown'; 
    }

    // Writes all server rules and returns the result of the nginx file write
    // (['ok' => bool, 'path' => string, 'error' => string, 'bytes' => int, 'time' => int]).
    // On Apache / LiteSpeed the result of the .htaccess write is returned instead.
    public static function force_update() {
        $status = self::write_nginx_rules();
        $ht = self::write_apache_rules();
        return self::detect_server() === 'apache' ? $ht : $status;
    }

    // Result of the last write, used by the "Server" tab (the .htaccess result on Apache / LiteSpeed).
    public static function rules_status() {
        $st = get_option(self::detect_server() === 'apache' ? 'tegatai_htaccess_status' : 'tegatai_rules_status', []);
        return is_array($st) ? $st : [];
    }

    public static function has_rules() {
        $ht = self::htaccess_file();
        return file_exists(self::get_rules_file_path())
            || (bool) self::legacy_rules_files()
            || (file_exists($ht) && strpos((string) @file_get_contents($ht), '# BEGIN Tegatai-Secure') !== false);
    }

    // Called on deactivation. The nginx file is emptied instead of deleted: nginx refuses to
    // start or reload when an "include" points to a missing file. The flag lets the next
    // activation (also of a renamed plugin folder) write the rules again.
    public static function remove_rules() {
        if (self::has_rules()) update_option('tegatai_restore_rules', 1, false);

        $stub = "# Tegatai Secure is deactivated - no rules active.\n# The rules are written again when the plugin is activated.\n";
        $file = self::get_rules_file_path();
        if (file_exists($file)) { @file_put_contents($file, $stub); }

        $ud = wp_upload_dir(null, false);

        // write_apache_rules() uses insert_with_markers(..., 'Tegatai-Secure'), i.e. "# BEGIN Tegatai-Secure".
        // "TEGATAI" / "TEGATAI UPLOADS" are markers written by older versions.
        self::remove_marker_blocks(self::htaccess_file(), ['Tegatai-Secure', 'TEGATAI']);
        self::remove_marker_blocks(trailingslashit($ud['basedir']) . '.htaccess', ['TEGATAI UPLOADS']);
    }

    private static function remove_marker_blocks($file, array $markers) {
        if (!file_exists($file) || !wp_is_writable($file)) return;
        $cur = @file_get_contents($file);
        if ($cur === false) return;

        $new = $cur;
        foreach ($markers as $marker) {
            $m = preg_quote($marker, '/');
            // Whole lines only, so "TEGATAI" never matches "TEGATAI UPLOADS".
            $new = preg_replace('/^# BEGIN ' . $m . '[ \t]*\R.*?^# END ' . $m . '[ \t]*(\R|$)/ms', '', $new);
        }
        if ($new !== null && $new !== $cur) {
            @file_put_contents($file, $new, LOCK_EX);
        }
    }

    /**
     * Folders of older versions in uploads, denied as long as they may exist. "tegatai-secure" is
     * left out where it is the plugin folder itself (uploads folder = plugins folder).
     */
    private static function old_data_dir_names() {
        $names = ['tegatai-backups', 'tegatai-logs', 'tegatai-quarantine', 'tegatai-server', 'tegatai-geoip'];
        if (tegatai_data_dir_name() !== 'tegatai-secure') {
            $plugin_in_uploads = untrailingslashit(wp_normalize_path(TEGATAI_PATH)) === untrailingslashit(wp_normalize_path(trailingslashit(wp_upload_dir(null, false)['basedir']) . 'tegatai-secure'));
            if (!$plugin_in_uploads) $names[] = 'tegatai-secure';
        }
        return $names;
    }

    // Folder of the 2.2.1 nginx file.
    public static function old_server_dir() {
        return trailingslashit(wp_upload_dir(null, false)['basedir']) . 'tegatai-server';
    }

    // URL of the include check (answered by the current rules file only).
    private static function include_check_url() {
        return trailingslashit(wp_upload_dir(null, false)['baseurl']) . tegatai_data_dir_name() . '/server/include-check';
    }

    /**
     * Exact-match location that answers the include check. Exact locations ("=") are matched
     * before the "^~" block that denies the data folder.
     */
    private static function include_check_line() {
        $path = self::url_path(self::include_check_url());
        return 'location = "' . $path . '" { access_log off; default_type text/plain; return 200 "tegatai-include-ok"; }';
    }

    /**
     * Whether the running nginx uses the current rules file, checked over HTTP:
     * 'yes' = the include check is answered, 'no' = it is not (include points elsewhere or nginx
     * was not reloaded), 'unknown' = the site cannot reach itself or the server is not nginx.
     * Cached 12 hours ('no' and 'unknown' one hour), cleared when the rules are written.
     */
    public static function include_state() {
        if (self::detect_server() !== 'nginx' || !file_exists(self::get_rules_file_path())) return 'unknown';
        $cached = get_transient('tegatai_include_check');
        if (is_array($cached) && isset($cached['state'])) return (string) $cached['state'];
        $r = wp_remote_get(self::include_check_url(), ['timeout' => 5, 'redirection' => 0, 'sslverify' => false]);
        if (is_wp_error($r)) {
            $state = 'unknown';
        } else {
            $state = ((int) wp_remote_retrieve_response_code($r) === 200 && trim((string) wp_remote_retrieve_body($r)) === 'tegatai-include-ok') ? 'yes' : 'no';
        }
        set_transient('tegatai_include_check', ['state' => $state, 'time' => time()], $state === 'yes' ? 12 * HOUR_IN_SECONDS : HOUR_IN_SECONDS);
        return $state;
    }

    // Time of the last include check (0 = none).
    public static function include_check_time() {
        $cached = get_transient('tegatai_include_check');
        return is_array($cached) ? (int) ($cached['time'] ?? 0) : 0;
    }

    /**
     * Removes uploads/tegatai-server/ (nginx file of 2.2.1). Only on request of the admin (Server
     * tab), never on its own: PHP cannot see whether another server block still includes the
     * old file, and nginx does not start or reload when an included file is missing. On nginx
     * a fresh include check must show that nginx uses the new file. Only Tegatai's own files are
     * deleted. Returns '' on success, otherwise the reason.
     */
    public static function remove_old_server_dir() {
        $old = self::old_server_dir();
        if (!is_dir($old) || is_link($old)) return '';
        if (self::detect_server() === 'nginx') {
            delete_transient('tegatai_include_check');
            if (self::include_state() !== 'yes') return 'nginx does not use the new file yet';
        }
        foreach (['tegatai-nginx.conf', '.htaccess', 'index.php', 'index.html', 'web.config'] as $f) {
            if (is_file($old . '/' . $f)) wp_delete_file($old . '/' . $f);
        }
        @rmdir($old); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- only succeeds when the folder is empty
        if (is_dir($old)) {
            return 'folder not empty or not writable: ' . implode(', ', array_slice(array_diff((array) @scandir($old), ['.', '..']), 0, 5));
        }
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('INFO', 'Old nginx folder removed: ' . $old);
        return '';
    }

    private static function write_nginx_rules() {
        $file_path = self::get_rules_file_path();
        // Own folder below uploads, protected for Apache/IIS; nginx denies it via the rules themselves.
        tegatai_protect_directory(tegatai_data_dir());
        tegatai_protect_directory(tegatai_server_dir());
        delete_transient('tegatai_dir_check'); // re-check the web access to the data folder
        delete_transient('tegatai_include_check'); // re-check which file nginx uses
        $rules = self::generate_nginx_content();
        
        $end_marker = "# --- END TEGATAI RULES ---";
        $pos = strpos($rules, $end_marker);
        if ($pos !== false) {
            $rules = substr($rules, 0, $pos + strlen($end_marker)) . "\n";
        }

        // Same target and write call as before (no extra locations); only the result is reported now.
        if (function_exists('error_clear_last')) error_clear_last();
        $bytes = @file_put_contents($file_path, $rules);
        $write_error = error_get_last();
        // Tegatai 2.2.1 wrote the file to uploads/tegatai-server/. As long as that folder exists
        // (removed with the button in the Server tab), the file is kept up to date with the same
        // rules, also when the new file could not be written, so an include that still points
        // there keeps working. The include check location is left
        // out there: only the new file answers it.
        $old_up = self::old_server_dir() . '/tegatai-nginx.conf';
        if (is_file($old_up) && wp_is_writable($old_up)) {
            @file_put_contents($old_up, str_replace(self::include_check_line() . "\n", '', $rules));
        }
        if ($bytes !== false && $bytes === strlen($rules)) {
            $status = ['ok' => true, 'path' => $file_path, 'error' => '', 'bytes' => (int) $bytes, 'time' => time()];
            update_option('tegatai_rules_status', $status, false);
            return $status;
        }
        $reason = $write_error['message'] ?? '';
        if ($reason === '') {
            $dir = dirname($file_path);
            if (!is_dir($dir)) $reason = 'directory does not exist';
            elseif (file_exists($file_path) && !wp_is_writable($file_path)) $reason = 'file is not writable (owner ' . @fileowner($file_path) . ', mode ' . substr(sprintf('%o', @fileperms($file_path)), -4) . ')';
            elseif (!wp_is_writable($dir)) $reason = 'directory is not writable';
            else $reason = 'unknown write error';
        }
        $errors = [$file_path . ': ' . $reason];
        $status = ['ok' => false, 'path' => $file_path, 'error' => implode(' | ', $errors), 'bytes' => 0, 'time' => time()];
        update_option('tegatai_rules_status', $status, false);
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('INFO', 'nginx rules could not be written: ' . $status['error']);
        return $status;
    }

    /**
     * Security headers for nginx (server block level), so they also reach responses without
     * PHP: pages from a page cache, static files, error pages.
     * fastcgi_hide_header / proxy_hide_header drop the copy PHP sends, add_header sends the
     * header once for every response ("always" includes error pages).
     * nginx rule: a location with its own add_header does not inherit these lines.
     */
    private static function nginx_header_lines($ops) {
        if (!class_exists('Tegatai_Headers')) return [];
        // Browsers ignore HSTS on plain HTTP responses, so it needs no HTTPS condition here.
        $headers = Tegatai_Headers::enabled($ops, true);
        if (!$headers) return [];

        $lines = [];
        $lines[] = "# Security headers (also for cached pages and static files).";
        $lines[] = "# A location with its own add_header does not inherit them (nginx rule).";
        foreach ($headers as $name => $value) {
            $lines[] = 'fastcgi_hide_header ' . $name . '; proxy_hide_header ' . $name . ';';
            $lines[] = 'add_header ' . $name . ' "' . str_replace('"', '\"', $value) . '" always;';
        }
        $lines[] = "";
        return $lines;
    }

    private static function generate_nginx_content() {
        $ops = tegatai_get_setting('tegatai_options');
        $date = current_time('mysql');
        
        // nginx matches the request URI, so all locations are built from URL paths (subdirectory installs,
        // custom WP_CONTENT_DIR/UPLOADS layouts), never from filesystem paths.
        $ud = wp_upload_dir();
        $up_dir = preg_quote(self::url_path($ud['baseurl']));
        $pl_dir = preg_quote(self::url_path(tegatai_plugins_url()));
        $th_dir = preg_quote(self::url_path(get_theme_root_uri()));
        $ct_dir = preg_quote(self::url_path(content_url()));

        $lines = [];
        $lines[] = "# --- TEGATAI SECURITY RULES ($date) ---";
        $lines[] = "# Include this file in your Nginx server block:";
        $lines[] = "# include " . self::get_rules_file_path() . ";";
        $lines[] = "";

        // Always written: Tegatai's data folder (logs, backups, server rules, GeoIP database) and
        // the folders of older versions. "^~" prefix locations win over every regex location of
        // the server block (e.g. static file rules for .html/.json), whatever their order.
        $up_path = untrailingslashit(self::url_path($ud['baseurl']));
        $ct_path = untrailingslashit(self::url_path(content_url()));
        $deny = ' { deny all; access_log off; log_not_found off; return 403; }';
        $lines[] = "# Tegatai data folder: never reachable from the web";
        $lines[] = 'location ^~ "' . $up_path . '/' . tegatai_data_dir_name() . '/"' . $deny;
        foreach (self::old_data_dir_names() as $old_dir) {
            $lines[] = 'location ^~ "' . $up_path . '/' . $old_dir . '/"' . $deny;
        }
        $lines[] = "# Answers Tegatai's check whether nginx uses this file";
        $lines[] = self::include_check_line();
        $lines[] = 'location ^~ "' . $ct_path . '/tegatai-quarantine/"' . $deny;
        $lines[] = "";

        $lines = array_merge($lines, self::nginx_header_lines($ops));

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
            // /.well-known/ stays reachable (ACME HTTP-01, security.txt, app links)
            $lines[] = "location ~ /\.(?!well-known/) { deny all; access_log off; log_not_found off; return 403; }";
        }

        if (!empty($ops['server_block_xmlrpc'])) {
            $lines[] = "location = /xmlrpc.php { deny all; access_log off; log_not_found off; return 403; }";
        }


        if (!empty($ops['server_disable_php_uploads'])) {
            $lines[] = "location ~ ^" . $up_dir . "/.+\.php$ { deny all; access_log off; log_not_found off; return 403; }";
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
        // Plugins and themes: blocked unless allowed; files on the exception list stay reachable
        // (they never match the deny location and fall through to the normal PHP location).
        if (self::block_plugin_php($ops)) {
            $la = self::php_exception_lookahead(self::php_exceptions($ops));
            if (!empty($pl_dir)) {
                $lines[] = "location ~ ^" . $pl_dir . "/" . $la . ".*\." . $phpre . "$ { deny all; }";
            }
            if (!empty($th_dir)) {
                $lines[] = "location ~ ^" . $th_dir . "/" . $la . ".*\." . $phpre . "$ { deny all; }";
            }
        }

        $lines[] = "";

        // WP Masking comes last: its rewrites end the server-level rule processing with "last",
        // so the bot filter above still applies to every request.
        if (class_exists('Tegatai_Mask')) {
            $lines = array_merge($lines, Tegatai_Mask::nginx_lines());
        }

        $lines[] = "# --- END TEGATAI RULES ---";

        return implode("\n", $lines);
    }
}
