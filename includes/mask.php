<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * WP Masking: hides the WordPress structure in the HTML that visitors receive.
 *
 * - Plugin and theme paths (/<plugins>/<folder>/, /<themes>/<slug>/) become /<base>/<alias>/.
 * - /wp-includes/ becomes /<includes alias>/, /wp-json/ /<rest alias>/, admin-ajax.php /<ajax alias>.
 * - Version parameters, script/style ids, generator tags, RSD/wlwmanifest/shortlink/REST links,
 *   the emoji script, the speculation rules and the X-Pingback header are removed.
 * - Original paths can be blocked for visitors (logged-in users keep access).
 *
 * - File names can be replaced by a neutral name per file (the folders stay, so relative URLs in
 *   CSS and JS keep working).
 *
 * nginx maps the new paths back to the real files (rules in tegatai-nginx.conf). The HTML is only
 * rewritten for entries whose new path was verified with a loopback request, so a missing nginx
 * reload never breaks the site. Blocking only covers verified entries for the same reason.
 */
class Tegatai_Mask {
    const SNAPSHOT_OPTION = 'tegatai_mask_snapshot';
    const STATUS_OPTION   = 'tegatai_mask_status';
    // Static file types that are served through the new paths (never PHP)
    const EXT = 'css|js|mjs|map|json|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|txt|xml';
    // Hidden file names: new name per file, e.g. /assets/bar/css/t3f9a0c1d2e4
    const FILES_OPTION = 'tegatai_mask_files';
    const FILES_CRON   = 'tegatai_mask_files_check';
    const TOKEN_RE     = 't[0-9a-f]{11}';
    // Replaced names (file changed) stay mapped this long for cached pages
    const FILES_KEEP   = 30 * DAY_IN_SECONDS;
    const RESERVED = ['wp-admin', 'wp-content', 'wp-includes', 'wp-json', 'wp-login', 'feed', 'comments', 'xmlrpc'];

    // tegatai_get_setting() keeps its own per-request cache, which is updated on save
    public static function ops() {
        $ops = tegatai_get_setting('tegatai_options', []);
        return is_array($ops) ? $ops : [];
    }

    public static function on($key) {
        $ops = self::ops();
        return !empty($ops['server_mask_' . $key]);
    }

    // ------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------

    private static function slug($value, $default) {
        $value = strtolower(trim((string) $value));
        $value = preg_replace('/[^a-z0-9\-]/', '', $value);
        if ($value === '' || in_array($value, self::RESERVED, true) || strpos($value, 'wp-') === 0) return $default;
        return substr($value, 0, 40);
    }

    public static function base()     { $o = self::ops(); return self::slug($o['server_mask_base'] ?? '', 'assets'); }
    public static function inc_alias() { $o = self::ops(); return self::slug($o['server_mask_includes'] ?? '', 'lib'); }
    public static function rest_alias(){ $o = self::ops(); return self::slug($o['server_mask_rest'] ?? '', 'api'); }
    public static function ajax_alias(){ $o = self::ops(); return self::slug($o['server_mask_ajax'] ?? '', 'ajax'); }

    // URL path without trailing slash, e.g. "/puraguin"
    private static function path($url) {
        return rtrim((string) wp_parse_url($url, PHP_URL_PATH), '/');
    }

    public static function home_path()     { return self::path(home_url('/')); }
    public static function host()          { return (string) wp_parse_url(home_url('/'), PHP_URL_HOST); }
    public static function plugins_path()  { return self::path(plugins_url()); }
    public static function themes_path()   { return self::path(get_theme_root_uri()); }
    public static function includes_path() { return self::path(includes_url()); }
    public static function ajax_path()     { return (string) wp_parse_url(admin_url('admin-ajax.php'), PHP_URL_PATH); }

    // Folders of the active plugins (single-file plugins have no folder and no assets of their own)
    public static function plugin_folders() {
        $list = (array) get_option('active_plugins', []);
        if (is_multisite()) $list = array_merge($list, array_keys((array) get_site_option('active_sitewide_plugins', [])));
        $out = [];
        foreach ($list as $p) {
            $dir = dirname((string) $p);
            if ($dir !== '.' && $dir !== '' && preg_match('/^[A-Za-z0-9._\-]+$/', $dir)) $out[$dir] = $dir;
        }
        ksort($out, SORT_NATURAL | SORT_FLAG_CASE);
        return array_values($out);
    }

    public static function theme_slugs() {
        return array_values(array_unique(array_filter([get_stylesheet(), get_template()])));
    }

    // Stable short alias used until an own name is saved, e.g. "x3f9a"
    public static function auto_alias($key) {
        return 'x' . substr(md5(wp_salt('auth') . '|' . $key), 0, 4);
    }

    /**
     * Current aliases: ['plugin:<folder>' => alias, 'theme:<slug>' => alias].
     * Saved names win; entries without a name get the automatic alias. Duplicates get a suffix.
     */
    public static function aliases() {
        $ops = self::ops();
        $saved = isset($ops['server_mask_aliases']) && is_array($ops['server_mask_aliases']) ? $ops['server_mask_aliases'] : [];
        $keys = [];
        foreach (self::plugin_folders() as $f) $keys[] = 'plugin:' . $f;
        foreach (self::theme_slugs() as $t) $keys[] = 'theme:' . $t;

        $taken = [self::inc_alias(), self::rest_alias(), self::ajax_alias()];
        $out = [];
        foreach ($keys as $k) {
            $a = self::slug($saved[$k] ?? '', self::auto_alias($k));
            $base = $a; $n = 2;
            while (in_array($a, $taken, true)) { $a = $base . '-' . $n++; }
            $taken[] = $a;
            $out[$k] = $a;
        }
        return $out;
    }

    // Real URL path of an alias key, e.g. "/puraguin/kanri"
    public static function real_path($key) {
        list($type, $name) = array_pad(explode(':', $key, 2), 2, '');
        return ($type === 'theme' ? self::themes_path() : self::plugins_path()) . '/' . $name;
    }

    // Verified entries: only these are rewritten in the HTML and blocked by nginx.
    public static function snapshot() {
        $s = get_option(self::SNAPSHOT_OPTION, []);
        $s = is_array($s) ? $s : [];
        // paths: [key => "<base>/<alias>"], old: [key => earlier paths], includes/ajax: alias ('' = not masked)
        return [
            'paths'    => is_array($s['paths'] ?? null) ? $s['paths'] : [],
            'old'      => is_array($s['old'] ?? null) ? $s['old'] : [],
            'includes' => (string) ($s['includes'] ?? ''),
            'ajax'     => (string) ($s['ajax'] ?? ''),
        ];
    }

    // ------------------------------------------------------------------
    // Requests on the new paths
    // ------------------------------------------------------------------

    // Runs while the plugin file is loaded, before the firewall and WordPress read the request URI.
    public static function boot() {
        if (self::on('core')) {
            $uri  = isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput -- only compared and remapped, never output
            $home = self::home_path();

            // /<rest>/... is answered by the REST API like /wp-json/...
            $rest = $home . '/' . self::rest_alias();
            if ($uri === $rest || strpos($uri, $rest . '/') === 0 || strpos($uri, $rest . '?') === 0) {
                $_SERVER['REQUEST_URI'] = $home . '/wp-json' . substr($uri, strlen($rest));
            }

            // nginx sends /<ajax> to admin-ajax.php; the URI is mapped so checks see the real endpoint
            $snap = self::snapshot();
            if ($snap['ajax'] !== '' && wp_doing_ajax()) {
                $ajax = $home . '/' . $snap['ajax'];
                if ($uri === $ajax || strpos($uri, $ajax . '?') === 0) {
                    $_SERVER['REQUEST_URI'] = self::ajax_path() . substr($uri, strlen($ajax));
                }
            }
        }

        add_action('init', [__CLASS__, 'init'], 1);
    }

    public static function init() {
        if (self::on('core')) {
            add_filter('rest_url', [__CLASS__, 'filter_rest_url'], 99);
        }

        // New file names found in the pages are added to the rules and checked hourly
        add_action(self::FILES_CRON, [__CLASS__, 'cron_files']);
        if (self::on('files') && !wp_next_scheduled(self::FILES_CRON)) {
            wp_schedule_event(time() + 300, 'hourly', self::FILES_CRON);
        } elseif (!self::on('files') && wp_next_scheduled(self::FILES_CRON)) {
            wp_clear_scheduled_hook(self::FILES_CRON);
        }

        if (self::on('strip')) {
            remove_action('wp_head', 'wp_generator');
            remove_action('wp_head', 'rsd_link');
            remove_action('wp_head', 'wlwmanifest_link');
            remove_action('wp_head', 'wp_shortlink_wp_head');
            remove_action('wp_head', 'rest_output_link_wp_head');
            remove_action('template_redirect', 'rest_output_link_header', 11);
            remove_action('template_redirect', 'wp_shortlink_header', 11);
            remove_action('wp_head', 'print_emoji_detection_script', 7);
            remove_action('wp_print_styles', 'print_emoji_styles');
            remove_action('wp_enqueue_scripts', 'wp_enqueue_emoji_styles');
            add_filter('the_generator', '__return_empty_string');
            add_filter('wp_headers', [__CLASS__, 'filter_headers']);
            // The speculation rules list the WordPress paths (/wp-admin/, /wp-content/plugins/ ...)
            add_filter('wp_speculation_rules_configuration', '__return_null');
            if (!is_admin()) {
                add_filter('style_loader_src', [__CLASS__, 'strip_ver'], 99);
                add_filter('script_loader_src', [__CLASS__, 'strip_ver'], 99);
            }
        }

        if (self::on('paths') || self::on('core') || self::on('strip')) {
            // Late priority: this buffer is processed before buffers that were started earlier
            // (page caches), so cached pages contain the masked HTML.
            add_action('template_redirect', [__CLASS__, 'start_buffer'], PHP_INT_MAX - 10);
            add_action('login_init', [__CLASS__, 'start_buffer'], 1);
        }
    }

    public static function filter_rest_url($url) {
        $from = self::home_path() . '/wp-json/';
        $to   = self::home_path() . '/' . self::rest_alias() . '/';
        return str_replace($from, $to, (string) $url);
    }

    public static function filter_headers($headers) {
        unset($headers['X-Pingback']);
        return $headers;
    }

    public static function strip_ver($src) {
        return is_string($src) ? remove_query_arg('ver', $src) : $src;
    }

    public static function start_buffer() {
        if (is_admin() || wp_doing_ajax() || (defined('REST_REQUEST') && REST_REQUEST) || is_feed() || is_robots()) return;
        ob_start([__CLASS__, 'process']);
    }

    // ------------------------------------------------------------------
    // HTML rewriting
    // ------------------------------------------------------------------

    // [from path => to path] for the verified entries, longest first
    public static function replacements() {
        $map  = [];
        $home = self::home_path();
        $snap = self::snapshot();

        if (self::on('paths')) {
            foreach ($snap['paths'] as $key => $new) {
                $map[self::real_path($key) . '/'] = $home . '/' . $new . '/';
            }
        }
        if (self::on('core')) {
            if ($snap['includes'] !== '') $map[self::includes_path() . '/'] = $home . '/' . $snap['includes'] . '/';
            if ($snap['ajax'] !== '') $map[self::ajax_path()] = $home . '/' . $snap['ajax'];
            $map[$home . '/wp-json/'] = $home . '/' . self::rest_alias() . '/';
        }
        uksort($map, static function ($a, $b) { return strlen($b) - strlen($a); });
        return $map;
    }

    public static function process($html) {
        if (!is_string($html) || $html === '' || strpos($html, '<') === false) return $html;
        // Only HTML documents (no JSON, XML, files)
        foreach (headers_list() as $h) {
            if (stripos($h, 'content-type:') === 0 && stripos($h, 'text/html') === false) return $html;
        }

        $map = self::replacements();
        if ($map) {
            $hosts = [];
            $parts = wp_parse_url(home_url());
            $host = ($parts['host'] ?? '') . (isset($parts['port']) ? ':' . $parts['port'] : '');
            foreach (['https://', 'http://', '//'] as $scheme) $hosts[] = $scheme . $host;

            foreach ($map as $from => $to) {
                // Absolute URLs of this site, also JSON-escaped (inline script data)
                foreach ($hosts as $h) {
                    $html = str_replace($h . $from, $h . $to, $html);
                    $html = str_replace(str_replace('/', '\/', $h . $from), str_replace('/', '\/', $h . $to), $html);
                }
                // Root-relative URLs in attributes, CSS url() and script strings
                $html = preg_replace('#(["\'(=,\s])' . preg_quote($from, '#') . '#', '$1' . $to, $html);
                $html = preg_replace('#(["\'(=,\s])' . preg_quote(str_replace('/', '\/', $from), '#') . '#', '$1' . str_replace('/', '\/', $to), $html);
            }
        }

        if (self::on('files')) {
            $html = self::tokenize($html);
        }

        if (self::on('strip')) {
            $html = preg_replace('#<meta\s+name=(["\'])generator\1[^>]*>\s*#i', '', $html);
            $html = preg_replace_callback('#<(?:link|script|style)\b[^>]*>#i', [__CLASS__, 'clean_tag'], $html);
        }
        return $html;
    }

    // Removes WordPress handle ids and version parameters from link/script/style tags
    public static function clean_tag($m) {
        $tag = $m[0];
        $tag = preg_replace('#\s+id=(["\'])[\w\-]+-(?:css|js|js-extra|js-before|js-after|js-translations|inline-css)\1#i', '', $tag);
        $tag = preg_replace_callback('#\s(href|src)=(["\'])([^"\']*)\2#i', static function ($a) {
            $url = $a[3];
            if (stripos($url, 'ver=') === false) return $a[0];
            $url = preg_replace('#([?&]|&amp;|&\#038;)ver=[^&"\'\#]*#i', '$1', $url);
            $url = preg_replace('#(\?)(?:&amp;|&\#038;|&)+#', '$1', $url);
            $url = preg_replace('#(?:&amp;|&\#038;|&)+(?=$|\#)#', '', $url);
            $url = preg_replace('#\?(?=$|\#)#', '', $url);
            return ' ' . $a[1] . '=' . $a[2] . $url . $a[2];
        }, $tag);
        return $tag;
    }

    // ------------------------------------------------------------------
    // nginx rules (part of tegatai-nginx.conf)
    // ------------------------------------------------------------------

    public static function nginx_lines() {
        $paths = self::on('paths');
        $core  = self::on('core');
        $block = self::on('block');
        if (!$paths && !$core) return [];

        $home = self::home_path();
        $ext  = self::EXT;
        $snap = self::snapshot();
        $lines = [];
        $lines[] = '# WP Masking: new paths are mapped to the real files (static files only, never PHP)';

        if ($paths) {
            // Current and verified paths, so renaming never breaks pages that still use the old name
            $pairs = [];
            foreach (self::aliases() as $key => $alias) $pairs[] = [$key, self::base() . '/' . $alias];
            foreach ($snap['paths'] as $key => $new) $pairs[] = [$key, $new];
            // Earlier names stay mapped, so cached pages that still use them keep working
            foreach ($snap['old'] as $key => $list) foreach ((array) $list as $new) $pairs[] = [$key, (string) $new];
            $done = [];
            foreach ($pairs as $pair) {
                list($key, $new) = $pair;
                $from = $home . '/' . $new . '/';
                if (isset($done[$from])) continue;
                $done[$from] = 1;
                $lines[] = 'rewrite "^' . preg_quote($from) . '(.+\.(?:' . $ext . '))$" ' . self::real_path($key) . '/$1 last;';
            }
        }
        if ($core) {
            foreach (array_unique(array_filter([self::inc_alias(), $snap['includes']])) as $inc) {
                $lines[] = 'rewrite "^' . preg_quote($home . '/' . $inc . '/') . '(.+\.(?:' . $ext . '))$" ' . self::includes_path() . '/$1 last;';
            }
            foreach (array_unique(array_filter([self::ajax_alias(), $snap['ajax']])) as $ajax) {
                $lines[] = 'rewrite "^' . preg_quote($home . '/' . $ajax) . '$" ' . self::ajax_path() . ' last;';
            }
        }

        if ($block) {
            $orig = [];
            if ($paths) {
                foreach (array_keys($snap['paths']) as $key) $orig[] = preg_quote(ltrim(self::real_path($key), '/')) . '/';
            }
            if ($core && $snap['includes'] !== '') $orig[] = preg_quote(ltrim(self::includes_path(), '/')) . '/';
            if ($core) $orig[] = preg_quote(ltrim($home . '/wp-json/', '/')) . '(?!tegatai/)';
            if ($orig) {
                $lines[] = '# WP Masking: direct requests for original paths answer 404 (logged-in users keep access).';
                $lines[] = '# The rewrites above stop here with "last", so the new paths are never blocked.';
                $lines[] = 'set $tegatai_mask_block "";';
                $lines[] = 'if ($request_uri ~* "^/(?:' . implode('|', $orig) . ')") { set $tegatai_mask_block "1"; }';
                $lines[] = 'if ($http_cookie ~* "wordpress_logged_in_") { set $tegatai_mask_block ""; }';
                // Files loaded by pages of this site send it as referer and stay reachable,
                // so pages that still contain an original path (cache, switch turned off) keep working
                $lines[] = 'if ($http_referer ~* "^https?://' . preg_quote(self::host()) . '(?::[0-9]+)?/") { set $tegatai_mask_block ""; }';
                $lines[] = 'if ($tegatai_mask_block) { return 404; }';
            }
        }

        if (self::on('files')) {
            $files = self::files();
            if ($files) {
                // Only requests ending in a file name token enter this location, all others skip it
                $lines[] = '# WP Masking: file names (new name -> real file)';
                $lines[] = 'location ~ "^' . preg_quote($home) . '/.+/' . self::TOKEN_RE . '$" {';
                foreach ($files as $token => $f) {
                    $target = self::file_base((string) $f['k']);
                    if ($target === '') continue;
                    $lines[] = '    rewrite "/' . $token . '$" ' . $target . '/' . $f['r'] . ' last;';
                }
                $lines[] = '    return 404;';
                $lines[] = '}';
            }
        }
        $lines[] = '';
        return $lines;
    }

    // ------------------------------------------------------------------
    // Verification (loopback requests on the new paths)
    // ------------------------------------------------------------------

    // First static file below a directory (depth 3), relative path
    private static function sample_file($dir) {
        $dir = rtrim($dir, '/\\');
        if (!is_dir($dir)) return '';
        $prefer = ['style.css'];
        foreach ($prefer as $p) if (is_file($dir . '/' . $p)) return $p;
        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS));
        $it->setMaxDepth(3);
        foreach ($it as $f) {
            if ($f->isFile() && preg_match('#\.(?:css|js|png|svg|gif|jpe?g|webp)$#i', $f->getFilename())) {
                $rel = ltrim(str_replace('\\', '/', substr($f->getPathname(), strlen($dir))), '/');
                if (preg_match('#^[A-Za-z0-9._\-/]+$#', $rel) && strpos($rel, 'node_modules/') === false) return $rel;
            }
        }
        return '';
    }

    private static function real_dir($key) {
        list($type, $name) = array_pad(explode(':', $key, 2), 2, '');
        return $type === 'theme' ? trailingslashit(get_theme_root()) . $name : trailingslashit(WP_PLUGIN_DIR) . $name;
    }

    private static function fetch($path) {
        $parts = wp_parse_url(home_url());
        $url = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '') . $path;
        // Logged-out request (no cookies): exactly what visitors get
        $r = wp_remote_get($url, ['timeout' => 10, 'redirection' => 0, 'sslverify' => apply_filters('https_local_ssl_verify', false), 'headers' => ['Cache-Control' => 'no-cache']]);
        if (is_wp_error($r)) return ['code' => 0, 'body' => '', 'error' => $r->get_error_message()];
        return ['code' => (int) wp_remote_retrieve_response_code($r), 'body' => (string) wp_remote_retrieve_body($r), 'error' => ''];
    }

    // Same bytes as the real file: the new path really serves that file
    private static function verify_file($new_path, $file) {
        if ($file === '' || !is_readable($file)) return __('no file to test', 'tegatai-secure');
        $res = self::fetch($new_path);
        if ($res['error'] !== '') return $res['error'];
        if ($res['code'] !== 200) return 'HTTP ' . $res['code'];
        if (md5($res['body']) !== md5_file($file)) return __('wrong content', 'tegatai-secure');
        return '';
    }

    /**
     * Tests every new path and stores the working ones as the snapshot.
     * Returns ['ok' => [...], 'failed' => [key => reason], 'time' => int].
     */
    public static function check() {
        $home = self::home_path();
        $base = self::base();
        $prev = self::snapshot();
        $snap = ['paths' => [], 'old' => $prev['old'], 'includes' => '', 'ajax' => ''];
        $ok = []; $failed = []; $skipped = [];

        if (self::on('paths')) {
            foreach (self::aliases() as $key => $alias) {
                $dir = self::real_dir($key);
                $rel = self::sample_file($dir);
                if ($rel === '') { $skipped[] = $key; continue; } // nothing to serve, nothing to hide
                $new = $base . '/' . $alias;
                $err = self::verify_file($home . '/' . $new . '/' . $rel, $dir . '/' . $rel);
                if ($err === '') { $snap['paths'][$key] = $new; $ok[] = $key; continue; }
                $failed[$key] = $err;
                // A renamed entry keeps its previous path while that one still works (nginx not reloaded yet)
                if (isset($prev['paths'][$key]) && $prev['paths'][$key] !== $new
                    && self::verify_file($home . '/' . $prev['paths'][$key] . '/' . $rel, $dir . '/' . $rel) === '') {
                    $snap['paths'][$key] = $prev['paths'][$key];
                }
            }
        }
        if (self::on('core')) {
            $rel = '';
            foreach (['images/blank.gif', 'images/wpspin.gif', 'css/dashicons.min.css'] as $c) {
                if (is_file(ABSPATH . WPINC . '/' . $c)) { $rel = $c; break; }
            }
            $file = ABSPATH . WPINC . '/' . $rel;
            foreach (array_unique(array_filter([self::inc_alias(), $prev['includes']])) as $i => $inc) {
                $err = self::verify_file($home . '/' . $inc . '/' . $rel, $file);
                if ($err === '') { $snap['includes'] = $inc; if ($i === 0) $ok[] = 'includes'; break; }
                if ($i === 0) $failed['includes'] = $err;
            }

            // admin-ajax.php without an action answers HTTP 400 with "0" (the WordPress HTTP API may
            // return that body empty); an unmapped path would be a WordPress 404 page instead
            foreach (array_unique(array_filter([self::ajax_alias(), $prev['ajax']])) as $i => $ajax) {
                $res = self::fetch($home . '/' . $ajax);
                if ($res['error'] === '' && $res['code'] === 400 && in_array(trim($res['body']), ['', '0'], true)) {
                    $snap['ajax'] = $ajax; if ($i === 0) $ok[] = 'ajax'; break;
                }
                if ($i === 0) $failed['ajax'] = $res['error'] !== '' ? $res['error'] : 'HTTP ' . $res['code'];
            }
        }

        // Remember replaced paths (last 3 per entry)
        foreach ($prev['paths'] as $key => $old) {
            if (isset($snap['paths'][$key]) && $snap['paths'][$key] !== $old) {
                $list = array_values(array_diff((array) ($snap['old'][$key] ?? []), [$old, $snap['paths'][$key]]));
                array_unshift($list, $old);
                $snap['old'][$key] = array_slice($list, 0, 3);
            }
        }
        update_option(self::SNAPSHOT_OPTION, $snap, false);
        if (self::on('files')) self::verify_files();
        $status = ['ok' => $ok, 'failed' => $failed, 'skipped' => $skipped, 'time' => time()];
        update_option(self::STATUS_OPTION, $status, false);
        // Blocking covers verified entries only, so the rules are written again with the new snapshot
        if (class_exists('Tegatai_Server')) Tegatai_Server::force_update();
        return $status;
    }

    public static function status() {
        $s = get_option(self::STATUS_OPTION, []);
        return is_array($s) ? $s : [];
    }

    // ------------------------------------------------------------------
    // Hidden file names
    // ------------------------------------------------------------------

    /**
     * Known file names: [token => ['k' => key, 'r' => relative path, 'm' => mtime,
     * 's' => 'p' (waiting) | 'a' (active), 't' => last seen]]. key is "plugin:<folder>",
     * "theme:<slug>" or "includes".
     */
    private static $files = null;
    private static $files_dirty = false;

    public static function files() {
        if (self::$files === null) {
            $f = get_option(self::FILES_OPTION, []);
            self::$files = is_array($f) ? $f : [];
        }
        return self::$files;
    }

    private static function save_files() {
        if (self::$files_dirty) {
            update_option(self::FILES_OPTION, self::$files, false);
            self::$files_dirty = false;
        }
    }

    // URL path of the real folder of a key
    private static function file_base($key) {
        if ($key === 'includes') return self::includes_path();
        return strpos($key, ':') !== false ? self::real_path($key) : '';
    }

    private static function file_dir($key) {
        if ($key === 'includes') return ABSPATH . WPINC;
        return strpos($key, ':') !== false ? self::real_dir($key) : '';
    }

    // Stable name per file and version: a changed file gets a new name (works as cache busting)
    public static function token($key, $rel, $mtime) {
        return 't' . substr(hash_hmac('sha256', $key . '|' . $rel . '|' . $mtime, wp_salt('auth')), 0, 11);
    }

    // New path prefix => key, for the verified entries
    private static function file_prefixes() {
        $home = self::home_path();
        $snap = self::snapshot();
        $out = [];
        if (self::on('paths')) foreach ($snap['paths'] as $key => $new) $out[$home . '/' . $new . '/'] = $key;
        if (self::on('core') && $snap['includes'] !== '') $out[$home . '/' . $snap['includes'] . '/'] = 'includes';
        return $out;
    }

    // Replaces the file names of masked files with their active new name; unknown files are recorded
    public static function tokenize($html) {
        $prefixes = self::file_prefixes();
        if (!$prefixes) return $html;
        self::files();
        $strip = self::on('strip');
        $host  = preg_quote((string) wp_parse_url(home_url(), PHP_URL_HOST) . (wp_parse_url(home_url(), PHP_URL_PORT) ? ':' . wp_parse_url(home_url(), PHP_URL_PORT) : ''), '#');
        $now   = time();

        foreach (['/', '\/'] as $sep) {
            $s = preg_quote($sep, '#');
            $alts = [];
            foreach (array_keys($prefixes) as $p) $alts[] = preg_quote(str_replace('/', $sep, $p), '#');
            $re = '#(?<=["\'(=,\s])((?:https?:)?' . $s . $s . $host . ')?(' . implode('|', $alts) . ')((?:[A-Za-z0-9_.\-]+' . $s . ')*)([A-Za-z0-9_.\-]+\.(?:' . self::EXT . '))(\?[^"\'\s)<>\\\\]*)?#i';
            $html = preg_replace_callback($re, static function ($m) use ($prefixes, $sep, $strip, $now) {
                $prefix = str_replace($sep, '/', $m[2]);
                $key = $prefixes[$prefix] ?? null;
                if ($key === null) return $m[0];
                $rel = str_replace($sep, '/', $m[3]) . $m[4];
                if (strpos($rel, '..') !== false) return $m[0];
                $file = self::file_dir($key) . '/' . $rel;
                $mtime = @filemtime($file);
                if ($mtime === false || !is_file($file)) return $m[0];

                $token = self::token($key, $rel, $mtime);
                if (!isset(self::$files[$token])) {
                    self::$files[$token] = ['k' => $key, 'r' => $rel, 'm' => $mtime, 's' => 'p', 't' => $now];
                    self::$files_dirty = true;
                    return $m[0];
                }
                if (($now - (int) self::$files[$token]['t']) > DAY_IN_SECONDS) {
                    self::$files[$token]['t'] = $now;
                    self::$files_dirty = true;
                }
                if (self::$files[$token]['s'] !== 'a') return $m[0];

                $query = $m[5] ?? '';
                if ($strip && $query !== '') {
                    $query = preg_replace('#(^\?|&amp;|&\#038;|&)ver=[^&]*#i', '$1', $query);
                    $query = preg_replace('#^\?(?:&amp;|&\#038;|&)+#', '?', $query);
                    if ($query === '?') $query = '';
                }
                return $m[1] . $m[2] . $m[3] . $token . $query;
            }, $html);
        }
        self::save_files();
        return $html;
    }

    // Checks the waiting file names (new name answers with the real file)
    public static function verify_files() {
        $files = self::files();
        if (!$files) return;
        $home = self::home_path();
        $snap = self::snapshot();
        foreach ($files as $token => $f) {
            if (($f['s'] ?? '') === 'a') continue;
            $key = (string) $f['k'];
            $prefix = $key === 'includes' ? $snap['includes'] : ($snap['paths'][$key] ?? '');
            if ($prefix === '') continue;
            $dir = dirname((string) $f['r']);
            $url = $home . '/' . $prefix . '/' . ($dir === '.' ? '' : $dir . '/') . $token;
            if (self::verify_file($url, self::file_dir($key) . '/' . $f['r']) === '') {
                self::$files[$token]['s'] = 'a';
                self::$files_dirty = true;
            }
        }
        self::save_files();
    }

    // Hourly: drop replaced names after FILES_KEEP, write the rules for new names, check them
    public static function cron_files() {
        if (!self::on('files')) return;
        self::files();
        $now = time();
        foreach (self::$files as $token => $f) {
            $file = self::file_dir((string) $f['k']) . '/' . $f['r'];
            $current = is_file($file) && (int) @filemtime($file) === (int) $f['m'];
            if (!$current && ($now - (int) $f['t']) > self::FILES_KEEP) {
                unset(self::$files[$token]);
                self::$files_dirty = true;
            }
        }
        self::save_files();
        $waiting = array_filter(self::$files, static function ($f) { return ($f['s'] ?? '') !== 'a'; });
        if ($waiting) {
            if (class_exists('Tegatai_Server')) Tegatai_Server::force_update();
            self::verify_files();
        }
    }

    // ['active' => n, 'waiting' => n]
    public static function files_summary() {
        $a = 0; $w = 0;
        foreach (self::files() as $f) { if (($f['s'] ?? '') === 'a') $a++; else $w++; }
        return ['active' => $a, 'waiting' => $w];
    }

    // Labels for the admin page
    public static function label($key) {
        if ($key === 'includes') return 'wp-includes';
        if ($key === 'ajax') return 'admin-ajax.php';
        list($type, $name) = array_pad(explode(':', $key, 2), 2, '');
        return ($type === 'theme' ? __('Theme', 'tegatai-secure') : __('Plugin', 'tegatai-secure')) . ' ' . $name;
    }
}

Tegatai_Mask::boot();
