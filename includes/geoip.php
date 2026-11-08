<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Local country lookup for the GeoIP block (no external request per visitor).
 *
 * Database: "IP to Country Lite" by DB-IP (https://db-ip.com), CC BY 4.0, MaxMind DB format,
 * read with the bundled MaxMind DB reader (lib/maxmind-db-reader, Apache-2.0).
 *
 * The file lives in wp-content/uploads/tegatai-geoip/ because WordPress replaces the plugin
 * folder on every update. It is only downloaded while the GeoIP block is switched on: by the
 * daily maintenance job when the local file is missing or older than 30 days, or with the
 * button on the GeoIP tab. That download from download.db-ip.com is the only external request;
 * visitor IP addresses never leave the server.
 */
class Tegatai_GeoIP {
    const FILE    = 'dbip-country-lite.mmdb';
    const MAX_AGE = 30 * DAY_IN_SECONDS;
    const OPTION  = 'tegatai_geoip_last_update';

    public static function init() {
        add_action('tegatai_daily_maintenance', [__CLASS__, 'maybe_update']);
        add_action('admin_post_tegatai_geoip_update', [__CLASS__, 'handle_update']);
    }

    /** True when the GeoIP block is switched on (blacklist or whitelist). */
    public static function enabled($ops = null) {
        if ($ops === null) $ops = tegatai_get_setting('tegatai_options');
        $mode = is_array($ops) ? (string) ($ops['geoip_mode'] ?? '') : '';
        return in_array($mode, ['blacklist', 'whitelist'], true);
    }

    /**
     * Country list of the settings. Codes may be separated by new lines, commas, semicolons or
     * spaces (the field asks for one per line; older settings used commas).
     */
    public static function country_list($ops) {
        $raw   = strtoupper((string) ($ops['geoip_list'] ?? ''));
        $parts = preg_split('/[\s,;]+/', $raw, -1, PREG_SPLIT_NO_EMPTY);
        return array_values(array_unique(array_filter($parts, function ($c) { return preg_match('/^[A-Z]{2}$/', $c); })));
    }

    /**
     * Whether a country is blocked by the settings. Unknown countries ('XX') and local
     * addresses ('LO') are never blocked (fail open), and an empty list blocks nothing, so a
     * missing database or an empty whitelist can never lock out every visitor.
     */
    public static function is_blocked($ops, $country) {
        if (!self::enabled($ops)) return false;
        if (!preg_match('/^[A-Z]{2}$/', (string) $country) || $country === 'XX') return false;
        $list = self::country_list($ops);
        if (empty($list)) return false;
        $listed = in_array($country, $list, true);
        return $ops['geoip_mode'] === 'blacklist' ? $listed : !$listed;
    }

    public static function dir() {
        $up = wp_upload_dir(null, false);
        return trailingslashit((string) $up['basedir']) . 'tegatai-geoip';
    }

    public static function path() {
        return self::dir() . '/' . self::FILE;
    }

    /** Loads the bundled reader classes without a global autoloader. */
    private static function load_reader() {
        if (class_exists('\MaxMind\Db\Reader', false)) return true;
        $base = TEGATAI_PATH . 'lib/maxmind-db-reader/src/MaxMind/Db/';
        foreach (['Reader/InvalidDatabaseException.php', 'Reader/Util.php', 'Reader/Decoder.php', 'Reader/Metadata.php', 'Reader.php'] as $f) {
            if (!is_readable($base . $f)) return false;
            require_once $base . $f;
        }
        return class_exists('\MaxMind\Db\Reader', false);
    }

    /** Open reader for the local database or null (cached per request). */
    private static function reader() {
        static $reader = false;
        if ($reader !== false) return $reader;
        $reader = null;
        $file = self::path();
        if (is_readable($file) && self::load_reader()) {
            try {
                $reader = new \MaxMind\Db\Reader($file);
            } catch (\Throwable $e) {
                $reader = null;
            }
        }
        return $reader;
    }

    public static function available() {
        return self::reader() !== null;
    }

    /**
     * Two-letter country code of an IP, 'LO' for local/private/reserved addresses and 'XX' when
     * it is unknown or there is no database.
     */
    public static function country($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return 'XX';
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return 'LO';
        $reader = self::reader();
        if (!$reader) return 'XX';
        try {
            $rec = $reader->get($ip);
        } catch (\Throwable $e) {
            return 'XX';
        }
        $code = is_array($rec) ? (string) ($rec['country']['iso_code'] ?? '') : '';
        return preg_match('/^[A-Z]{2}$/', $code) ? $code : 'XX';
    }

    /** File date, build date and last update result for the GeoIP tab. */
    public static function info() {
        $file = self::path();
        $info = ['exists' => is_readable($file), 'path' => $file, 'mtime' => 0, 'built' => 0, 'size' => 0];
        if ($info['exists']) {
            $info['mtime'] = (int) filemtime($file);
            $info['size']  = (int) filesize($file);
            $reader = self::reader();
            if ($reader) $info['built'] = (int) $reader->metadata()->buildEpoch;
        }
        $last = get_option(self::OPTION, []);
        $info['last'] = is_array($last) ? $last : [];
        return $info;
    }

    /** Daily job: only while the GeoIP block is on, and only when the file is missing or old. */
    public static function maybe_update() {
        if (!self::enabled()) return;
        $file = self::path();
        if (is_readable($file) && (time() - (int) filemtime($file)) < self::MAX_AGE) return;
        self::update();
    }

    public static function handle_update() {
        if (!current_user_can('manage_options')) wp_die('Access Denied', 403);
        check_admin_referer('teg_geoip_update');
        $r = self::update();
        $msg = is_wp_error($r) ? 'geoip_failed' : 'geoip_updated';
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=geoip&msg=' . $msg));
        exit;
    }

    /**
     * Downloads the current monthly edition (or the previous month's at the start of a month,
     * before the new one is published), unpacks and checks it, then swaps it in.
     *
     * @return true|WP_Error
     */
    public static function update() {
        if (!function_exists('download_url')) require_once ABSPATH . 'wp-admin/includes/file.php';
        if (!self::load_reader()) return self::result(new WP_Error('reader', 'The MaxMind DB reader library is missing (lib/maxmind-db-reader).'));
        if (!function_exists('gzopen')) return self::result(new WP_Error('zlib', 'The PHP zlib extension is missing.'));

        $dir = self::dir();
        if (!wp_mkdir_p($dir) || !wp_is_writable($dir)) return self::result(new WP_Error('dir', 'Folder not writable: ' . $dir));
        tegatai_protect_directory($dir);

        $gz = null;
        $error = null;
        foreach ([gmdate('Y-m'), gmdate('Y-m', strtotime('first day of last month'))] as $month) {
            $tmp = download_url('https://download.db-ip.com/free/dbip-country-lite-' . $month . '.mmdb.gz', 120);
            if (!is_wp_error($tmp)) { $gz = $tmp; break; }
            $error = $tmp;
        }
        if ($gz === null) return self::result($error instanceof WP_Error ? $error : new WP_Error('download', 'Download failed.'));

        $new = $dir . '/' . self::FILE . '.new';
        $in  = gzopen($gz, 'rb');
        $out = $in ? fopen($new, 'wb') : false;
        if (!$in || !$out) {
            if ($in) gzclose($in);
            wp_delete_file($gz);
            return self::result(new WP_Error('unpack', 'The download could not be unpacked.'));
        }
        while (!gzeof($in)) {
            $chunk = gzread($in, 1 << 20);
            if ($chunk === false) break;
            fwrite($out, $chunk);
        }
        gzclose($in);
        fclose($out);
        wp_delete_file($gz);

        try {
            $test = new \MaxMind\Db\Reader($new);
            $type = (string) $test->metadata()->databaseType;
            $test->close();
            if (stripos($type, 'country') === false) throw new \RuntimeException('Unexpected database type: ' . $type);
        } catch (\Throwable $e) {
            wp_delete_file($new);
            return self::result(new WP_Error('invalid', 'The downloaded file is not a valid country database (' . $e->getMessage() . ').'));
        }

        if (!rename($new, self::path())) {
            wp_delete_file($new);
            return self::result(new WP_Error('rename', 'The database could not be replaced.'));
        }
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('GEOIP', 'Country database updated.');
        return self::result(true);
    }

    private static function result($r) {
        update_option(self::OPTION, [
            'time'  => time(),
            'ok'    => $r === true,
            'error' => is_wp_error($r) ? $r->get_error_message() : '',
        ], false);
        return $r;
    }
}

Tegatai_GeoIP::init();
