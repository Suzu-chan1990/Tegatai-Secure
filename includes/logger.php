<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Logger {
    // Central client IP detection.
    // REMOTE_ADDR is the only value that cannot be forged by the client. Proxy headers
    // (CF-Connecting-IP, X-Real-IP, X-Forwarded-For) are only honored when the request
    // actually comes from a configured trusted proxy, see get_trusted_proxies().
    public static function get_ip() {
        static $resolved = null;
        if ($resolved !== null) return $resolved;

        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        if (!filter_var($remote, FILTER_VALIDATE_IP)) {
            // No usable peer address (e.g. CLI). Must not map to a whitelisted loopback address.
            return $resolved = '0.0.0.0';
        }

        // A local reverse proxy (nginx -> Apache/PHP on the same host, loopback or SERVER_ADDR) is trusted implicitly,
        // but only for X-Forwarded-For, which is evaluated from the right.
        $explicit = self::get_trusted_proxies();
        $local    = ['127.0.0.1', '::1'];
        if (!empty($_SERVER['SERVER_ADDR']) && filter_var($_SERVER['SERVER_ADDR'], FILTER_VALIDATE_IP)) {
            $local[] = (string)$_SERVER['SERVER_ADDR'];
        }
        $proxies  = array_merge($explicit, $local);
        if (!self::ip_matches_any($remote, $proxies)) {
            return $resolved = $remote;
        }

        // Single-value headers are passed through unchanged by misconfigured proxies,
        // so they are only accepted from explicitly configured proxies.
        if (!empty($explicit) && self::ip_matches_any($remote, $explicit)) {
            foreach (['HTTP_CF_CONNECTING_IP', 'HTTP_X_REAL_IP'] as $key) {
                if (!empty($_SERVER[$key])) {
                    $ip = trim((string)$_SERVER[$key]);
                    if (filter_var($ip, FILTER_VALIDATE_IP)) return $resolved = $ip;
                }
            }
        }

        // X-Forwarded-For: walk from right to left, skip our own proxies, the first
        // untrusted hop is the client. Entries left of it are client-controlled.
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $hops = array_reverse(array_map('trim', explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR'])));
            foreach ($hops as $hop) {
                if (!filter_var($hop, FILTER_VALIDATE_IP)) break;
                if (!self::ip_matches_any($hop, $proxies)) return $resolved = $hop;
            }
        }

        return $resolved = $remote;
    }

    /**
     * Trusted reverse proxies (IPs or CIDR ranges).
     * Configure via wp-config.php: define('TEGATAI_TRUSTED_PROXIES', '10.0.0.0/8, 192.168.1.5');
     * or the 'tegatai_trusted_proxies' filter.
     */
    public static function get_trusted_proxies() {
        $list = defined('TEGATAI_TRUSTED_PROXIES') ? TEGATAI_TRUSTED_PROXIES : [];
        if (is_string($list)) $list = preg_split('/[\s,;]+/', $list);
        if (!is_array($list)) $list = [];
        if (function_exists('apply_filters')) $list = (array) apply_filters('tegatai_trusted_proxies', $list);
        return array_values(array_filter(array_map('trim', $list)));
    }

    /**
     * Whether the direct peer (REMOTE_ADDR) is an explicitly configured proxy, i.e. headers it
     * adds such as CF-IPCountry can be trusted.
     */
    public static function is_trusted_proxy_request() {
        $remote = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        $explicit = self::get_trusted_proxies();
        return $remote !== '' && !empty($explicit) && self::ip_matches_any($remote, $explicit);
    }

    private static function ip_matches_any($ip, array $ranges) {
        foreach ($ranges as $range) {
            if (self::ip_in_range($ip, $range)) return true;
        }
        return false;
    }

    public static function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) {
            $a = @inet_pton($ip); $b = @inet_pton($range);
            return $a !== false && $b !== false && $a === $b;
        }
        list($subnet, $bits) = explode('/', $range, 2);
        $ip_bin = @inet_pton($ip); $sub_bin = @inet_pton($subnet);
        if ($ip_bin === false || $sub_bin === false || strlen($ip_bin) !== strlen($sub_bin)) return false;
        $bits = (int)$bits;
        $len = strlen($ip_bin);
        if ($bits < 0 || $bits > $len * 8) return false;
        $mask = '';
        for ($i = 0; $i < $len; $i++) {
            $take = max(0, min(8, $bits - $i * 8));
            $mask .= chr($take ? (0xFF << (8 - $take)) & 0xFF : 0);
        }
        return ($ip_bin & $mask) === ($sub_bin & $mask);
    }

    private static function tegatai_is_private_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }

    public function __construct() {
        // Admin Audit Trail
        add_action('activated_plugin', [$this, 'log_plugin_activation'], 10, 2);
        add_action('deactivated_plugin', [$this, 'log_plugin_deactivation'], 10, 2);
        add_action('deleted_post', [$this, 'log_post_deletion'], 10, 2);
    }

    public function log_plugin_activation($plugin, $network_wide) { self::log('AUDIT', 'Plugin aktiviert: ' . sanitize_text_field($plugin)); }
    public function log_plugin_deactivation($plugin, $network_wide) { self::log('AUDIT', 'Plugin deaktiviert: ' . sanitize_text_field($plugin)); }
    public function log_post_deletion($post_id, $post) { 
        if(in_array($post->post_type, ['post','page'])) {
            self::log('AUDIT', 'Beitrag gelöscht: ' . intval($post_id) . ' (' . sanitize_text_field($post->post_title) . ')'); 
        }
    }

    public static function log($type, $message, $ip = null) {
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        
        if (!$ip) $ip = self::get_ip();
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown';
        $time = current_time('mysql');

        // Insert in DB
        // Wir nutzen $wpdb->insert statt prepare manuell, da sicherer
        $wpdb->insert(
            $table,
            [
                'time' => $time,
                'type' => $type,
                'ip' => $ip,
                'message' => $message,
                'user_agent' => substr($ua, 0, 255) // Kürzen falls zu lang
            ],
            ['%s', '%s', '%s', '%s', '%s']
        );

        // --- WEBHOOK ALERTS ---
        $ops = tegatai_get_setting('tegatai_options');
        if (!empty($ops['alert_webhook_url']) && in_array($type, ['BAN-404', 'FLOOD', 'AUTH-BAN', 'SEC-WARN'])) {
            $msg_json = wp_json_encode([
                'content' => "🚨 **Tegatai Security Alert**",
                'embeds' => [[
                    'title' => "Ereignis: " . $type,
                    'description' => "**Details:** $message\n**IP-Adresse:** $ip\n**User-Agent:** $ua",
                    'color' => 16711680 // Rot
                ]]
            ]);
            do {
            $url = isset($ops['alert_webhook_url']) ? esc_url_raw($ops['alert_webhook_url']) : '';
            if (!$url || !wp_http_validate_url($url)) { break; }
            $host = (string)parse_url($url, PHP_URL_HOST);
            if ($host === 'localhost' || $host === '127.0.0.1' || $host === '::1') { break; }
            if (filter_var($host, FILTER_VALIDATE_IP) && self::tegatai_is_private_ip($host)) { break; }
            wp_remote_post($url, [
                'headers' => ['Content-Type' => 'application/json'],
                'body' => $msg_json,
                'blocking' => false // Blockiert den Seitenaufbau nicht
            ]);
        } while (false);
        }
    }

    public static function get_logs($limit = 100) {
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        
        // Check if table exists (safety)
        if($wpdb->get_var("SHOW TABLES LIKE '$table'") != $table) return [];

        $results = $wpdb->get_results("SELECT * FROM $table ORDER BY id DESC LIMIT " . intval($limit), ARRAY_A);
        return $results ? $results : [];
    }
    
    public static function get_stats() {
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        if($wpdb->get_var("SHOW TABLES LIKE '$table'") != $table) return ['total'=>0, 'blocked'=>0];

        $total = $wpdb->get_var("SELECT COUNT(*) FROM $table");
        // Wir zählen alles als "Blocked", was nicht "LOGIN" oder "INFO" oder "BACKUP" ist
        $blocked = $wpdb->get_var("SELECT COUNT(*) FROM $table WHERE type NOT IN ('LOGIN', 'INFO', 'BACKUP', 'AUTH')");
        
        return ['total' => $total, 'blocked' => $blocked];
    }

    public static function clear() {
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        $wpdb->query("TRUNCATE TABLE $table");
    }

    public static function prune_logs($days = 30) {
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';

        // do_action() without arguments passes '' as first argument.
        $days = (int)$days > 0 ? (int)$days : 30;

        // 1. Delete entries older than X days. Log times are stored in site-local time (current_time('mysql')).
        $time_limit = gmdate('Y-m-d H:i:s', current_time('timestamp') - $days * DAY_IN_SECONDS);
        $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE time < %s", $time_limit));
        
        // 2. Hard Limit (Max 5000 Einträge behalten, Überlaufschutz)
        $count = $wpdb->get_var("SELECT COUNT(*) FROM $table");
        if ($count > 5000) {
            $limit = intval($count - 5000);
            $wpdb->query("DELETE FROM $table ORDER BY id ASC LIMIT $limit");
        }

        // 3. CLEANUP: expired transients (rate-limit counters, nonces). The previous custom query
        // used a subquery on the same table, which MySQL rejects (error 1093). Core's helper
        // removes expired value/timeout pairs and keeps transients without expiry (permanent bans).
        delete_expired_transients();

        // 4. CLEANUP: Veraltete RAM-First Cache-Files löschen (DDoS-Trap Cleanup)
        $cache_dir = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/';
        if (is_dir($cache_dir)) {
            foreach (glob($cache_dir . '*.txt') as $file) {
                if (time() - filemtime($file) > 86400) @unlink($file);
            }
        }
    }

}
