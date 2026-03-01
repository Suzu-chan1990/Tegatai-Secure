<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Logger {
    private static function tegatai_is_private_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) { return false; }
        return !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE);
    }


    
    public function __construct() {
        // TEGATAI_PRO_FEATURE: Admin Audit Trail
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
        
        if (!$ip) $ip = $_SERVER['REMOTE_ADDR'];
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
        $ops = get_option('tegatai_options');
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
        
        // 1. Lösche Einträge älter als X Tage
        $time_limit = date('Y-m-d H:i:s', strtotime("-$days days"));
        $wpdb->query($wpdb->prepare("DELETE FROM $table WHERE time < %s", $time_limit));
        
        // 2. Hard Limit (Max 5000 Einträge behalten, Überlaufschutz)
        $count = $wpdb->get_var("SELECT COUNT(*) FROM $table");
        if ($count > 5000) {
            $limit = intval($count - 5000);
            $wpdb->query("DELETE FROM $table ORDER BY id ASC LIMIT $limit");
        }

        // 3. CLEANUP: Alte Tegatai Transients aus wp_options entfernen
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_teg\_%' AND option_value < '" . time() . "'");
        $wpdb->query("DELETE FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_teg\_%' AND option_name NOT IN (SELECT CONCAT('_transient_', SUBSTRING(option_name, 20)) FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_teg\_%')");

        // 4. CLEANUP: Veraltete RAM-First Cache-Files löschen (DDoS-Trap Cleanup)
        $cache_dir = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/';
        if (is_dir($cache_dir)) {
            foreach (glob($cache_dir . '*.txt') as $file) {
                if (time() - filemtime($file) > 86400) @unlink($file);
            }
        }
    }

}