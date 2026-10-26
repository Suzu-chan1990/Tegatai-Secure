<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Hive {
    const MAX_RETRIES  = 4;

    public function __construct() {
        add_action('rest_api_init', [$this, 'register_rest_route']);
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('tegatai_ip_banned', [$this, 'broadcast_ban'], 10, 3);
        add_action('wp_ajax_tegatai_hive_test', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_tegatai_sudo_hive', [$this, 'ajax_sudo_hive']);
        add_action('wp_login', [$this, 'remember_admin_ip'], 10, 2);

        // Background Worker Queue
        add_action('tegatai_hive_retry_cron', [$this, 'process_retry_queue']);
        add_action('tegatai_hive_flush', [$this, 'process_retry_queue']);
        add_action('init', [$this, 'init_cron']);
    }

    public function init_cron() {
        if (!wp_next_scheduled('tegatai_hive_retry_cron')) {
            wp_schedule_event(time(), 'hourly', 'tegatai_hive_retry_cron');
        }
    }

    public function register_rest_route() {
        register_rest_route('tegatai/v1', '/hive/receive', [
            'methods' => 'POST',
            'callback' => [$this, 'receive_ban'],
            'permission_callback' => '__return_true'
        ]);
    }

    // --- Configuration helpers ---

    private static function get_options() {
        $ops = get_option('tegatai_hive_options', []);
        return is_array($ops) ? $ops : [];
    }

    private static function get_shared_secret($ops) {
        return defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : '');
    }

    /**
     * Peers are configured one per line as "URL" or "URL | pair-secret".
     * A pair secret is shared only between this node and that peer, so a compromised
     * peer cannot impersonate any other node and can be revoked individually.
     * Peers without their own secret fall back to the network-wide shared secret.
     */
    public static function get_peers($ops = null) {
        $ops = $ops ?? self::get_options();
        $raw = isset($ops['node_urls']) ? (string)$ops['node_urls'] : '';
        $peers = [];
        foreach (explode("\n", str_replace(["\r\n", "\r"], "\n", $raw)) as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $parts = array_map('trim', explode('|', $line, 2));
            $url = esc_url_raw($parts[0]);
            if (!$url) continue;
            $peers[self::normalize_node($url)] = [
                'url'    => untrailingslashit($url),
                'secret' => isset($parts[1]) ? $parts[1] : '',
            ];
        }
        return $peers;
    }

    private static function normalize_node($url) {
        $url = strtolower(trim((string)$url));
        $url = preg_replace('#^https?://#', '', $url);
        return untrailingslashit($url);
    }

    private static function secret_for_peer($peer, $ops) {
        if (!empty($peer['secret'])) return $peer['secret'];
        return self::get_shared_secret($ops);
    }

    // --- Never-ban protection ---

    public function remember_admin_ip($user_login, $user) {
        if (!($user instanceof WP_User) || !user_can($user, 'manage_options')) return;
        $ip = Tegatai_Logger::get_ip();
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return;
        $ips = get_option('tegatai_hive_admin_ips', []);
        if (!is_array($ips)) $ips = [];
        $ips[$ip] = time();
        $cutoff = time() - 30 * DAY_IN_SECONDS;
        $ips = array_filter($ips, function ($t) use ($cutoff) { return $t >= $cutoff; });
        arsort($ips);
        update_option('tegatai_hive_admin_ips', array_slice($ips, 0, 20, true), false);
    }

    /**
     * IPs that the Hive never bans and never broadcasts: loopback, this server, private/reserved
     * ranges, the firewall whitelists, the Hive allowlist, and IPs admins logged in from (30 days).
     */
    public static function is_protected_ip($ip, $ops = null) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return true;
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return true;
        if (!empty($_SERVER['SERVER_ADDR']) && $ip === $_SERVER['SERVER_ADDR']) return true;

        $ops = $ops ?? self::get_options();
        $teg = tegatai_get_setting('tegatai_options', []);
        $lists = [
            $ops['protected_ips'] ?? '',
            is_array($teg) ? ($teg['whitelist_ips'] ?? '') : '',
            is_array($teg) ? ($teg['waf_whitelist_ips'] ?? '') : '',
        ];
        foreach ($lists as $list) {
            foreach (preg_split('/[\s,;]+/', (string)$list) as $entry) {
                if ($entry !== '' && Tegatai_Logger::ip_in_range($ip, $entry)) return true;
            }
        }

        $admin_ips = get_option('tegatai_hive_admin_ips', []);
        return is_array($admin_ips) && isset($admin_ips[$ip]);
    }

    // --- Ban storage (expiring, separate from the manual blacklist) ---

    private static function store_ban($ip, $node, $reason, $level, $ttl) {
        // Shared, expiring ban list enforced by the firewall; does not re-broadcast.
        return Tegatai_Bans::add($ip, $ttl, $reason, 'hive:' . $node, $level);
    }

    private static function ban_ttl($ops) {
        $hours = isset($ops['ban_ttl_hours']) ? (int)$ops['ban_ttl_hours'] : 24;
        return max(1, min(720, $hours)) * HOUR_IN_SECONDS;
    }

    // --- Inbound ---

    public function receive_ban(WP_REST_Request $request) {
        $ops = self::get_options();
        if (empty($ops['enable_hive'])) {
            return new WP_Error('disabled', 'Hive network is disabled on this node.', ['status' => 403]);
        }

        $raw_body = $request->get_body();
        $signature = (string)$request->get_header('X-Tegatai-Signature');
        $claimed_node = self::normalize_node((string)$request->get_header('X-Tegatai-Node'));

        if (empty($raw_body) || $signature === '') {
            return new WP_Error('bad_request', 'Missing payload or signature.', ['status' => 400]);
        }

        // Pick the key by the claimed sender. Unknown or anonymous senders are only accepted
        // with the shared secret, and only while strict peer mode is off (legacy nodes).
        $peers = self::get_peers($ops);
        if ($claimed_node !== '' && isset($peers[$claimed_node])) {
            $secret = self::secret_for_peer($peers[$claimed_node], $ops);
            $node_label = $peers[$claimed_node]['url'];
        } elseif (empty($ops['strict_peers'])) {
            $secret = self::get_shared_secret($ops);
            $node_label = 'legacy:' . ($claimed_node !== '' ? $claimed_node : 'unknown');
        } else {
            return new WP_Error('unknown_peer', 'Sender is not a configured peer.', ['status' => 403]);
        }
        if (empty($secret)) {
            return new WP_Error('disabled', 'No secret configured for this peer.', ['status' => 403]);
        }

        $expected_signature = hash_hmac('sha256', $raw_body, $secret);
        if (!hash_equals($expected_signature, $signature)) {
            return new WP_Error('unauthorized', 'HMAC Signature verification failed.', ['status' => 403]);
        }

        $data = json_decode($raw_body, true);
        if (json_last_error() !== JSON_ERROR_NONE || empty($data['timestamp']) || empty($data['req_id'])) {
            return new WP_Error('invalid_payload', 'Malformed payload data.', ['status' => 400]);
        }

        // The signed node must match the header, otherwise a peer could relay foreign payloads.
        if (isset($data['node']) && self::normalize_node($data['node']) !== $claimed_node) {
            return new WP_Error('invalid_payload', 'Node mismatch.', ['status' => 403]);
        }

        if (abs(time() - intval($data['timestamp'])) > 60) {
            return new WP_Error('replay_attack', 'Request expired (Time drift > 60s).', ['status' => 403]);
        }

        // Atomic claim; the nonce outlives the full ±60 s timestamp window.
        if (!tegatai_claim_nonce('tg_hive_req_' . md5((string)$data['req_id']), 180)) {
            return new WP_Error('duplicate_request', 'Request ID already processed.', ['status' => 429]);
        }

        if (!empty($data['is_test'])) {
            return rest_ensure_response(['success' => true, 'message' => 'HMAC Verified. Connection successful.']);
        }

        $ip = sanitize_text_field($data['ip'] ?? '');
        $reason = sanitize_text_field($data['reason'] ?? '');
        $level = sanitize_text_field($data['level'] ?? 'critical');

        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return new WP_Error('invalid_ip', 'Invalid IP address format.', ['status' => 400]);
        }

        if (self::is_protected_ip($ip, $ops)) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIVE-DENY', "Ignored ban for protected IP $ip from $node_label");
            return new WP_Error('protected_ip', 'This IP address is protected on this node.', ['status' => 403]);
        }

        // Cap bans per peer, so a compromised peer cannot flood the ban list.
        $limit = (int) apply_filters('tegatai_hive_max_bans_per_peer_hour', 100);
        $rate_key = 'tg_hive_rate_' . md5($node_label);
        $count = (int) get_transient($rate_key);
        if ($count >= $limit) {
            return new WP_Error('rate_limited', 'Too many bans from this peer.', ['status' => 429]);
        }
        set_transient($rate_key, $count + 1, HOUR_IN_SECONDS);

        if (self::store_ban($ip, $node_label, $reason, $level, self::ban_ttl($ops)) && class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('HIVE-SYNC', "Applied network ban for $ip from $node_label. Level: [$level]. Reason: $reason");
        }

        return rest_ensure_response(['success' => true, 'message' => 'Threat successfully synced to local node.']);
    }

    // --- Outbound ---

    /**
     * Fired via do_action('tegatai_ip_banned', $ip, $reason, $level) by the firewall and login traps.
     * Never blocks the current request: payloads are queued and sent by a cron worker.
     */
    public function broadcast_ban($ip, $reason = 'Malicious Activity', $level = 'critical') {
        $ops = self::get_options();
        if (empty($ops['enable_hive'])) return;
        if (self::is_protected_ip($ip, $ops)) return;

        $peers = self::get_peers($ops);
        if (empty($peers)) return;

        // One broadcast per IP and hour, repeated hits of the same attacker are not re-sent.
        if (!tegatai_claim_nonce('tg_hive_out_' . md5($ip), HOUR_IN_SECONDS)) return;

        $queue = get_option('tegatai_hive_queue', []);
        if (!is_array($queue)) $queue = [];
        foreach ($peers as $key => $peer) {
            $queue[] = [
                'peer' => $key,
                'url' => $peer['url'] . '/wp-json/tegatai/v1/hive/receive',
                'payload' => ['ip' => $ip, 'reason' => (string)$reason, 'level' => (string)$level],
                'retries' => 0,
                'queued_at' => time(),
            ];
        }
        update_option('tegatai_hive_queue', array_slice($queue, -500), false);

        if (!wp_next_scheduled('tegatai_hive_flush')) {
            wp_schedule_single_event(time(), 'tegatai_hive_flush');
        }
    }

    private static function send_signed($url, array $payload, $secret, $ssl_verify, $timeout) {
        $payload['node'] = home_url();
        $payload['timestamp'] = time();
        $payload['req_id'] = bin2hex(random_bytes(16));
        $json_payload = wp_json_encode($payload);

        return wp_remote_post($url, [
            'blocking' => true,
            'timeout' => $timeout,
            'sslverify' => $ssl_verify,
            'headers' => [
                'X-Tegatai-Signature' => hash_hmac('sha256', $json_payload, $secret),
                'X-Tegatai-Node' => home_url(),
                'Content-Type' => 'application/json; charset=utf-8'
            ],
            'body' => $json_payload
        ]);
    }

    public function process_retry_queue() {
        $queue = get_option('tegatai_hive_queue', []);
        if (empty($queue) || !is_array($queue)) return;

        $ops = self::get_options();
        $peers = self::get_peers($ops);
        $ssl_verify = isset($ops['ssl_verify']) ? (bool) $ops['ssl_verify'] : true;
        $new_queue = [];

        foreach ($queue as $item) {
            // Garbage Collection: drop entries older than 24 hours or after too many attempts
            $queued_at = isset($item['queued_at']) ? intval($item['queued_at']) : 0;
            $retries = isset($item['retries']) ? (int)$item['retries'] : 0;
            if (($queued_at > 0 && time() - $queued_at > DAY_IN_SECONDS) || $retries >= self::MAX_RETRIES) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIVE-GC', "Dropped queue item for " . $item['url'] . " after $retries attempts.");
                continue;
            }

            $peer = isset($item['peer'], $peers[$item['peer']]) ? $peers[$item['peer']] : null;
            $secret = $peer ? self::secret_for_peer($peer, $ops) : self::get_shared_secret($ops);
            if (empty($secret) || empty($item['payload']) || !is_array($item['payload'])) continue;

            $payload = array_intersect_key($item['payload'], array_flip(['ip', 'reason', 'level']));
            $response = self::send_signed($item['url'], $payload, $secret, $ssl_verify, 5);
            $code = is_wp_error($response) ? 0 : wp_remote_retrieve_response_code($response);

            // 403 protected_ip / 429 duplicate are final answers, retrying would not help.
            if ($code === 200 || $code === 403 || $code === 429) {
                if ($retries > 0 && $code === 200 && class_exists('Tegatai_Logger')) {
                    Tegatai_Logger::log('HIVE-RETRY', "Successfully delivered delayed payload to " . $item['url']);
                }
                continue;
            }

            $item['retries'] = $retries + 1;
            $new_queue[] = $item;
            if (class_exists('Tegatai_Logger')) {
                $err = is_wp_error($response) ? $response->get_error_message() : $code;
                Tegatai_Logger::log('HIVE-QUEUE', "Failed to deliver to {$item['url']} ($err). Will retry.");
            }
        }

        if (empty($new_queue)) {
            delete_option('tegatai_hive_queue');
        } else {
            update_option('tegatai_hive_queue', $new_queue, false);
        }
    }

    public function ajax_test_connection() {
        if (ob_get_length()) { ob_clean(); }
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_hive_test_nonce', 'security');

        $ops = self::get_options();
        $peers = self::get_peers($ops);

        if (empty($ops['enable_hive']) || empty($peers)) {
            if (ob_get_length()) { ob_clean(); }
            wp_send_json_error(__('Hive network is disabled or missing configuration.', 'tegatai-secure'));
        }

        $ssl_verify = isset($ops['ssl_verify']) ? (bool) $ops['ssl_verify'] : true;
        $results = [];

        foreach ($peers as $peer) {
            $secret = self::secret_for_peer($peer, $ops);
            if (empty($secret)) {
                $results[] = ['url' => $peer['url'], 'status' => 'error', 'msg' => __('No secret configured for this peer', 'tegatai-secure')];
                continue;
            }
            $response = self::send_signed($peer['url'] . '/wp-json/tegatai/v1/hive/receive', [
                'ip' => '127.0.0.1',
                'reason' => 'Connection Test',
                'level' => 'low',
                'is_test' => true,
            ], $secret, $ssl_verify, 5);

            if (is_wp_error($response)) {
                $results[] = ['url' => $peer['url'], 'status' => 'error', 'msg' => $response->get_error_message()];
            } else {
                $code = wp_remote_retrieve_response_code($response);
                if ($code === 200) {
                    $results[] = ['url' => $peer['url'], 'status' => 'success', 'msg' => __('OK - HMAC Verified', 'tegatai-secure')];
                } elseif ($code === 403) {
                    $results[] = ['url' => $peer['url'], 'status' => 'error', 'msg' => __('HTTP 403 - Invalid Signature, unknown peer or expired', 'tegatai-secure')];
                } else {
                    $results[] = ['url' => $peer['url'], 'status' => 'error', 'msg' => 'HTTP ' . $code];
                }
            }
        }

        if (ob_get_length()) { ob_clean(); }
        wp_send_json_success($results);
    }

    public function ajax_sudo_hive() {
        if (ob_get_length()) { ob_clean(); }
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_hive_sudo_nonce', 'security');

        if (!defined('TEGATAI_SUDO_PIN')) {
             wp_send_json_error('SUDO_NOT_CONFIGURED');
        }

        $pin = isset($_POST['pin']) ? sanitize_text_field($_POST['pin']) : '';
        if (!password_verify($pin, TEGATAI_SUDO_PIN)) {
             wp_send_json_error('INVALID_PIN');
        }

        $mode = isset($_POST['mode']) ? sanitize_text_field($_POST['mode']) : 'reveal';
        
        if ($mode === 'generate') {
            $key = 'tg_hmac_' . bin2hex(random_bytes(32));
        } else {
            $ops = self::get_options();
            $key = !empty($ops['shared_secret']) ? $ops['shared_secret'] : '';
        }

        wp_send_json_success(['key' => $key]);
    }

    public function register_page() {
        add_submenu_page('tegatai-Secure', __('The Hive', 'tegatai-secure'), __('The Hive', 'tegatai-secure'), 'manage_options', 'tegatai-hive', [$this, 'render_page']);
    }

    public function render_page() {
        if (!current_user_can('manage_options')) wp_die(esc_html__('Access Denied', 'tegatai-secure'));

        if (isset($_POST['tegatai_hive_nonce']) && wp_verify_nonce($_POST['tegatai_hive_nonce'], 'save_hive_settings')) {
            $current_ops = get_option('tegatai_hive_options', []);
            $new_secret = isset($_POST['shared_secret']) ? sanitize_text_field($_POST['shared_secret']) : '';
            $ops = [
                'enable_hive' => isset($_POST['enable_hive']) ? 1 : 0,
                'ssl_verify' => isset($_POST['ssl_verify']) ? 1 : 0,
                'shared_secret' => !empty($new_secret) ? $new_secret : (isset($current_ops['shared_secret']) ? $current_ops['shared_secret'] : ''),
                'node_urls' => sanitize_textarea_field($_POST['node_urls']),
                'strict_peers' => isset($_POST['strict_peers']) ? 1 : 0,
                'ban_ttl_hours' => max(1, min(720, (int)($_POST['ban_ttl_hours'] ?? 24))),
                'protected_ips' => sanitize_textarea_field($_POST['protected_ips'] ?? ''),
            ];
            update_option('tegatai_hive_options', $ops);
            echo '<div class="notice notice-success is-dismissible" style="margin-top:20px;"><p>' . esc_html__('Hive network settings updated successfully.', 'tegatai-secure') . '</p></div>';
        }

        $ops = array_merge(['enable_hive' => 0, 'ssl_verify' => 1, 'shared_secret' => '', 'node_urls' => '', 'strict_peers' => 0, 'ban_ttl_hours' => 24, 'protected_ips' => ''], self::get_options());
        $active_bans = array_filter(Tegatai_Bans::active(), function ($b) { return strpos((string)($b['source'] ?? ''), 'hive:') === 0; });
        
        ?>
        <style>
            :root { 
                --teg-primary: #06b6d4; 
                --teg-accent: #7c3aed; 
                --teg-bg: #f8fafc; 
                --teg-surface: #ffffff; 
                --teg-card: #ffffff; 
                --teg-text: #0f1720; 
                --teg-muted: #6b7280; 
                --teg-border: #e2e8f0; 
                --teg-success: #10b981; 
                --teg-danger: #ef4444; 
            }
            .teg-wrap { max-width: 1400px; margin: 20px auto; font-family: 'Inter', system-ui, sans-serif; color: var(--teg-text); }
            .teg-header { background: linear-gradient(135deg, #0f1720 0%, #1e293b 100%); color: white; padding: 25px 30px; border-radius: 12px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
            .teg-title { font-size: 24px; font-weight: 800; display: flex; align-items: center; gap: 12px; }
            .teg-badge { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; color: #fff; border: 1px solid rgba(255,255,255,0.2); }
            
            /* Horizontal Inner Nav */
            .teg-inner-nav { display: flex; align-items: center; background: var(--teg-surface); padding: 12px 20px; border-radius: 10px; border: 1px solid var(--teg-border); margin-bottom: 24px; overflow-x: auto; box-shadow: 0 1px 3px rgba(0,0,0,0.02); gap: 20px; }
            .teg-back-btn { display: inline-flex; align-items: center; gap: 6px; text-decoration: none; color: var(--teg-text); font-weight: 700; font-size: 13px; border-right: 1px solid var(--teg-border); padding-right: 20px; transition: 0.2s; white-space: nowrap; }
            .teg-back-btn:hover { color: var(--teg-primary); }
            .teg-horizontal-tabs { display: flex; align-items: center; gap: 10px; }
            .teg-h-tab { padding: 8px 16px; border-radius: 6px; text-decoration: none; color: var(--teg-muted); font-size: 13px; font-weight: 600; white-space: nowrap; transition: 0.2s; border: 1px solid transparent; }
            .teg-h-tab.active { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); color: #fff; border-color: transparent; }

            /* Kachel-Optik (Tile UI) */
            .teg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 16px; align-items: start; }
            .teg-card { background: var(--teg-card); border-radius: 6px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid var(--teg-border); }
            .teg-card h3 { margin-top: 0; font-size: 12px; font-weight: 700; border-bottom: 1px solid var(--teg-border); padding-bottom: 10px; margin-bottom: 12px; text-transform: uppercase; color: var(--teg-muted); letter-spacing: 0.5px; display: flex; align-items: center; gap: 8px; }
            
            /* Switches */
            .teg-switch-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid #f8fafc; }
            .teg-switch-row:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
            .teg-switch-label { font-size: 13px; font-weight: 600; color: var(--teg-text); display: flex; align-items: center; gap: 4px; }
            .teg-switch-desc { font-size: 11px; color: var(--teg-muted); line-height: 1.4; margin-bottom: 10px; display: block; }
            
            .switch { position: relative; display: inline-block; width: 36px; height: 20px; flex-shrink: 0; margin: 0; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--teg-border); transition: .3s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
            input:checked + .slider { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); }
            input:checked + .slider:before { transform: translateX(16px); }

            /* Inputs */
            .teg-form-input { width: 100%; padding: 8px 10px; border: 1px solid var(--teg-border); border-radius: 6px; font-size: 13px; margin-bottom: 8px; background: var(--teg-bg); color: var(--teg-text); transition: all 0.2s; box-sizing: border-box; }
            .teg-form-input:focus { border-color: var(--teg-primary); outline: none; background: var(--teg-surface); box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.15); }
            textarea.teg-form-input { min-height: 80px; font-family: monospace; font-size: 12px; line-height: 1.4; resize: vertical; }

            .button-primary { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)) !important; border: none !important; padding: 6px 16px !important; border-radius: 6px !important; font-weight:600 !important; color:#fff !important; text-shadow: none !important; }
            .button-secondary { background: var(--teg-surface) !important; border: 1px solid var(--teg-border) !important; padding: 6px 16px !important; border-radius: 6px !important; font-weight:600 !important; color: var(--teg-text) !important; text-shadow: none !important; cursor: pointer; }
        </style>

        <div class="teg-wrap">
            <div class="teg-header">
                <div class="teg-title"><span class="dashicons dashicons-networking" style="font-size:32px;"></span> Tegatai Hive</div>
                <div class="teg-badge">v1.2</div>
            </div>
            
            <div class="teg-inner-nav">
                <a href="admin.php?page=tegatai-Secure&tab=dashboard" class="teg-back-btn">
                    <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Dashboard', 'tegatai-secure'); ?>
                </a>
                <div class="teg-horizontal-tabs">
                    <span class="teg-h-tab active"><?php echo esc_html__('Network Setup', 'tegatai-secure'); ?></span>
                </div>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('save_hive_settings', 'tegatai_hive_nonce'); ?>
                <div id="sudo_nonce_container"><?php wp_nonce_field('tegatai_hive_sudo_nonce', 'tegatai_hive_sudo_nonce'); ?></div>
                
                <div class="teg-grid">
                    <div class="teg-card" style="grid-column: span 2;">
                        <h3><span class="dashicons dashicons-info"></span> <?php esc_html_e('Hive Network Status', 'tegatai-secure'); ?></h3>
                        <p class="teg-switch-desc" style="margin-bottom:15px;"><?php esc_html_e('The Hive uses HMAC-SHA256 payload signing, strict timestamps, and request IDs to create a zero-trust, replay-resistant defense grid.', 'tegatai-secure'); ?></p>
                        
                        <div class="teg-switch-row">
                            <div><span class="teg-switch-label"><?php esc_html_e('Enable Broadcast & Receive', 'tegatai-secure'); ?></span></div>
                            <label class="switch"><input type="checkbox" name="enable_hive" value="1" <?php checked($ops['enable_hive'], 1); ?>><span class="slider"></span></label>
                        </div>
                        <div class="teg-switch-row">
                            <div>
                                <span class="teg-switch-label"><?php esc_html_e('Enforce strict SSL verification', 'tegatai-secure'); ?></span>
                                <span class="teg-switch-desc" style="margin:0;"><?php esc_html_e('Uncheck only for self-signed certs/local nodes', 'tegatai-secure'); ?></span>
                            </div>
                            <label class="switch"><input type="checkbox" name="ssl_verify" value="1" <?php checked($ops['ssl_verify'], 1); ?>><span class="slider"></span></label>
                        </div>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e('HMAC Shared Secret', 'tegatai-secure'); ?></h3>
                        <?php if (defined('TEGATAI_HIVE_SECRET')) : ?>
                            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                <strong>🔒 <?php esc_html_e('Secret loaded from wp-config.php', 'tegatai-secure'); ?></strong><br>
                                <?php esc_html_e('The secret is active and secured. It is hidden from the UI.', 'tegatai-secure'); ?>
                            </div>
                        <?php else : ?>
                            <?php if (!empty($ops['shared_secret'])) : ?>
                                <div style="background: #fffbeb; border: 1px solid #fde68a; color: #b45309; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                    <strong>⚠️ <?php esc_html_e('Secret active in Database', 'tegatai-secure'); ?></strong><br>
                                    <?php esc_html_e('For security reasons, it is not displayed here. We strongly recommend migrating it to wp-config.php.', 'tegatai-secure'); ?>
                                </div>
                            <?php endif; ?>
                            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 5px;">
                                <input type="password" name="shared_secret" id="hive_secret_key" value="" class="teg-form-input" style="margin:0;" autocomplete="new-password" placeholder="<?php echo !empty($ops['shared_secret']) ? '••••••••••••••••••••••••••••••••' : ''; ?>">
                            </div>
                            
                            <div style="display:flex; gap:8px; margin-bottom:10px; margin-top:8px;">
                                <?php if (!empty($ops['shared_secret'])) : ?>
                                    <button type="button" class="button button-secondary" id="reveal_hive_key" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Reveal (Sudo)', 'tegatai-secure'); ?></button>
                                <?php endif; ?>
                                <button type="button" class="button button-secondary" id="generate_hive_key" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Generate New', 'tegatai-secure'); ?></button>
                                <button type="button" class="button button-secondary" id="copy_hive_key" style="display: none; font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Copy', 'tegatai-secure'); ?></button>
                            </div>
                            
                            <p class="teg-switch-desc"><?php esc_html_e('Leave blank to keep current secret.', 'tegatai-secure'); ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-admin-links"></span> <?php esc_html_e('Peer Node URLs', 'tegatai-secure'); ?></h3>
                        <p class="teg-switch-desc"><?php esc_html_e('One peer per line: "URL" or "URL | pair secret". A pair secret is shared only with that peer (configure the same value on both sides); peers without one use the shared secret.', 'tegatai-secure'); ?></p>
                        <textarea name="node_urls" class="teg-form-input" placeholder="https://example.com | tg_hmac_...&#10;https://another-site.net"><?php echo esc_textarea($ops['node_urls']); ?></textarea>
                        <div class="teg-switch-row">
                            <div>
                                <span class="teg-switch-label"><?php esc_html_e('Strict peer mode', 'tegatai-secure'); ?></span>
                                <span class="teg-switch-desc" style="margin:0;"><?php esc_html_e('Only accept bans from listed peers that identify themselves (requires the current Tegatai version on all nodes).', 'tegatai-secure'); ?></span>
                            </div>
                            <label class="switch"><input type="checkbox" name="strict_peers" value="1" <?php checked($ops['strict_peers'], 1); ?>><span class="slider"></span></label>
                        </div>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-clock"></span> <?php esc_html_e('Ban Policy', 'tegatai-secure'); ?></h3>
                        <label class="teg-switch-label"><?php esc_html_e('Network ban duration (hours)', 'tegatai-secure'); ?></label>
                        <input type="number" name="ban_ttl_hours" min="1" max="720" value="<?php echo esc_attr((int)$ops['ban_ttl_hours']); ?>" class="teg-form-input">
                        <label class="teg-switch-label"><?php esc_html_e('Never-ban allowlist (IP / CIDR)', 'tegatai-secure'); ?></label>
                        <textarea name="protected_ips" class="teg-form-input" placeholder="203.0.113.10&#10;66.249.64.0/19"><?php echo esc_textarea($ops['protected_ips']); ?></textarea>
                        <p class="teg-switch-desc"><?php esc_html_e('Always protected as well: firewall whitelists, private ranges, this server and IPs admins logged in from (30 days).', 'tegatai-secure'); ?></p>
                        <p class="teg-switch-desc"><?php echo esc_html(sprintf(__('Active network bans: %d', 'tegatai-secure'), count($active_bans))); ?></p>
                    </div>
                </div>

                <div style="margin-top:20px; display: flex; gap: 10px; align-items: center;">
                    <button type="submit" class="button button-primary"><?php esc_html_e('Save Hive Configuration', 'tegatai-secure'); ?></button>
                    <button type="button" class="button button-secondary" id="test_hive_connections"><?php esc_html_e('Test Connections', 'tegatai-secure'); ?></button>
                    <span id="test_spinner" class="spinner" style="float: none; margin: 0;"></span>
                </div>
            </form>

            <div id="test_results" style="margin-top: 20px; display: none; padding: 16px; background: #fff; border: 1px solid var(--teg-border); border-left: 4px solid var(--teg-primary); border-radius: 6px; box-shadow: 0 1px 3px rgba(0,0,0,0.02);"></div>

            <script>
            document.addEventListener('DOMContentLoaded', function() {
                const input = document.getElementById('hive_secret_key');
                const btnGen = document.getElementById('generate_hive_key');
                const btnRev = document.getElementById('reveal_hive_key');
                const btnCop = document.getElementById('copy_hive_key');
                const btnTest = document.getElementById('test_hive_connections');
                const spinner = document.getElementById('test_spinner');
                const resultsDiv = document.getElementById('test_results');

                function triggerSudoAction(mode) {
                    const pin = prompt('Tegatai Sudo Vault: Please enter your TEGATAI_SUDO_PIN');
                    if (!pin) return;

                    const fd = new FormData();
                    fd.append('action', 'tegatai_sudo_hive');
                    fd.append('pin', pin);
                    fd.append('mode', mode);
                    fd.append('security', document.getElementById('tegatai_hive_sudo_nonce').value);

                    fetch(ajaxurl, { method: 'POST', body: fd })
                        .then(res => res.text())
                        .then(text => { 
                            let clean = text.substring(text.indexOf('{'));
                            return JSON.parse(clean); 
                        })
                        .then(data => {
                            if (!data.success) {
                                alert(data.data === 'SUDO_NOT_CONFIGURED' ? 'Error: TEGATAI_SUDO_PIN is not defined in wp-config.php.' : 'Sudo Access Denied: Invalid PIN.');
                                return;
                            }
                            input.value = data.data.key;
                            input.type = 'text';
                            if (btnCop) btnCop.style.display = 'inline-block';
                            if (mode === 'reveal' && btnRev) btnRev.style.display = 'none';
                        })
                        .catch(err => alert('Sudo Request failed: ' + err.message));
                }

                if (btnGen) {
                    btnGen.addEventListener('click', function(e) {
                        e.preventDefault();
                        triggerSudoAction('generate');
                    });
                }

                if (btnRev) {
                    btnRev.addEventListener('click', function(e) {
                        e.preventDefault();
                        triggerSudoAction('reveal');
                    });
                }

                if (btnCop) {
                    btnCop.addEventListener('click', function(e) {
                        e.preventDefault();
                        if(input.value === '') return;
                        
                        navigator.clipboard.writeText(input.value).then(() => {
                            const orig = btnCop.innerText; 
                            btnCop.innerText = '✔ <?php esc_html_e('Copied!', 'tegatai-secure'); ?>';
                            setTimeout(() => btnCop.innerText = orig, 2000);
                        }).catch(err => {
                            input.type = 'text'; input.select(); document.execCommand('copy'); input.type = 'password';
                            const orig = btnCop.innerText; 
                            btnCop.innerText = '✔ <?php esc_html_e('Copied!', 'tegatai-secure'); ?>';
                            setTimeout(() => btnCop.innerText = orig, 2000);
                        });
                    });
                }

                if (btnTest) {
                    btnTest.addEventListener('click', function(e) {
                        e.preventDefault();
                        spinner.classList.add('is-active');
                        resultsDiv.style.display = 'block';
                        resultsDiv.innerHTML = '<em style="font-size:13px; color:var(--teg-muted);"><?php esc_html_e('Signing payload and pinging nodes...', 'tegatai-secure'); ?></em>';

                        const fd = new FormData();
                        fd.append('action', 'tegatai_hive_test');
                        fd.append('security', '<?php echo wp_create_nonce('tegatai_hive_test_nonce'); ?>');

                        fetch(ajaxurl, { method: 'POST', body: fd })
                            .then(res => res.text())
                            .then(text => {
                                try {
                                    let jsonStr = text.trim();
                                    const jsonStart = jsonStr.indexOf('{');
                                    if (jsonStart > -1) jsonStr = jsonStr.substring(jsonStart);
                                    return JSON.parse(jsonStr);
                                } catch(err) {
                                    throw new Error(text.substring(0, 400));
                                }
                            })
                            .then(data => {
                                spinner.classList.remove('is-active');
                                if (!data || !data.success) {
                                    let errMsg = (data && data.data) ? data.data : 'Unbekannter Backend-Fehler';
                                    resultsDiv.innerHTML = '<span style="color: var(--teg-danger); font-weight:600;">✖ ' + errMsg + '</span>';
                                    return;
                                }
                                let html = '<strong style="font-size:14px;"><?php esc_html_e('Cryptographic Handshake Results:', 'tegatai-secure'); ?></strong><br><ul style="margin-top: 8px; margin-bottom: 0; font-size:13px; line-height:1.6;">';
                                data.data.forEach(item => {
                                    const color = item.status === 'success' ? 'var(--teg-success)' : 'var(--teg-danger)';
                                    const icon = item.status === 'success' ? '✔' : '✖';
                                    html += '<li style="color: ' + color + ';">' + icon + ' <strong>' + item.url + '</strong> &rarr; ' + item.msg + '</li>';
                                });
                                resultsDiv.innerHTML = html + '</ul>';
                            })
                            .catch(err => {
                                spinner.classList.remove('is-active');
                                resultsDiv.innerHTML = '<div style="background:#fffbeb; border-left:4px solid #b45309; padding:12px; margin-top:10px; border-radius:4px;"><strong style="color:#b45309;">Verbindungsfehler oder ungültige Server-Antwort:</strong><br><pre style="white-space:pre-wrap; margin:8px 0 0 0; font-family:monospace; font-size:11px; color:#333;">' + err.message + '</pre></div>';
                            });
                    });
                }
            });
            </script>
        </div>
        <?php
    }
}
