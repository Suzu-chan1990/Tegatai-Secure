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
     * Peers are configured one per line as "URL", "URL | pair-secret" or "URL | ed25519:<public key>".
     * - ed25519 (protocol v2): the peer signs with its own private key; this node only knows the
     *   public key. A compromised peer can never impersonate another node, and messages are
     *   encrypted end to end (X25519 derived from the same keys).
     * - pair secret / shared secret (protocol v1, HMAC-SHA256): kept for nodes that are not
     *   switched yet. A pair secret is shared only between this node and that peer.
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
            $second = isset($parts[1]) ? $parts[1] : '';
            $pubkey = '';
            if (stripos($second, 'ed25519:') === 0) {
                $pubkey = self::decode_public_key(substr($second, 8));
                if ($pubkey === '') continue; // invalid key: never fall back to a weaker mode
                $second = '';
            }
            $peers[self::normalize_node($url)] = [
                'url'    => untrailingslashit($url),
                'secret' => $second,
                'pubkey' => $pubkey,
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

    // --- Ed25519 node key (protocol v2) ---

    public static function sodium_available() {
        return function_exists('sodium_crypto_sign_detached') && function_exists('sodium_crypto_box');
    }

    /**
     * Private key file next to tegatai-secrets.php (outside the web root).
     * Another location: define('TEGATAI_HIVE_KEY_FILE', '/path/tegatai-hive-key.php') in wp-config.php.
     */
    public static function key_file() {
        if (defined('TEGATAI_HIVE_KEY_FILE')) return (string) TEGATAI_HIVE_KEY_FILE;
        return dirname(tegatai_secrets_file()) . '/tegatai-hive-key.php';
    }

    /**
     * This node's Ed25519 secret key (64 bytes) or ''. Read from TEGATAI_HIVE_PRIVATE_KEY
     * (wp-config.php) or from the key file written by "wp tegatai hive-keygen".
     * Tegatai never creates this key on its own.
     */
    public static function own_secret_key() {
        static $key = null;
        if ($key !== null) return $key;
        $key = '';
        if (!self::sodium_available()) return $key;
        $b64 = '';
        if (defined('TEGATAI_HIVE_PRIVATE_KEY')) {
            $b64 = (string) TEGATAI_HIVE_PRIVATE_KEY;
        } else {
            $file = self::key_file();
            if ($file !== '' && @is_file($file) && @is_readable($file)) {
                $data = include $file;
                if (is_array($data) && isset($data['private_key']) && is_string($data['private_key'])) $b64 = $data['private_key'];
            }
        }
        $raw = base64_decode(preg_replace('/^ed25519:/i', '', trim($b64)), true);
        if (is_string($raw) && strlen($raw) === SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) $key = $raw;
        return $key;
    }

    /** Public key of this node as "ed25519:<base64>" or ''. */
    public static function own_public_key() {
        $sk = self::own_secret_key();
        return $sk === '' ? '' : 'ed25519:' . base64_encode(sodium_crypto_sign_publickey_from_secretkey($sk));
    }

    private static function decode_public_key($b64) {
        if (!self::sodium_available()) return '';
        $raw = base64_decode(trim((string) $b64), true);
        return (is_string($raw) && strlen($raw) === SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) ? $raw : '';
    }

    /**
     * Creates a new key pair and writes the private key to the key file (0600, folder 0700).
     * Only called by the WP-CLI command the admin runs explicitly. Refuses to overwrite an
     * existing key unless $replace is true. Returns the public key or a WP_Error.
     */
    public static function write_new_key($replace = false) {
        if (!self::sodium_available()) return new WP_Error('sodium', 'The PHP sodium extension is missing.');
        if (defined('TEGATAI_HIVE_PRIVATE_KEY')) return new WP_Error('constant', 'TEGATAI_HIVE_PRIVATE_KEY is set in wp-config.php; remove it there first.');
        $file = self::key_file();
        if (@is_file($file) && !$replace) return new WP_Error('exists', 'A key already exists: ' . $file . ' (use --replace to create a new one; all peers then need the new public key).');
        $dir_ok = tegatai_secure_key_dir(dirname($file));
        if (is_wp_error($dir_ok)) return $dir_ok;

        $pair = sodium_crypto_sign_keypair();
        $sk   = sodium_crypto_sign_secretkey($pair);
        $pk   = sodium_crypto_sign_publickey($pair);
        $php  = "<?php\n// Tegatai Hive private key (Ed25519) of " . home_url() . ". Never share or copy this file to another site.\n"
              . "if ( ! defined( 'ABSPATH' ) ) exit;\n"
              . "return [ 'private_key' => '" . base64_encode($sk) . "', 'created' => '" . gmdate('c') . "' ];\n";
        sodium_memzero($sk);
        sodium_memzero($pair);

        $written = tegatai_write_key_file($file, $php);
        sodium_memzero($php);
        if (is_wp_error($written)) return $written;
        return 'ed25519:' . base64_encode($pk);
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

        $peers = self::get_peers($ops);
        $peer = ($claimed_node !== '' && isset($peers[$claimed_node])) ? $peers[$claimed_node] : null;

        if (stripos($signature, 'ed25519:') === 0) {
            return $this->receive_v2($raw_body, substr($signature, 8), $claimed_node, $peer, $ops);
        }

        // Protocol v1 (HMAC). A peer with an Ed25519 key must never be accepted over HMAC (downgrade).
        if ($peer && !empty($peer['pubkey'])) {
            return new WP_Error('unauthorized', 'This peer uses Ed25519; HMAC is not accepted.', ['status' => 403]);
        }

        // Pick the key by the claimed sender. Unknown or anonymous senders are only accepted
        // with the shared secret, and only while strict peer mode is off (legacy nodes).
        if ($peer) {
            $secret = self::secret_for_peer($peer, $ops);
            $node_label = $peer['url'];
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
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data) || empty($data['timestamp']) || empty($data['req_id'])) {
            return new WP_Error('invalid_payload', 'Malformed payload data.', ['status' => 400]);
        }

        // The signed node must match the header, otherwise a peer could relay foreign payloads.
        if (isset($data['node']) && self::normalize_node($data['node']) !== $claimed_node) {
            return new WP_Error('invalid_payload', 'Node mismatch.', ['status' => 403]);
        }
        // Since 2.0 the recipient is signed too: a message for another node is rejected
        // (older senders do not send it yet).
        if (isset($data['to']) && self::normalize_node($data['to']) !== self::normalize_node(home_url())) {
            return new WP_Error('invalid_payload', 'Message is addressed to another node.', ['status' => 403]);
        }

        $check = self::check_fresh($data);
        if (is_wp_error($check)) return $check;

        return self::apply_payload($data, $node_label, $ops);
    }

    /**
     * Protocol v2: Ed25519 signature over the raw body, payload encrypted with crypto_box
     * (X25519 keys derived from both nodes' Ed25519 keys). Only configured peers with a key.
     */
    private function receive_v2($raw_body, $signature_b64, $claimed_node, $peer, $ops) {
        if (!$peer || empty($peer['pubkey'])) {
            return new WP_Error('unknown_peer', 'Sender is not a configured Ed25519 peer.', ['status' => 403]);
        }
        $sk = self::own_secret_key();
        if ($sk === '') {
            return new WP_Error('no_key', 'This node has no Hive key yet (wp tegatai hive-keygen).', ['status' => 403]);
        }
        $sig = base64_decode(trim($signature_b64), true);
        if (!is_string($sig) || strlen($sig) !== SODIUM_CRYPTO_SIGN_BYTES || !sodium_crypto_sign_verify_detached($sig, $raw_body, $peer['pubkey'])) {
            return new WP_Error('unauthorized', 'Ed25519 signature verification failed.', ['status' => 403]);
        }

        $data = json_decode($raw_body, true);
        if (!is_array($data) || (int)($data['v'] ?? 0) !== 2 || empty($data['timestamp']) || empty($data['req_id']) || empty($data['nonce']) || empty($data['box'])) {
            return new WP_Error('invalid_payload', 'Malformed payload data.', ['status' => 400]);
        }
        if (self::normalize_node($data['node'] ?? '') !== $claimed_node) {
            return new WP_Error('invalid_payload', 'Node mismatch.', ['status' => 403]);
        }
        if (self::normalize_node($data['to'] ?? '') !== self::normalize_node(home_url())) {
            return new WP_Error('invalid_payload', 'Message is addressed to another node.', ['status' => 403]);
        }

        $check = self::check_fresh($data);
        if (is_wp_error($check)) return $check;

        $nonce = base64_decode((string)$data['nonce'], true);
        $box   = base64_decode((string)$data['box'], true);
        $plain = false;
        if (is_string($nonce) && strlen($nonce) === SODIUM_CRYPTO_BOX_NONCEBYTES && is_string($box)) {
            $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey(
                sodium_crypto_sign_ed25519_sk_to_curve25519($sk),
                sodium_crypto_sign_ed25519_pk_to_curve25519($peer['pubkey'])
            );
            $plain = sodium_crypto_box_open($box, $nonce, $kp);
            sodium_memzero($kp);
        }
        $payload = is_string($plain) ? json_decode($plain, true) : null;
        if (!is_array($payload)) {
            return new WP_Error('unauthorized', 'Payload could not be decrypted.', ['status' => 403]);
        }

        return self::apply_payload($payload, $peer['url'], $ops);
    }

    /** Timestamp window and one-time request ID (replay protection), same for v1 and v2. */
    private static function check_fresh(array $data) {
        if (abs(time() - intval($data['timestamp'])) > 60) {
            return new WP_Error('replay_attack', 'Request expired (Time drift > 60s).', ['status' => 403]);
        }
        // Atomic claim; the nonce outlives the full ±60 s timestamp window.
        if (!tegatai_claim_nonce('tg_hive_req_' . md5((string)$data['req_id']), 180)) {
            return new WP_Error('duplicate_request', 'Request ID already processed.', ['status' => 429]);
        }
        return true;
    }

    /** Applies a verified ban (or answers a connection test). */
    private static function apply_payload(array $data, $node_label, $ops) {
        if (!empty($data['is_test'])) {
            return rest_ensure_response(['success' => true, 'message' => 'Signature verified. Connection successful.']);
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

        if (self::store_ban($ip, $node_label, $reason, $level, self::ban_ttl($ops))) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIVE-SYNC', "Applied network ban for $ip from $node_label. Level: [$level]. Reason: $reason");
            // New ban from a peer (not re-broadcast); used by the AbuseIPDB reporter
            do_action('tegatai_hive_ban_applied', $ip, $reason, $level, $node_label);
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
                'url' => self::endpoint_url($peer['url']),
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

    /**
     * Sends a payload to a peer: Ed25519 + encryption when the peer has a public key (v2),
     * otherwise HMAC (v1). Returns the HTTP response or a WP_Error.
     */
    private static function send_to_peer(array $peer, array $payload, $ops, $ssl_verify, $timeout) {
        $url = self::endpoint_url($peer['url']);
        if (!empty($peer['pubkey'])) {
            $sk = self::own_secret_key();
            if ($sk === '') return new WP_Error('no_key', __('This node has no Hive key yet (wp tegatai hive-keygen).', 'tegatai-secure'));
            return self::send_v2($url, $peer, $payload, $sk, $ssl_verify, $timeout);
        }
        $secret = self::secret_for_peer($peer, $ops);
        if (empty($secret)) return new WP_Error('no_secret', __('No secret configured for this peer', 'tegatai-secure'));
        return self::send_signed($url, $payload, $secret, $ssl_verify, $timeout, $peer['url']);
    }

    /**
     * Hive endpoint of a peer. The plain REST form (?rest_route=) works on every WordPress site,
     * also when /wp-json/ is renamed (WP Masking), blocked by server rules or taken over by
     * maintenance or caching plugins. Only the route is in the URL; the message itself is in
     * the POST body, signed and (v2) encrypted, and the connection uses HTTPS.
     */
    public static function endpoint_url($peer_url) {
        return untrailingslashit((string) $peer_url) . '/?rest_route=/tegatai/v1/hive/receive';
    }

    /**
     * Interprets a peer's answer. Only a JSON answer of the Hive endpoint counts:
     * a plain HTTP 200 (e.g. a redirect target, a cached page or a proxy) is not a delivery.
     * Returns ['ok' => bool, 'final' => bool (do not retry), 'msg' => string].
     */
    private static function read_answer($response) {
        if (is_wp_error($response)) return ['ok' => false, 'final' => false, 'msg' => $response->get_error_message()];
        $code = (int) wp_remote_retrieve_response_code($response);
        if ($code >= 300 && $code < 400) {
            $loc = (string) wp_remote_retrieve_header($response, 'location');
            return ['ok' => false, 'final' => false, 'msg' => sprintf('HTTP %d redirect to %s - the Hive endpoint must answer directly (check the peer URL, www/https and server rules)', $code, $loc !== '' ? $loc : '?')];
        }
        $json = json_decode((string) wp_remote_retrieve_body($response), true);
        if (!is_array($json)) {
            return ['ok' => false, 'final' => false, 'msg' => sprintf('HTTP %d, but no answer from the Tegatai Hive endpoint (Tegatai 2.0 not active there, cache or proxy in between?)', $code)];
        }
        if ($code === 200 && !empty($json['success'])) {
            return ['ok' => true, 'final' => true, 'msg' => (string) ($json['message'] ?? 'OK')];
        }
        // A real refusal of the endpoint (signature, protected IP, duplicate …): retrying does not help
        $final = isset($json['code']) && in_array($code, [400, 403, 429], true);
        return ['ok' => false, 'final' => $final, 'msg' => sprintf('HTTP %d %s', $code, sanitize_text_field((string) ($json['message'] ?? '')))];
    }

    private static function send_v2($url, array $peer, array $payload, $sk, $ssl_verify, $timeout) {
        $nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES);
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey(
            sodium_crypto_sign_ed25519_sk_to_curve25519($sk),
            sodium_crypto_sign_ed25519_pk_to_curve25519($peer['pubkey'])
        );
        $box = sodium_crypto_box(wp_json_encode($payload), $nonce, $kp);
        sodium_memzero($kp);

        $body = wp_json_encode([
            'v'         => 2,
            'node'      => home_url(),
            'to'        => $peer['url'],
            'timestamp' => time(),
            'req_id'    => bin2hex(random_bytes(16)),
            'nonce'     => base64_encode($nonce),
            'box'       => base64_encode($box),
        ]);

        return wp_remote_post($url, [
            'blocking' => true,
            'redirection' => 0, // a redirect turns the POST into a GET on another page; never follow it
            'timeout' => $timeout,
            'sslverify' => $ssl_verify,
            'headers' => [
                'X-Tegatai-Signature' => 'ed25519:' . base64_encode(sodium_crypto_sign_detached($body, $sk)),
                'X-Tegatai-Node' => home_url(),
                'X-Tegatai-Version' => '2',
                'Content-Type' => 'application/json; charset=utf-8'
            ],
            'body' => $body
        ]);
    }

    private static function send_signed($url, array $payload, $secret, $ssl_verify, $timeout, $to = '') {
        $payload['node'] = home_url();
        if ($to !== '') $payload['to'] = $to; // recipient is signed too (ignored by nodes before 2.0)
        $payload['timestamp'] = time();
        $payload['req_id'] = bin2hex(random_bytes(16));
        $json_payload = wp_json_encode($payload);

        return wp_remote_post($url, [
            'blocking' => true,
            'redirection' => 0, // a redirect turns the POST into a GET on another page; never follow it
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

            // Peers removed from the list are not contacted any more
            $peer = isset($item['peer'], $peers[$item['peer']]) ? $peers[$item['peer']] : null;
            if (!$peer || empty($item['payload']) || !is_array($item['payload'])) continue;

            $payload = array_intersect_key($item['payload'], array_flip(['ip', 'reason', 'level']));
            $response = self::send_to_peer($peer, $payload, $ops, $ssl_verify, 5);
            if (is_wp_error($response) && in_array($response->get_error_code(), ['no_key', 'no_secret'], true)) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIVE-QUEUE', "Dropped payload for {$peer['url']}: " . $response->get_error_message());
                continue;
            }
            $answer = self::read_answer($response);

            if ($answer['ok']) {
                if ($retries > 0 && class_exists('Tegatai_Logger')) {
                    Tegatai_Logger::log('HIVE-RETRY', "Successfully delivered delayed payload to " . $item['url']);
                }
                continue;
            }
            // Refused by the peer's Hive endpoint (protected IP, duplicate, signature): retrying would not help.
            if ($answer['final']) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('HIVE-QUEUE', "Peer {$item['url']} refused the payload: {$answer['msg']}");
                continue;
            }

            $item['retries'] = $retries + 1;
            $new_queue[] = $item;
            if (class_exists('Tegatai_Logger')) {
                Tegatai_Logger::log('HIVE-QUEUE', "Failed to deliver to {$item['url']} ({$answer['msg']}). Will retry.");
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
            $response = self::send_to_peer($peer, [
                'ip' => '127.0.0.1',
                'reason' => 'Connection Test',
                'level' => 'low',
                'is_test' => true,
            ], $ops, $ssl_verify, 5);

            // Success only when the peer's Hive endpoint itself confirms the verified message
            $answer = self::read_answer($response);
            if ($answer['ok']) {
                $results[] = ['url' => $peer['url'], 'status' => 'success', 'msg' => !empty($peer['pubkey']) ? __('OK - Ed25519 verified, encrypted', 'tegatai-secure') : __('OK - HMAC Verified', 'tegatai-secure')];
            } else {
                $results[] = ['url' => $peer['url'], 'status' => 'error', 'msg' => $answer['msg']];
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

        $pin = isset($_POST['pin']) ? sanitize_text_field(wp_unslash($_POST['pin'])) : '';
        if (!password_verify($pin, TEGATAI_SUDO_PIN)) {
             wp_send_json_error('INVALID_PIN');
        }

        $mode = isset($_POST['mode']) ? sanitize_text_field(wp_unslash($_POST['mode'])) : 'reveal';
        
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

        if (isset($_POST['tegatai_hive_nonce']) && wp_verify_nonce(sanitize_key(wp_unslash($_POST['tegatai_hive_nonce'])), 'save_hive_settings')) {
            $current_ops = get_option('tegatai_hive_options', []);
            $new_secret = isset($_POST['shared_secret']) ? sanitize_text_field(wp_unslash($_POST['shared_secret'])) : '';
            $ops = [
                'enable_hive' => isset($_POST['enable_hive']) ? 1 : 0,
                'ssl_verify' => isset($_POST['ssl_verify']) ? 1 : 0,
                'shared_secret' => !empty($new_secret) ? $new_secret : (isset($current_ops['shared_secret']) ? $current_ops['shared_secret'] : ''),
                'node_urls' => sanitize_textarea_field(wp_unslash($_POST['node_urls'] ?? '')),
                'strict_peers' => isset($_POST['strict_peers']) ? 1 : 0,
                'ban_ttl_hours' => max(1, min(720, absint(wp_unslash($_POST['ban_ttl_hours'] ?? 24)))),
                'protected_ips' => sanitize_textarea_field(wp_unslash($_POST['protected_ips'] ?? '')),
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
                <div class="teg-badge">v2</div>
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
                        <p class="teg-switch-desc" style="margin-bottom:15px;"><?php esc_html_e('Nodes with an Ed25519 key sign every message with their own private key and encrypt it end to end; other nodes use HMAC-SHA256. Timestamps, request IDs and the signed recipient make messages replay-resistant.', 'tegatai-secure'); ?></p>
                        
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
                        <h3><span class="dashicons dashicons-lock"></span> <?php esc_html_e('Node Key (Ed25519)', 'tegatai-secure'); ?></h3>
                        <?php $own_pk = self::own_public_key(); ?>
                        <?php if (!self::sodium_available()) : ?>
                            <div style="background:#fef2f2; border:1px solid #fecaca; color:#991b1b; padding:12px; border-radius:6px; font-size:12px;"><?php esc_html_e('The PHP sodium extension is missing, Ed25519 is not available on this server.', 'tegatai-secure'); ?></div>
                        <?php elseif ($own_pk !== '') : ?>
                            <div style="background:#f0fdf4; border:1px solid #bbf7d0; color:#166534; padding:12px; border-radius:6px; font-size:12px; margin-bottom:10px;">
                                <strong>🔒 <?php esc_html_e('Private key loaded from the secrets folder or wp-config.php', 'tegatai-secure'); ?></strong><br>
                                <?php esc_html_e('Add this line to the peer list of every other node:', 'tegatai-secure'); ?>
                            </div>
                            <input type="text" readonly class="teg-form-input" style="font-family:monospace; font-size:11px;" onclick="this.select();" value="<?php echo esc_attr(home_url() . ' | ' . $own_pk); ?>">
                        <?php else : ?>
                            <div style="background:#fffbeb; border:1px solid #fde68a; color:#b45309; padding:12px; border-radius:6px; font-size:12px;">
                                <strong><?php esc_html_e('No node key yet.', 'tegatai-secure'); ?></strong><br>
                                <?php esc_html_e('Create it on the server as the site\'s PHP user (Tegatai never creates keys on its own). The private key is written to the secrets folder and never shown:', 'tegatai-secure'); ?>
                                <code style="display:block; margin-top:8px; word-break:break-all;">sudo -u &lt;fpm-user&gt; wp tegatai hive-keygen --path=<?php echo esc_html(untrailingslashit(ABSPATH)); ?></code>
                            </div>
                        <?php endif; ?>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e('HMAC Shared Secret', 'tegatai-secure'); ?></h3>
                        <p class="teg-switch-desc"><?php esc_html_e('Only used for peers without an Ed25519 key (nodes that are not switched yet).', 'tegatai-secure'); ?></p>
                        <?php if (defined('TEGATAI_HIVE_SECRET')) : ?>
                            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                <strong>🔒 <?php esc_html_e('Secret loaded from tegatai-secrets.php or wp-config.php', 'tegatai-secure'); ?></strong><br>
                                <?php esc_html_e('The secret is active and secured. It is hidden from the UI.', 'tegatai-secure'); ?>
                            </div>
                        <?php else : ?>
                            <?php if (!empty($ops['shared_secret'])) : ?>
                                <div style="background: #fffbeb; border: 1px solid #fde68a; color: #b45309; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                    <strong>⚠️ <?php esc_html_e('Secret active in Database', 'tegatai-secure'); ?></strong><br>
                                    <?php esc_html_e('For security reasons, it is not displayed here. We strongly recommend moving it to tegatai-secrets.php (outside the web root).', 'tegatai-secure'); ?>
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
                        <p class="teg-switch-desc"><?php esc_html_e('One peer per line: "URL | ed25519:public key" (recommended), "URL | pair secret" or "URL" (shared secret). Peers with a key are only accepted with their Ed25519 signature.', 'tegatai-secure'); ?></p>
                        <textarea name="node_urls" class="teg-form-input" placeholder="https://example.com | ed25519:...&#10;https://another-site.net | tg_hmac_..."><?php echo esc_textarea($ops['node_urls']); ?></textarea>
                        <?php
                        $peer_list = self::get_peers($ops);
                        if ($peer_list) {
                            $n_ed = count(array_filter($peer_list, function ($p) { return !empty($p['pubkey']); }));
                            echo '<p class="teg-switch-desc">' . esc_html(sprintf(/* translators: 1: peers with Ed25519, 2: all peers */ __('%1$d of %2$d peers use Ed25519.', 'tegatai-secure'), $n_ed, count($peer_list))) . '</p>';
                        }
                        ?>
                        <div class="teg-switch-row">
                            <div>
                                <span class="teg-switch-label"><?php esc_html_e('Strict peer mode', 'tegatai-secure'); ?></span>
                                <span class="teg-switch-desc" style="margin:0;"><?php esc_html_e('Only accept HMAC bans from listed peers that identify themselves. Ed25519 peers are always strict.', 'tegatai-secure'); ?></span>
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
                        <p class="teg-switch-desc"><?php echo esc_html(sprintf(/* translators: %d: number of active bans */ __('Active network bans: %d', 'tegatai-secure'), count($active_bans))); ?></p>
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
                                alert(data.data === 'SUDO_NOT_CONFIGURED' ? 'Error: TEGATAI_SUDO_PIN is not defined (tegatai-secrets.php or wp-config.php).' : 'Sudo Access Denied: Invalid PIN.');
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
                        fd.append('security', '<?php echo esc_js( wp_create_nonce('tegatai_hive_test_nonce') ); ?>');

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

/**
 * WP-CLI commands for the Hive node key. Run them as the site's FPM user, never as root,
 * so the key file belongs to the user PHP runs as:
 *   sudo -u <fpm-user> wp tegatai hive-keygen --path=/path/to/site
 */
if (defined('WP_CLI') && WP_CLI) {
    /**
     * Creates this node's Ed25519 key pair for The Hive.
     *
     * The private key is written to secrets/tegatai-hive-key.php next to tegatai-secrets.php
     * (file 0600, folder 0700) and is never printed. Only the public key is shown; add it to
     * the peer lists of the other nodes as "URL | ed25519:...".
     *
     * [--replace]
     * : Replace an existing key. All peers then need the new public key.
     */
    WP_CLI::add_command('tegatai hive-keygen', function ($args, $assoc) {
        $r = Tegatai_Hive::write_new_key(!empty($assoc['replace']));
        if (is_wp_error($r)) WP_CLI::error($r->get_error_message());
        WP_CLI::success('Private key written to ' . Tegatai_Hive::key_file());
        WP_CLI::log('Add this line to the peer list of every other node:');
        WP_CLI::log(home_url() . ' | ' . $r);
    });

    /**
     * Prints this node's public key line for the peer lists of the other nodes.
     */
    WP_CLI::add_command('tegatai hive-pubkey', function () {
        $pk = Tegatai_Hive::own_public_key();
        if ($pk === '') WP_CLI::error('No Hive key yet. Create one with: wp tegatai hive-keygen');
        WP_CLI::log(home_url() . ' | ' . $pk);
    });
}
