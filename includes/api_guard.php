<?php
if (!defined('ABSPATH')) { exit; }
// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- The firewall inspects the raw request on purpose (it may run before WordPress adds slashes); values are matched, never output unescaped, and SQL is prepared
// phpcs:disable WordPress.Security.NonceVerification -- Request inspection of the REST API gateway; it does not process forms

class Tegatai_API_Guard {
    public function __construct() {
        add_action('init', [$this, 'protect_sync_routes'], 1);
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('wp_ajax_tegatai_sudo_api', [$this, 'ajax_sudo_api']);
    }

    // Memory Backend Abstraction (APCu > Redis/Memcached > DB)
    private function get_cache($key) {
        if (function_exists('apcu_fetch')) return apcu_fetch($key);
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) return wp_cache_get($key, 'tegatai');
        return get_transient($key);
    }

    private function set_cache($key, $val, $ttl) {
        if (function_exists('apcu_store')) { apcu_store($key, $val, $ttl); return; }
        if (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) { wp_cache_set($key, $val, 'tegatai', $ttl); return; }
        set_transient($key, $val, $ttl);
    }

    // IP Fallback Wrapper
    private function get_client_ip() {
        if (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip')) {
            return Tegatai_Logger::get_ip() ?: tegatai_server_ip('REMOTE_ADDR');
        }
        // Validated IP or '' (never a default that could match a whitelisted address)
        return tegatai_server_ip('REMOTE_ADDR');
    }

    public function protect_sync_routes() {
        $ops = get_option('tegatai_api_guard_options', []);
        $raw_endpoints = isset($ops['endpoints']) ? $ops['endpoints'] : '';
        if (empty(trim($raw_endpoints))) return;

        $endpoints = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $raw_endpoints))));
        if (empty($endpoints)) return;

        $uri = tegatai_server_raw('REQUEST_URI');
        $match_mode = isset($ops['match_mode']) ? $ops['match_mode'] : 'contains';
        $is_protected = false;
        
        foreach ($endpoints as $ep) {
            if ($ep === '') continue;
            if ($match_mode === 'exact' && strtolower($uri) === strtolower($ep)) {
                $is_protected = true; break;
            } elseif ($match_mode === 'contains' && strpos(strtolower($uri), strtolower($ep)) !== false) {
                $is_protected = true; break;
            } elseif ($match_mode === 'regex') {
                if (strlen($ep) > 255 || preg_match('/(\\(.*?\\)\\*|\\(.*?\\)\\+)/', $ep)) continue;
                // @preg_match verhindert HTTP-Header Corruption bei defekten Regex-Patterns
                $matched = @preg_match('#' . str_replace('#', '\\#', $ep) . '#i', $uri);
                if ($matched === false) {
                    if (class_exists('Tegatai_Logger')) {
                        Tegatai_Logger::log('API-ERROR', "Regex failed (PCRE Err: " . preg_last_error() . ") for rule: $ep");
                    }
                } elseif ($matched) {
                    $is_protected = true; break;
                }
            }
        }

        if (!$is_protected) return;

        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) return;

        $ip = $this->get_client_ip();

        $raw_allowlist = isset($ops['allowlist']) ? $ops['allowlist'] : '';
        if (!empty(trim($raw_allowlist))) {
            $allowed_ips = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $raw_allowlist))));
            $ip_allowed = false;
            foreach ($allowed_ips as $allowed_ip) {
                if ($this->ip_in_range($ip, $allowed_ip)) {
                    $ip_allowed = true; break;
                }
            }
            if (!$ip_allowed) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('API-BLOCK', "IP rejection: $uri from $ip");
                http_response_code(403); die('403 Forbidden - IP Unauthorized');
            }
        }

        if (!empty($ops['enable_rate_limit'])) {
            $clean_uri = wp_parse_url($uri, PHP_URL_PATH);
            if (!$clean_uri) $clean_uri = $uri;
            
            $m_key = 'tg_rl_m_' . md5($ip . $clean_uri);
            $h_key = 'tg_rl_h_' . md5($ip . $clean_uri);
            if ((int)$this->get_cache($m_key) >= 10 || (int)$this->get_cache($h_key) >= 50) {
                http_response_code(429); header('Retry-After: 60'); die('429 Too Many Requests');
            }
            $this->set_cache($m_key, ((int)$this->get_cache($m_key)) + 1, 60);
            $this->set_cache($h_key, ((int)$this->get_cache($h_key)) + 1, 3600);
        }

        $secret = tegatai_secret('TEGATAI_API_SECRET');
        if (empty($secret)) {
            http_response_code(500); die('500 Internal Error - API Guard not initialized');
        }

        $auth_mode = isset($ops['auth_mode']) ? $ops['auth_mode'] : 'static';
        $auth_passed = false;

        if ($auth_mode === 'hmac') {
            // Signature v2: METHOD|REQUEST_URI|timestamp|req_id|sha256(raw body)
            // Method and body are covered, so an intercepted request cannot be reused with
            // a different verb or payload.
            $ts = (int) tegatai_server('HTTP_X_TEGATAI_TIMESTAMP', 20);
            $sig = (string) preg_replace('/[^a-f0-9]/i', '', tegatai_server('HTTP_X_TEGATAI_SIGNATURE', 128));
            $req_id = tegatai_server('HTTP_X_TEGATAI_REQ_ID', 128);

            if ($sig !== '' && preg_match('/^[a-f0-9]{16,64}$/i', $req_id) && abs(time() - $ts) <= self::HMAC_MAX_DRIFT) {
                $method = strtoupper(tegatai_server('REQUEST_METHOD', 10) ?: 'GET');
                $body = (string)file_get_contents('php://input');
                $string_to_sign = $method . '|' . $uri . '|' . $ts . '|' . strtolower($req_id) . '|' . hash('sha256', $body);
                $expected = hash_hmac('sha256', $string_to_sign, $secret);

                // Verify first, then claim the nonce atomically. The nonce must live as long
                // as the whole timestamp window (past + future drift), otherwise a request
                // signed with a future timestamp could be replayed after the nonce expired.
                if (hash_equals($expected, strtolower($sig))
                    && tegatai_claim_nonce('tg_api_nonce_' . md5(strtolower($req_id)), 2 * self::HMAC_MAX_DRIFT + 60)) {
                    $auth_passed = true;
                }
            }
        } else {
            $token = tegatai_server('HTTP_X_TEGATAI_SYNC', 256);
            if ($token === '' && isset($_GET['sync_token'])) $token = sanitize_text_field(wp_unslash((string) $_GET['sync_token'])); // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- authenticated by the token itself
            if (!empty($token) && is_string($token) && hash_equals($secret, $token)) $auth_passed = true;
        }

        if (!$auth_passed) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('API-BLOCK', "Auth failed: $uri from $ip");
            $this->tarpit();
            http_response_code(403); die('403 Forbidden');
        }
    }

    const HMAC_MAX_DRIFT = 60;

    /**
     * Delays failed auth attempts, but never ties up more than a few PHP workers at once.
     * An unbounded sleep() per failed request turns the tarpit into a DoS amplifier
     * against the PHP-FPM pool. Without an atomic counter backend there is no delay.
     */
    private function tarpit() {
        $max_slots = (int) apply_filters('tegatai_api_tarpit_max_concurrent', 2);
        if ($max_slots < 1) return;

        $key = 'tg_api_tarpit_slots';
        $ttl = 30; // self-healing if a worker dies before releasing its slot
        $release = null;

        if (function_exists('apcu_inc') && function_exists('apcu_enabled') && apcu_enabled()) {
            apcu_add($key, 0, $ttl);
            $slots = apcu_inc($key);
            $release = function () use ($key) { apcu_dec($key); };
        } elseif (function_exists('wp_using_ext_object_cache') && wp_using_ext_object_cache()) {
            wp_cache_add($key, 0, 'tegatai', $ttl);
            $slots = wp_cache_incr($key, 1, 'tegatai');
            $release = function () use ($key) { wp_cache_decr($key, 1, 'tegatai'); };
        } else {
            return;
        }

        if ($slots !== false && $slots <= $max_slots) {
            sleep(random_int(2, 4));
        }
        $release();
    }

    private function ip_in_range($ip, $range) {
        return Tegatai_Logger::ip_in_range($ip, trim($range));
    }

    public function ajax_sudo_api() {
        if (ob_get_length()) { ob_clean(); }
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_api_sudo_nonce', 'security');
        
        if (!defined('TEGATAI_SUDO_PIN')) {
             wp_send_json_error('SUDO_NOT_CONFIGURED');
        }
        $pin = isset($_POST['pin']) ? sanitize_text_field(wp_unslash($_POST['pin'])) : '';
        if (!password_verify($pin, TEGATAI_SUDO_PIN)) {
             wp_send_json_error('INVALID_PIN');
        }

        $mode = isset($_POST['mode']) ? sanitize_text_field(wp_unslash($_POST['mode'])) : 'reveal';
        
        // "generate" only creates a value to copy into the secrets file; secrets are never stored in the database.
        if ($mode === 'generate') {
            $secret = bin2hex(random_bytes(32));
        } else {
            $secret = tegatai_secret('TEGATAI_API_SECRET');
        }

        wp_send_json_success(['secret' => $secret]);
    }

    public function register_page() {
        add_submenu_page('tegatai-Secure', __('API Guard', 'tegatai-secure'), __('API Guard', 'tegatai-secure'), 'manage_options', 'tegatai-api-guard', [$this, 'render_page']);
    }

    public function render_page() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        if (isset($_POST['tegatai_api_guard_nonce']) && wp_verify_nonce(sanitize_key(wp_unslash($_POST['tegatai_api_guard_nonce'])), 'save_api_guard')) {
            update_option('tegatai_api_guard_options', [
                'endpoints' => sanitize_textarea_field(wp_unslash($_POST['endpoints'] ?? '')),
                'match_mode' => sanitize_text_field(wp_unslash($_POST['match_mode'] ?? '')),
                'auth_mode' => sanitize_text_field(wp_unslash($_POST['auth_mode'] ?? '')),
                'enable_rate_limit' => isset($_POST['enable_rate_limit']) ? 1 : 0,
                'allowlist' => sanitize_textarea_field(wp_unslash($_POST['allowlist'] ?? ''))
            ]);
            echo '<div class="notice notice-success is-dismissible" style="margin-top:20px;"><p>' . esc_html__('API Gateway rules updated successfully.', 'tegatai-secure') . '</p></div>';
        }
        
        $ops = get_option('tegatai_api_guard_options', ['endpoints' => '', 'match_mode' => 'contains', 'auth_mode' => 'static', 'enable_rate_limit' => 0, 'allowlist' => '']);
        $is_locked = defined('TEGATAI_API_SECRET');
        $secret = tegatai_secret('TEGATAI_API_SECRET');
        ?>

        <div class="teg-wrap">
            <div class="teg-header">
                <div class="teg-title"><span class="dashicons dashicons-lock" style="font-size:32px;"></span> Tegatai API Gateway</div>
                <div class="teg-badge">v1.2</div>
            </div>

            <div class="teg-inner-nav">
                <a href="admin.php?page=tegatai-Secure&tab=dashboard" class="teg-back-btn">
                    <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Dashboard', 'tegatai-secure'); ?>
                </a>
                <div class="teg-horizontal-tabs">
                    <span class="teg-h-tab active"><?php echo esc_html__('API Rules', 'tegatai-secure'); ?></span>
                </div>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('save_api_guard', 'tegatai_api_guard_nonce'); ?>
                <input type="hidden" id="tegatai_api_sudo_nonce" value="<?php echo esc_attr( wp_create_nonce('tegatai_api_sudo_nonce') ); ?>">
                
                <div class="teg-grid">
                    <div class="teg-card" style="grid-column: span 2;">
                        <h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e('Master Sync Token', 'tegatai-secure'); ?></h3>
                        <?php if ($is_locked) : ?>
                            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                <strong>🔒 <?php esc_html_e('Secret loaded from tegatai-secrets.php or wp-config.php', 'tegatai-secure'); ?></strong><br>
                                <?php esc_html_e('The API token is active and secured. It is completely hidden from the UI.', 'tegatai-secure'); ?>
                            </div>
                        <?php else: ?>
                            <?php if (!empty($secret)) : ?>
                                <div style="background: #fffbeb; border: 1px solid #fde68a; color: #b45309; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                    <strong>⚠️ <?php esc_html_e('Secret still in the database (older version)', 'tegatai-secure'); ?></strong><br>
                                    <?php esc_html_e('Copy it into the secrets file as TEGATAI_API_SECRET (command in the Secrets tab). It is then deleted from the database automatically.', 'tegatai-secure'); ?>
                                </div>
                            <?php endif; ?>
                            
                            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 5px;">
                                <input type="password" id="api_secret_gen" class="teg-form-input" style="margin:0;" readonly value="" autocomplete="new-password" placeholder="<?php echo !empty($secret) ? '••••••••••••••••••••••••••••••••' : ''; ?>">
                            </div>
                            
                            <div style="display:flex; gap:8px; margin-bottom:10px; margin-top:8px;">
                                <?php if (!empty($secret)) : ?>
                                    <button type="button" class="button button-secondary" id="reveal_api_btn" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Reveal (Sudo)', 'tegatai-secure'); ?></button>
                                <?php endif; ?>
                                <button type="button" class="button button-secondary" id="generate_api_btn" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Generate New', 'tegatai-secure'); ?></button>
                                <button type="button" class="button button-secondary" id="copy_api_btn" style="display: none; font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Copy', 'tegatai-secure'); ?></button>
                            </div>
                            <p class="teg-switch-desc"><?php esc_html_e('"Generate New" only shows a new random key; it is not saved. Put it into the secrets file as TEGATAI_API_SECRET and into your API clients.', 'tegatai-secure'); ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-randomize"></span> <?php esc_html_e('Routing & Authentication', 'tegatai-secure'); ?></h3>
                        
                        <label class="teg-switch-label"><?php esc_html_e('Match Mode', 'tegatai-secure'); ?></label>
                        <select name="match_mode" class="teg-form-input">
                            <option value="contains" <?php selected($ops['match_mode'], 'contains'); ?>><?php esc_html_e('Contains (e.g. sync.php)', 'tegatai-secure'); ?></option>
                            <option value="exact" <?php selected($ops['match_mode'], 'exact'); ?>><?php esc_html_e('Exact Match (e.g. /wp-json/sync/start)', 'tegatai-secure'); ?></option>
                            <option value="regex" <?php selected($ops['match_mode'], 'regex'); ?>><?php esc_html_e('Regex (ReDoS protected)', 'tegatai-secure'); ?></option>
                        </select>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('Protected Endpoints', 'tegatai-secure'); ?></label>
                        <textarea name="endpoints" class="teg-form-input" placeholder="/api/v1/sync"><?php echo esc_textarea($ops['endpoints']); ?></textarea>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('Auth Mode', 'tegatai-secure'); ?></label>
                        <select name="auth_mode" id="auth_mode_selector" class="teg-form-input">
                            <option value="static" <?php selected($ops['auth_mode'], 'static'); ?>><?php esc_html_e('Static Token (Header / GET)', 'tegatai-secure'); ?></option>
                            <option value="hmac" <?php selected($ops['auth_mode'], 'hmac'); ?>><?php esc_html_e('HMAC v2 (Method + URI + Timestamp + Req ID + Body)', 'tegatai-secure'); ?></option>
                        </select>
                        <p class="teg-switch-desc"><?php esc_html_e('HMAC enforces a 60-second rolling window signature.', 'tegatai-secure'); ?></p>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-shield"></span> <?php esc_html_e('Traffic Control & Firewall', 'tegatai-secure'); ?></h3>
                        
                        <div class="teg-switch-row">
                            <div><span class="teg-switch-label"><?php esc_html_e('Rate Limit (10/min, 50/hr)', 'tegatai-secure'); ?></span></div>
                            <label class="switch"><input type="checkbox" name="enable_rate_limit" value="1" <?php checked($ops['enable_rate_limit'], 1); ?>><span class="slider"></span></label>
                        </div>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('IP / CIDR Allowlist', 'tegatai-secure'); ?></label>
                        <textarea name="allowlist" class="teg-form-input" placeholder="192.168.1.1&#10;10.0.0.0/24"><?php echo esc_textarea($ops['allowlist']); ?></textarea>
                        <p class="teg-switch-desc"><?php esc_html_e('Optional. If defined, ONLY these IPs can hit the endpoints. Everything else is dropped immediately.', 'tegatai-secure'); ?></p>
                    </div>

                    <div class="teg-card" style="grid-column: 1 / -1; background: #fafafa;">
                        <h3 style="border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;"><span class="dashicons dashicons-editor-code"></span> Integration Examples</h3>
                        
                        <div id="snippet_static" style="display: <?php echo $ops['auth_mode'] === 'static' ? 'block' : 'none'; ?>;">
                            <p style="font-size:12px; color:var(--teg-text); font-weight:600;">Static Header Mode:</p>
                            <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; border-radius: 6px; font-size:12px; overflow-x:auto;">curl -H "X-Tegatai-Sync: YOUR_SECRET" https://<?php echo esc_html((string) wp_parse_url(home_url(), PHP_URL_HOST)); ?>/api</pre>
                        </div>
                        
                        <div id="snippet_hmac" style="display: <?php echo $ops['auth_mode'] === 'hmac' ? 'block' : 'none'; ?>;">
                            <p style="font-size:12px; color:var(--teg-text); font-weight:600;">HMAC v2 PHP Client (Sign Method + URI + Timestamp + Req ID + Body Hash):</p>
                            <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; border-radius: 6px; font-size:12px; overflow-x:auto;">$uri = '/api/sync';
$timestamp = time();
$req_id = bin2hex(random_bytes(16));
$body = json_encode(['example' => true]);
$signature = hash_hmac('sha256', 'POST|' . $uri . '|' . $timestamp . '|' . $req_id . '|' . hash('sha256', $body), 'YOUR_SECRET');

$ch = curl_init('https://<?php echo esc_html((string) wp_parse_url(home_url(), PHP_URL_HOST)); ?>' . $uri);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "Content-Type: application/json",
    "X-Tegatai-Timestamp: $timestamp",
    "X-Tegatai-Signature: $signature",
    "X-Tegatai-Req-Id: $req_id"
]);
curl_exec($ch);</pre>
                        </div>
                    </div>
                </div>

                <div style="margin-top:20px;">
                    <button type="submit" class="button button-primary"><?php esc_html_e('Save Gateway Rules', 'tegatai-secure'); ?></button>
                </div>
            </form>
            
        </div>
        <?php
    }
}
