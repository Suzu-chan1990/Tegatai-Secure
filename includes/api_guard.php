<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_API_Guard {
    public function __construct() {
        add_action('init', [$this, 'protect_sync_routes'], 1);
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('wp_ajax_tegatai_sudo_api', [$this, 'ajax_sudo_api']);
    }

    // 4. Memory Backend Abstraction (APCu > Redis/Memcached > DB)
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

    public function protect_sync_routes() {
        $ops = get_option('tegatai_api_guard_options', []);
        $raw_endpoints = isset($ops['endpoints']) ? $ops['endpoints'] : '';
        if (empty(trim($raw_endpoints))) return;

        $endpoints = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $raw_endpoints))));
        if (empty($endpoints)) return;

        $uri = $_SERVER['REQUEST_URI'];
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
                if (@preg_match('#' . str_replace('#', '\\#', $ep) . '#i', $uri)) {
                    $is_protected = true; break;
                }
            }
        }

        if (!$is_protected) return;

        if (php_sapi_name() === 'cli' || (defined('WP_CLI') && WP_CLI)) return;

        $ip = class_exists('Tegatai_Logger') ? Tegatai_Logger::get_ip() : $_SERVER['REMOTE_ADDR'];

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
            $m_key = 'tg_rl_m_' . md5($ip . $uri);
            $h_key = 'tg_rl_h_' . md5($ip . $uri);
            if ((int)$this->get_cache($m_key) >= 10 || (int)$this->get_cache($h_key) >= 50) {
                http_response_code(429); header('Retry-After: 60'); die('429 Too Many Requests');
            }
            $this->set_cache($m_key, ((int)$this->get_cache($m_key)) + 1, 60);
            $this->set_cache($h_key, ((int)$this->get_cache($h_key)) + 1, 3600);
        }

        $secret = defined('TEGATAI_API_SECRET') ? TEGATAI_API_SECRET : get_option('tegatai_api_sync_secret');
        if (empty($secret)) {
            http_response_code(500); die('500 Internal Error - API Guard not initialized');
        }

        $auth_mode = isset($ops['auth_mode']) ? $ops['auth_mode'] : 'static';
        $auth_passed = false;

        if ($auth_mode === 'hmac') {
            $ts = (int)($_SERVER['HTTP_X_TEGATAI_TIMESTAMP'] ?? 0);
            $sig = $_SERVER['HTTP_X_TEGATAI_SIGNATURE'] ?? '';
            $req_id = $_SERVER['HTTP_X_TEGATAI_REQ_ID'] ?? '';

            if (preg_match('/^[a-f0-9]{16,64}$/i', $req_id) && abs(time() - $ts) <= 60) {
                $nonce_key = 'tg_api_nonce_' . md5($req_id);
                if (!$this->get_cache($nonce_key)) {
                    $expected = hash_hmac('sha256', $uri . '|' . $ts . '|' . $req_id, $secret);
                    if (!empty($sig) && hash_equals($expected, $sig)) {
                        $this->set_cache($nonce_key, 1, 60);
                        $auth_passed = true;
                    }
                }
            }
        } else {
            $token = $_SERVER['HTTP_X_TEGATAI_SYNC'] ?? $_GET['sync_token'] ?? '';
            if (!empty($token) && hash_equals($secret, $token)) $auth_passed = true;
        }

        if (!$auth_passed) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('API-BLOCK', "Auth failed: $uri from $ip");
            sleep(random_int(6, 10)); 
            http_response_code(403); die('403 Forbidden');
        }
    }

    private function ip_in_range($ip, $range) {
        if (strpos($range, '/') === false) return $ip === $range;
        list($subnet, $bits) = explode('/', $range);
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            $ip_l = ip2long($ip); $sub_l = ip2long($subnet);
            $mask = -1 << (32 - $bits);
            return ($ip_l & $mask) == ($sub_l & $mask);
        }
        
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) && filter_var($subnet, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $ip_bin = inet_pton($ip); $sub_bin = inet_pton($subnet);
            $mask_bin = '';
            for ($i = 0; $i < 16; $i++) {
                $m = 0;
                if ($bits > 0) {
                    $m = (0xFF << (8 - min($bits, 8))) & 0xFF; $bits -= 8;
                }
                $mask_bin .= chr($m);
            }
            return ($ip_bin & $mask_bin) === ($sub_bin & $mask_bin);
        }
        return false;
    }

    public function ajax_sudo_api() {
        if (ob_get_length()) { ob_clean(); }
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_api_sudo_nonce', 'security');
        if (!defined('TEGATAI_SUDO_PIN') || !password_verify($_POST['pin'] ?? '', TEGATAI_SUDO_PIN)) {
             wp_send_json_error('INVALID_PIN');
        }
        $secret = get_option('tegatai_api_sync_secret');
        if (empty($secret)) {
            $secret = bin2hex(random_bytes(32));
            update_option('tegatai_api_sync_secret', $secret, false);
        }
        wp_send_json_success(['secret' => $secret]);
    }

    public function register_page() {
        add_submenu_page('tegatai-secure', __('API Guard', 'tegatai-secure'), __('API Guard', 'tegatai-secure'), 'manage_options', 'tegatai-api-guard', [$this, 'render_page']);
    }

    public function render_page() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        if (isset($_POST['tegatai_api_guard_nonce']) && wp_verify_nonce($_POST['tegatai_api_guard_nonce'], 'save_api_guard')) {
            update_option('tegatai_api_guard_options', [
                'endpoints' => sanitize_textarea_field($_POST['endpoints']),
                'match_mode' => sanitize_text_field($_POST['match_mode']),
                'auth_mode' => sanitize_text_field($_POST['auth_mode']),
                'enable_rate_limit' => isset($_POST['enable_rate_limit']) ? 1 : 0,
                'allowlist' => sanitize_textarea_field($_POST['allowlist'])
            ]);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('API Gateway rules updated successfully.', 'tegatai-secure') . '</p></div>';
        }
        
        $ops = get_option('tegatai_api_guard_options', ['endpoints' => '', 'match_mode' => 'contains', 'auth_mode' => 'static', 'enable_rate_limit' => 0, 'allowlist' => '']);
        $secret = defined('TEGATAI_API_SECRET') ? TEGATAI_API_SECRET : get_option('tegatai_api_sync_secret');
        ?>
        <div class="wrap" style="max-width: 800px;">
            <h1 style="margin-bottom: 20px;">🛡️ <?php esc_html_e('Tegatai API Gateway v2.2', 'tegatai-secure'); ?></h1>
            
            <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); margin-bottom: 20px;">
                <h2 style="margin-top: 0;"><?php esc_html_e('Master Sync Token', 'tegatai-secure'); ?></h2>
                <?php if (defined('TEGATAI_API_SECRET')) : ?>
                    <div style="background: #f6fcf8; border-left: 4px solid #00a32a; padding: 10px;">
                        <span style="color: #008a20; font-weight: bold;">🔒 <?php esc_html_e('Secret loaded from wp-config.php', 'tegatai-secure'); ?></span>
                        <p style="margin: 5px 0 0 0; font-size: 13px;"><?php esc_html_e('The API token is active and secured. It is completely hidden from the UI.', 'tegatai-secure'); ?></p>
                    </div>
                <?php else: ?>
                    <div style="background: #fff8e5; border-left: 4px solid #f0c33c; padding: 10px; margin-bottom: 15px;">
                        <span style="color: #8a6d3b; font-weight: bold;">⚠️ <?php esc_html_e('Secret active in Database', 'tegatai-secure'); ?></span>
                        <p style="margin: 5px 0 0 0; font-size: 13px;"><?php esc_html_e('An API token is stored in the database. Define TEGATAI_API_SECRET in wp-config.php to lock it.', 'tegatai-secure'); ?></p>
                    </div>
                    <div style="display: flex; gap: 8px; align-items: center;">
                        <input type="text" id="api_secret_gen" class="regular-text" readonly value="" style="display: none;">
                        <button type="button" class="button" id="reveal_api_btn"><?php esc_html_e('Reveal Token (Sudo Vault)', 'tegatai-secure'); ?></button>
                        <input type="hidden" id="tegatai_api_sudo_nonce" value="<?php echo wp_create_nonce('tegatai_api_sudo_nonce'); ?>">
                    </div>
                <?php endif; ?>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('save_api_guard', 'tegatai_api_guard_nonce'); ?>
                
                <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); margin-bottom: 20px;">
                    <h2 style="margin-top: 0;"><?php esc_html_e('Routing & Authentication', 'tegatai-secure'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Match Mode', 'tegatai-secure'); ?></th>
                            <td>
                                <select name="match_mode">
                                    <option value="contains" <?php selected($ops['match_mode'], 'contains'); ?>><?php esc_html_e('Contains (e.g. sync.php)', 'tegatai-secure'); ?></option>
                                    <option value="exact" <?php selected($ops['match_mode'], 'exact'); ?>><?php esc_html_e('Exact Match (e.g. /wp-json/sync/start)', 'tegatai-secure'); ?></option>
                                    <option value="regex" <?php selected($ops['match_mode'], 'regex'); ?>><?php esc_html_e('Regex (ReDoS protected)', 'tegatai-secure'); ?></option>
                                </select>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Protected Endpoints', 'tegatai-secure'); ?></th>
                            <td>
                                <textarea name="endpoints" rows="4" class="large-text code" placeholder="/api/v1/sync"><?php echo esc_textarea($ops['endpoints']); ?></textarea>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Auth Mode', 'tegatai-secure'); ?></th>
                            <td>
                                <select name="auth_mode" id="auth_mode_selector">
                                    <option value="static" <?php selected($ops['auth_mode'], 'static'); ?>><?php esc_html_e('Static Token (Header / GET param)', 'tegatai-secure'); ?></option>
                                    <option value="hmac" <?php selected($ops['auth_mode'], 'hmac'); ?>><?php esc_html_e('HMAC v2 (Signed Req ID + Timestamp)', 'tegatai-secure'); ?></option>
                                </select>
                                <p class="description"><?php esc_html_e('HMAC prevents replay attacks by enforcing a 60-second rolling window signature based on URI + Timestamp + Req ID.', 'tegatai-secure'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>

                <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); margin-bottom: 20px;">
                    <h2 style="margin-top: 0;"><?php esc_html_e('Traffic Control & Firewall', 'tegatai-secure'); ?></h2>
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Rate Limiting', 'tegatai-secure'); ?></th>
                            <td>
                                <label>
                                    <input type="checkbox" name="enable_rate_limit" value="1" <?php checked($ops['enable_rate_limit'], 1); ?>>
                                    <strong><?php esc_html_e('Enable Leaky Bucket (10 req/min, 50 req/hr)', 'tegatai-secure'); ?></strong>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('IP / CIDR Allowlist', 'tegatai-secure'); ?></th>
                            <td>
                                <textarea name="allowlist" rows="4" class="large-text code" placeholder="192.168.1.1&#10;10.0.0.0/24"><?php echo esc_textarea($ops['allowlist']); ?></textarea>
                                <p class="description"><?php esc_html_e('Optional. If defined, ONLY these IPs or CIDR ranges (IPv4/IPv6) can hit the endpoints. Everything else is dropped immediately.', 'tegatai-secure'); ?></p>
                            </td>
                        </tr>
                    </table>
                </div>

                <p class="submit">
                    <button type="submit" class="button button-primary"><?php esc_html_e('Save Gateway Rules', 'tegatai-secure'); ?></button>
                </p>
            </form>
            
            <div style="background: #eef6fc; border-left: 4px solid #0073aa; padding: 15px; margin-top: 20px;">
                <h3 style="margin-top: 0;">💻 Integration Examples</h3>
                <div id="snippet_static" style="display: <?php echo $ops['auth_mode'] === 'static' ? 'block' : 'none'; ?>;">
                    <p><strong>Static Header Mode:</strong></p>
                    <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; border-radius: 4px;">curl -H "X-Tegatai-Sync: YOUR_SECRET" https://<?php echo $_SERVER['HTTP_HOST']; ?>/api</pre>
                </div>
                <div id="snippet_hmac" style="display: <?php echo $ops['auth_mode'] === 'hmac' ? 'block' : 'none'; ?>;">
                    <p><strong>HMAC v2 PHP Client (Sign URI + Timestamp + Req ID):</strong></p>
                    <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; overflow-x: auto; border-radius: 4px;">$uri = '/api/sync';
$timestamp = time();
$req_id = bin2hex(random_bytes(16));
$signature = hash_hmac('sha256', $uri . '|' . $timestamp . '|' . $req_id, 'YOUR_SECRET');

$ch = curl_init('https://<?php echo $_SERVER['HTTP_HOST']; ?>' . $uri);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    "X-Tegatai-Timestamp: $timestamp",
    "X-Tegatai-Signature: $signature",
    "X-Tegatai-Req-Id: $req_id"
]);
curl_exec($ch);</pre>
                </div>
            </div>
            
            <script>
            document.addEventListener('DOMContentLoaded', function() {
                const modeSelector = document.getElementById('auth_mode_selector');
                if (modeSelector) {
                    modeSelector.addEventListener('change', function() {
                        document.getElementById('snippet_static').style.display = this.value === 'static' ? 'block' : 'none';
                        document.getElementById('snippet_hmac').style.display = this.value === 'hmac' ? 'block' : 'none';
                    });
                }

                const btn = document.getElementById('reveal_api_btn');
                if(btn) {
                    btn.addEventListener('click', function(e) {
                        e.preventDefault();
                        const pin = prompt('Tegatai Sudo Vault: Please enter your TEGATAI_SUDO_PIN');
                        if (!pin) return;
                        const fd = new FormData();
                        fd.append('action', 'tegatai_sudo_api'); fd.append('pin', pin); fd.append('security', document.getElementById('tegatai_api_sudo_nonce').value);
                        fetch(ajaxurl, {method:'POST', body:fd})
                            .then(res => res.text())
                            .then(text => { let clean = text.substring(text.indexOf('{')); return JSON.parse(clean); })
                            .then(data => {
                                if (!data.success) { alert('Sudo Access Denied or not configured.'); return; }
                                const input = document.getElementById('api_secret_gen');
                                input.value = data.data.secret; input.style.display = 'inline-block'; btn.style.display = 'none';
                            }).catch(err => alert('Error: ' + err.message));
                    });
                }
            });
            </script>
        </div>
        <?php
    }
}
