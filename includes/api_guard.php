<?php
if (!defined('ABSPATH')) { exit; }

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
            return Tegatai_Logger::get_ip() ?: $_SERVER['REMOTE_ADDR'];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    public function protect_sync_routes() {
        $ops = get_option('tegatai_api_guard_options', []);
        $raw_endpoints = isset($ops['endpoints']) ? $ops['endpoints'] : '';
        if (empty(trim($raw_endpoints))) return;

        $endpoints = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $raw_endpoints))));
        if (empty($endpoints)) return;

        $uri = $_SERVER['REQUEST_URI'] ?? '';
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
        
        if (!defined('TEGATAI_SUDO_PIN')) {
             wp_send_json_error('SUDO_NOT_CONFIGURED');
        }
        $pin = isset($_POST['pin']) ? sanitize_text_field($_POST['pin']) : '';
        if (!password_verify($pin, TEGATAI_SUDO_PIN)) {
             wp_send_json_error('INVALID_PIN');
        }

        $mode = isset($_POST['mode']) ? sanitize_text_field($_POST['mode']) : 'reveal';
        
        if ($mode === 'generate') {
            $secret = bin2hex(random_bytes(32));
            update_option('tegatai_api_sync_secret', $secret, false);
        } else {
            $secret = get_option('tegatai_api_sync_secret');
        }

        wp_send_json_success(['secret' => $secret]);
    }

    public function register_page() {
        add_submenu_page('tegatai-Secure', __('API Guard', 'tegatai-Secure'), __('API Guard', 'tegatai-Secure'), 'manage_options', 'tegatai-api-guard', [$this, 'render_page']);
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
            echo '<div class="notice notice-success is-dismissible" style="margin-top:20px;"><p>' . esc_html__('API Gateway rules updated successfully.', 'tegatai-Secure') . '</p></div>';
        }
        
        $ops = get_option('tegatai_api_guard_options', ['endpoints' => '', 'match_mode' => 'contains', 'auth_mode' => 'static', 'enable_rate_limit' => 0, 'allowlist' => '']);
        $db_secret = get_option('tegatai_api_sync_secret');
        $is_locked = defined('TEGATAI_API_SECRET');
        $secret = $is_locked ? TEGATAI_API_SECRET : $db_secret;
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
                <div class="teg-title"><span class="dashicons dashicons-lock" style="font-size:32px;"></span> Tegatai API Gateway</div>
                <div class="teg-badge">v1.2</div>
            </div>

            <div class="teg-inner-nav">
                <a href="admin.php?page=tegatai-Secure&tab=dashboard" class="teg-back-btn">
                    <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Dashboard', 'tegatai-Secure'); ?>
                </a>
                <div class="teg-horizontal-tabs">
                    <span class="teg-h-tab active"><?php echo esc_html__('API Rules', 'tegatai-Secure'); ?></span>
                </div>
            </div>

            <form method="post" action="">
                <?php wp_nonce_field('save_api_guard', 'tegatai_api_guard_nonce'); ?>
                <input type="hidden" id="tegatai_api_sudo_nonce" value="<?php echo wp_create_nonce('tegatai_api_sudo_nonce'); ?>">
                
                <div class="teg-grid">
                    <div class="teg-card" style="grid-column: span 2;">
                        <h3><span class="dashicons dashicons-admin-network"></span> <?php esc_html_e('Master Sync Token', 'tegatai-Secure'); ?></h3>
                        <?php if ($is_locked) : ?>
                            <div style="background: #f0fdf4; border: 1px solid #bbf7d0; color: #166534; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                <strong>🔒 <?php esc_html_e('Secret loaded from wp-config.php', 'tegatai-Secure'); ?></strong><br>
                                <?php esc_html_e('The API token is active and secured. It is completely hidden from the UI.', 'tegatai-Secure'); ?>
                            </div>
                        <?php else: ?>
                            <?php if (!empty($secret)) : ?>
                                <div style="background: #fffbeb; border: 1px solid #fde68a; color: #b45309; padding: 12px; border-radius: 6px; font-size: 12px; margin-bottom:10px;">
                                    <strong>⚠️ <?php esc_html_e('Secret active in Database', 'tegatai-Secure'); ?></strong><br>
                                    <?php esc_html_e('An API token is stored in the database. We strongly recommend defining TEGATAI_API_SECRET in wp-config.php to lock it.', 'tegatai-Secure'); ?>
                                </div>
                            <?php endif; ?>
                            
                            <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 5px;">
                                <input type="password" id="api_secret_gen" class="teg-form-input" style="margin:0;" readonly value="" autocomplete="new-password" placeholder="<?php echo !empty($secret) ? '••••••••••••••••••••••••••••••••' : ''; ?>">
                            </div>
                            
                            <div style="display:flex; gap:8px; margin-bottom:10px; margin-top:8px;">
                                <?php if (!empty($secret)) : ?>
                                    <button type="button" class="button button-secondary" id="reveal_api_btn" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Reveal (Sudo)', 'tegatai-Secure'); ?></button>
                                <?php endif; ?>
                                <button type="button" class="button button-secondary" id="generate_api_btn" style="font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Generate New', 'tegatai-Secure'); ?></button>
                                <button type="button" class="button button-secondary" id="copy_api_btn" style="display: none; font-size:11px; padding:2px 8px !important;"><?php esc_html_e('Copy', 'tegatai-Secure'); ?></button>
                            </div>
                            <p class="teg-switch-desc"><?php esc_html_e('Generate a new key only if you need to copy it to your wp-config.php or client applications.', 'tegatai-Secure'); ?></p>
                        <?php endif; ?>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-randomize"></span> <?php esc_html_e('Routing & Authentication', 'tegatai-Secure'); ?></h3>
                        
                        <label class="teg-switch-label"><?php esc_html_e('Match Mode', 'tegatai-Secure'); ?></label>
                        <select name="match_mode" class="teg-form-input">
                            <option value="contains" <?php selected($ops['match_mode'], 'contains'); ?>><?php esc_html_e('Contains (e.g. sync.php)', 'tegatai-Secure'); ?></option>
                            <option value="exact" <?php selected($ops['match_mode'], 'exact'); ?>><?php esc_html_e('Exact Match (e.g. /wp-json/sync/start)', 'tegatai-Secure'); ?></option>
                            <option value="regex" <?php selected($ops['match_mode'], 'regex'); ?>><?php esc_html_e('Regex (ReDoS protected)', 'tegatai-Secure'); ?></option>
                        </select>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('Protected Endpoints', 'tegatai-Secure'); ?></label>
                        <textarea name="endpoints" class="teg-form-input" placeholder="/api/v1/sync"><?php echo esc_textarea($ops['endpoints']); ?></textarea>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('Auth Mode', 'tegatai-Secure'); ?></label>
                        <select name="auth_mode" id="auth_mode_selector" class="teg-form-input">
                            <option value="static" <?php selected($ops['auth_mode'], 'static'); ?>><?php esc_html_e('Static Token (Header / GET)', 'tegatai-Secure'); ?></option>
                            <option value="hmac" <?php selected($ops['auth_mode'], 'hmac'); ?>><?php esc_html_e('HMAC v2 (Timestamp + Req ID)', 'tegatai-Secure'); ?></option>
                        </select>
                        <p class="teg-switch-desc"><?php esc_html_e('HMAC enforces a 60-second rolling window signature.', 'tegatai-Secure'); ?></p>
                    </div>

                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-shield"></span> <?php esc_html_e('Traffic Control & Firewall', 'tegatai-Secure'); ?></h3>
                        
                        <div class="teg-switch-row">
                            <div><span class="teg-switch-label"><?php esc_html_e('Rate Limit (10/min, 50/hr)', 'tegatai-Secure'); ?></span></div>
                            <label class="switch"><input type="checkbox" name="enable_rate_limit" value="1" <?php checked($ops['enable_rate_limit'], 1); ?>><span class="slider"></span></label>
                        </div>
                        
                        <label class="teg-switch-label" style="margin-top:10px;"><?php esc_html_e('IP / CIDR Allowlist', 'tegatai-Secure'); ?></label>
                        <textarea name="allowlist" class="teg-form-input" placeholder="192.168.1.1&#10;10.0.0.0/24"><?php echo esc_textarea($ops['allowlist']); ?></textarea>
                        <p class="teg-switch-desc"><?php esc_html_e('Optional. If defined, ONLY these IPs can hit the endpoints. Everything else is dropped immediately.', 'tegatai-Secure'); ?></p>
                    </div>

                    <div class="teg-card" style="grid-column: 1 / -1; background: #fafafa;">
                        <h3 style="border-bottom: 1px solid #e5e7eb; padding-bottom: 10px;"><span class="dashicons dashicons-editor-code"></span> Integration Examples</h3>
                        
                        <div id="snippet_static" style="display: <?php echo $ops['auth_mode'] === 'static' ? 'block' : 'none'; ?>;">
                            <p style="font-size:12px; color:var(--teg-text); font-weight:600;">Static Header Mode:</p>
                            <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; border-radius: 6px; font-size:12px; overflow-x:auto;">curl -H "X-Tegatai-Sync: YOUR_SECRET" https://<?php echo $_SERVER['HTTP_HOST']; ?>/api</pre>
                        </div>
                        
                        <div id="snippet_hmac" style="display: <?php echo $ops['auth_mode'] === 'hmac' ? 'block' : 'none'; ?>;">
                            <p style="font-size:12px; color:var(--teg-text); font-weight:600;">HMAC v2 PHP Client (Sign URI + Timestamp + Req ID):</p>
                            <pre style="background: #1d2327; color: #a9b7c6; padding: 15px; border-radius: 6px; font-size:12px; overflow-x:auto;">$uri = '/api/sync';
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
                </div>

                <div style="margin-top:20px;">
                    <button type="submit" class="button button-primary"><?php esc_html_e('Save Gateway Rules', 'tegatai-Secure'); ?></button>
                </div>
            </form>
            
            <script>
            document.addEventListener('DOMContentLoaded', function() {
                const modeSelector = document.getElementById('auth_mode_selector');
                if (modeSelector) {
                    modeSelector.addEventListener('change', function() {
                        document.getElementById('snippet_static').style.display = this.value === 'static' ? 'block' : 'none';
                        document.getElementById('snippet_hmac').style.display = this.value === 'hmac' ? 'block' : 'none';
                    });
                }

                const input = document.getElementById('api_secret_gen');
                const btnRev = document.getElementById('reveal_api_btn');
                const btnGen = document.getElementById('generate_api_btn');
                const btnCop = document.getElementById('copy_api_btn');

                function triggerApiSudo(mode) {
                    const pin = prompt('Tegatai Sudo Vault: Please enter your TEGATAI_SUDO_PIN');
                    if (!pin) return;
                    
                    const fd = new FormData();
                    fd.append('action', 'tegatai_sudo_api'); 
                    fd.append('pin', pin); 
                    fd.append('mode', mode);
                    fd.append('security', document.getElementById('tegatai_api_sudo_nonce').value);
                    
                    fetch(ajaxurl, {method:'POST', body:fd})
                        .then(res => res.text())
                        .then(text => { let clean = text.substring(text.indexOf('{')); return JSON.parse(clean); })
                        .then(data => {
                            if (!data.success) { 
                                alert(data.data === 'SUDO_NOT_CONFIGURED' ? 'Error: TEGATAI_SUDO_PIN is not defined in wp-config.php.' : 'Sudo Access Denied: Invalid PIN.'); 
                                return; 
                            }
                            
                            input.value = data.data.secret; 
                            input.type = 'text';
                            
                            if (btnCop) btnCop.style.display = 'inline-block';
                            if (mode === 'reveal' && btnRev) btnRev.style.display = 'none';
                        }).catch(err => alert('Error: ' + err.message));
                }

                if (btnRev) {
                    btnRev.addEventListener('click', function(e) {
                        e.preventDefault();
                        triggerApiSudo('reveal');
                    });
                }

                if (btnGen) {
                    btnGen.addEventListener('click', function(e) {
                        e.preventDefault();
                        triggerApiSudo('generate');
                    });
                }

                if (btnCop) {
                    btnCop.addEventListener('click', function(e) {
                        e.preventDefault();
                        if(input.value === '') return;
                        
                        navigator.clipboard.writeText(input.value).then(() => {
                            const orig = btnCop.innerText; 
                            btnCop.innerText = '✔ <?php esc_html_e('Copied!', 'tegatai-Secure'); ?>';
                            setTimeout(() => btnCop.innerText = orig, 2000);
                        }).catch(err => {
                            input.type = 'text'; input.select(); document.execCommand('copy'); input.type = 'password';
                            const orig = btnCop.innerText; 
                            btnCop.innerText = '✔ <?php esc_html_e('Copied!', 'tegatai-Secure'); ?>';
                            setTimeout(() => btnCop.innerText = orig, 2000);
                        });
                    });
                }
            });
            </script>
        </div>
        <?php
    }
}
