<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Hive {
    public function __construct() {
        add_action('rest_api_init', [$this, 'register_rest_route']);
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('tegatai_ip_banned', [$this, 'broadcast_ban'], 10, 3); // Added 3rd param for Level
        add_action('wp_ajax_tegatai_hive_test', [$this, 'ajax_test_connection']);
        add_action('wp_ajax_tegatai_sudo_hive', [$this, 'ajax_sudo_hive']);
    }

    public function register_rest_route() {
        register_rest_route('tegatai/v1', '/hive/receive', [
            'methods' => 'POST',
            'callback' => [$this, 'receive_ban'],
            'permission_callback' => '__return_true'
        ]);
    }

    public function receive_ban(WP_REST_Request $request) {
        $ops = get_option('tegatai_hive_options', []);
        if (empty($ops['enable_hive']) || empty((defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : '')))) {
            return new WP_Error('disabled', 'Hive network is disabled on this node.', ['status' => 403]);
        }

        // 1. Get RAW body and Signature
        $raw_body = $request->get_body();
        $signature = $request->get_header('X-Tegatai-Signature');

        if (empty($raw_body) || empty($signature)) {
            return new WP_Error('bad_request', 'Missing payload or signature.', ['status' => 400]);
        }

        // 2. Verify HMAC-SHA256 Signature
        $expected_signature = hash_hmac('sha256', $raw_body, (defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : '')));
        if (!hash_equals($expected_signature, $signature)) {
            return new WP_Error('unauthorized', 'HMAC Signature verification failed.', ['status' => 403]);
        }

        // 3. Decode Payload
        $data = json_decode($raw_body, true);
        if (json_last_error() !== JSON_ERROR_NONE || empty($data['timestamp']) || empty($data['req_id'])) {
            return new WP_Error('invalid_payload', 'Malformed payload data.', ['status' => 400]);
        }

        // 4. Replay Protection: Time Drift Check (Max 60 seconds)
        if (abs(time() - intval($data['timestamp'])) > 60) {
            return new WP_Error('replay_attack', 'Request expired (Time drift > 60s).', ['status' => 403]);
        }

        // 5. Spam/Double-Delivery Protection (Request ID)
        $transient_key = 'tg_hive_req_' . md5($data['req_id']);
        if (get_transient($transient_key)) {
            return new WP_Error('duplicate_request', 'Request ID already processed.', ['status' => 429]);
        }
        set_transient($transient_key, 1, 60);

        // Check if this is just a connectivity test
        if (!empty($data['is_test'])) {
            return rest_ensure_response(['success' => true, 'message' => 'HMAC Verified. Connection successful.']);
        }

        $ip = sanitize_text_field($data['ip'] ?? '');
        $reason = sanitize_text_field($data['reason'] ?? '');
        $level = sanitize_text_field($data['level'] ?? 'critical');

                                if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return new WP_Error('invalid_ip', 'Invalid IP address format.', ['status' => 400]);
        }

        // UNIVERSAL IMMUNITY: Niemals Localhost oder die eigene Server-IP sperren
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) {
            return new WP_Error('protected_ip', 'System critical IP addresses cannot be banned.', ['status' => 403]);
        }

        // UNIVERSAL IMMUNITY: Niemals Localhost oder die eigene Server-IP sperren
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) {
            return new WP_Error('protected_ip', 'System critical IP addresses cannot be banned.', ['status' => 403]);
        }

        // UNIVERSAL IMMUNITY: Niemals Localhost oder die eigene Server-IP sperren
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) {
            return new WP_Error('protected_ip', 'System critical IP addresses cannot be banned.', ['status' => 403]);
        }

        // Apply Ban based on Level (Currently logs all, blocks all - can be extended)
        $teg_ops = get_option('tegatai_options', []);
        $blacklist = isset($teg_ops['blacklist_ips']) ? $teg_ops['blacklist_ips'] : '';
        
        if (strpos($blacklist, $ip) === false) {
            $blacklist .= "\n" . $ip;
            $teg_ops['blacklist_ips'] = trim($blacklist);
            update_option('tegatai_options', $teg_ops);
            
            if (class_exists('Tegatai_Logger')) {
                Tegatai_Logger::log('HIVE-SYNC', "Applied network ban for $ip. Level: [$level]. Reason: $reason");
            }
        }

        return rest_ensure_response(['success' => true, 'message' => 'Threat successfully synced to local node.']);
    }

    public function broadcast_ban($ip, $reason = 'Malicious Activity', $level = 'critical') {
        $ops = get_option('tegatai_hive_options', []);
        if (empty($ops['enable_hive']) || empty((defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : ''))) || empty($ops['node_urls'])) {
            return;
        }

                                if (!filter_var($ip, FILTER_VALIDATE_IP)) return;

        // UNIVERSAL IMMUNITY: Sende niemals kritische System-IPs an das Netzwerk
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) return;

        // UNIVERSAL IMMUNITY: Sende niemals kritische System-IPs an das Netzwerk
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) return;

        // UNIVERSAL IMMUNITY: Sende niemals kritische System-IPs an das Netzwerk
        $server_ip = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $protected_ips = ['127.0.0.1', '::1', $server_ip];
        if (in_array($ip, $protected_ips)) return;

        $urls = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $ops['node_urls']))));
        if (empty($urls)) return;
        
        $secret = (defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : ''));
        $ssl_verify = isset($ops['ssl_verify']) ? (bool) $ops['ssl_verify'] : true;

        foreach ($urls as $url) {
            if (empty($url)) continue;
            $endpoint = rtrim($url, '/') . '/wp-json/tegatai/v1/hive/receive';
            
            // Build Payload
            $payload = [
                'ip' => $ip,
                'reason' => $reason,
                'level' => $level,
                'timestamp' => time(),
                'req_id' => bin2hex(random_bytes(16))
            ];
            $json_payload = wp_json_encode($payload);
            
            // Generate HMAC Signature
            $signature = hash_hmac('sha256', $json_payload, $secret);

            wp_remote_post($endpoint, [
                'blocking' => false,
                'timeout' => 2,
                'sslverify' => $ssl_verify,
                'headers' => [
                    'X-Tegatai-Signature' => $signature,
                    'Content-Type' => 'application/json; charset=utf-8'
                ],
                'body' => $json_payload
            ]);
        }
    }

    public function ajax_test_connection() {
        if (ob_get_length()) { ob_clean(); } // IMMUNITY: Strip external warnings (like Anzen)
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_hive_test_nonce', 'security');

        $ops = get_option('tegatai_hive_options', []);
        $secret = defined('TEGATAI_HIVE_SECRET') ? TEGATAI_HIVE_SECRET : (!empty($ops['shared_secret']) ? $ops['shared_secret'] : '');

        if (empty($ops['enable_hive']) || empty($secret) || empty($ops['node_urls'])) {
            if (ob_get_length()) { ob_clean(); }
            wp_send_json_error(__('Hive network is disabled or missing configuration.', 'tegatai-secure'));
        }

        $urls = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $ops['node_urls']))));
        $ssl_verify = isset($ops['ssl_verify']) ? (bool) $ops['ssl_verify'] : true;
        $results = [];

        foreach ($urls as $url) {
            if (empty($url)) continue;
            $endpoint = rtrim($url, '/') . '/wp-json/tegatai/v1/hive/receive';
            
            $payload = [
                'ip' => '127.0.0.1', 
                'reason' => 'Connection Test',
                'level' => 'low',
                'is_test' => true,
                'timestamp' => time(),
                'req_id' => bin2hex(random_bytes(16))
            ];
            $json_payload = wp_json_encode($payload);
            $signature = hash_hmac('sha256', $json_payload, $secret);

            $response = wp_remote_post($endpoint, [
                'blocking' => true,
                'timeout' => 5,
                'sslverify' => $ssl_verify,
                'headers' => [
                    'X-Tegatai-Signature' => $signature,
                    'Content-Type' => 'application/json; charset=utf-8'
                ],
                'body' => $json_payload
            ]);

            if (is_wp_error($response)) {
                $results[] = ['url' => $url, 'status' => 'error', 'msg' => $response->get_error_message()];
            } else {
                $code = wp_remote_retrieve_response_code($response);
                if ($code === 200) {
                    $results[] = ['url' => $url, 'status' => 'success', 'msg' => __('OK - HMAC Verified', 'tegatai-secure')];
                } elseif ($code === 403) {
                    $results[] = ['url' => $url, 'status' => 'error', 'msg' => __('HTTP 403 - Invalid Signature or Expired', 'tegatai-secure')];
                } else {
                    $results[] = ['url' => $url, 'status' => 'error', 'msg' => 'HTTP ' . $code];
                }
            }
        }
        
        if (ob_get_length()) { ob_clean(); } // IMMUNITY: Ensure pure JSON
        wp_send_json_success($results);
    }

    public function ajax_sudo_hive() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_ajax_referer('tegatai_hive_sudo_nonce', 'security');

        if (!defined('TEGATAI_SUDO_PIN')) {
            if (ob_get_length()) { ob_clean(); } wp_send_json_error('SUDO_NOT_CONFIGURED');
        }

        $pin = isset($_POST['pin']) ? sanitize_text_field($_POST['pin']) : '';
        // CRYPTO-UPGRADE: PIN gegen Bcrypt-Hash prüfen
        if (!password_verify($pin, TEGATAI_SUDO_PIN)) {
            if (ob_get_length()) { ob_clean(); } wp_send_json_error('INVALID_PIN');
        }

        // Serverseitige Generierung des Tokens
        $key = 'tg_hmac_' . bin2hex(random_bytes(32));
        if (ob_get_length()) { ob_clean(); } wp_send_json_success(['key' => $key]);
    }

    public function register_page() {
        add_submenu_page('tegatai-secure', __('The Hive', 'tegatai-secure'), __('The Hive', 'tegatai-secure'), 'manage_options', 'tegatai-hive', [$this, 'render_page']);
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
                'node_urls' => sanitize_textarea_field($_POST['node_urls'])
            ];
            update_option('tegatai_hive_options', $ops);
            echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Hive network settings updated successfully.', 'tegatai-secure') . '</p></div>';
        }

        $ops = get_option('tegatai_hive_options', ['enable_hive' => 0, 'ssl_verify' => 1, 'shared_secret' => '', 'node_urls' => '']);
        
        ?>
        <div class="wrap" style="max-width: 800px;">
            <h1 style="margin-bottom: 20px;">🌐 <?php esc_html_e('Tegatai Hive: Cryptographic Intelligence', 'tegatai-secure'); ?></h1>
            
            <div style="background: #fff; border: 1px solid #ccd0d4; padding: 20px; box-shadow: 0 1px 1px rgba(0,0,0,.04); margin-bottom: 20px;">
                <p><?php esc_html_e('The Hive uses HMAC-SHA256 payload signing, strict timestamps, and request IDs to create a zero-trust, replay-resistant defense grid.', 'tegatai-secure'); ?></p>
                
                <form method="post" action="">
                    <?php wp_nonce_field('save_hive_settings', 'tegatai_hive_nonce'); ?>
                    <div id="sudo_nonce_container"><?php wp_nonce_field('tegatai_hive_sudo_nonce', 'tegatai_hive_sudo_nonce'); ?></div>
                    
                    <table class="form-table">
                        <tr>
                            <th scope="row"><?php esc_html_e('Network Status', 'tegatai-secure'); ?></th>
                            <td>
                                <label style="margin-right: 15px;">
                                    <input type="checkbox" name="enable_hive" value="1" <?php checked($ops['enable_hive'], 1); ?>>
                                    <strong><?php esc_html_e('Enable Broadcast & Receive', 'tegatai-secure'); ?></strong>
                                </label>
                                <br><br>
                                <label>
                                    <input type="checkbox" name="ssl_verify" value="1" <?php checked($ops['ssl_verify'], 1); ?>>
                                    <?php esc_html_e('Enforce strict SSL verification (Uncheck only for self-signed certs/local nodes)', 'tegatai-secure'); ?>
                                </label>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('HMAC Shared Secret', 'tegatai-secure'); ?></th>
                            <td>
                                <?php if (defined('TEGATAI_HIVE_SECRET')) : ?>
                                    <div style="background: #f6fcf8; border-left: 4px solid #00a32a; padding: 10px;">
                                        <span style="color: #008a20; font-weight: bold;">🔒 <?php esc_html_e('Secret loaded from wp-config.php', 'tegatai-secure'); ?></span>
                                        <p style="margin: 5px 0 0 0; font-size: 13px;"><?php esc_html_e('The secret is active and secured. It is completely hidden from the UI and database.', 'tegatai-secure'); ?></p>
                                    </div>
                                <?php else : ?>
                                    <?php if (!empty($ops['shared_secret'])) : ?>
                                        <div style="background: #fff8e5; border-left: 4px solid #f0c33c; padding: 10px; margin-bottom: 10px;">
                                            <span style="color: #8a6d3b; font-weight: bold;">⚠️ <?php esc_html_e('Secret active in Database', 'tegatai-secure'); ?></span>
                                            <p style="margin: 5px 0 0 0; font-size: 13px;"><?php esc_html_e('A secret is active but stored in the database. For security reasons, it is not displayed here. We strongly recommend migrating it to wp-config.php.', 'tegatai-secure'); ?></p>
                                        </div>
                                    <?php endif; ?>
                                    <div style="display: flex; gap: 8px; align-items: center; margin-bottom: 5px;">
                                        <input type="password" name="shared_secret" id="hive_secret_key" value="" class="regular-text" autocomplete="new-password" placeholder="<?php echo !empty($ops['shared_secret']) ? '••••••••••••••••••••••••••••••••' : ''; ?>">
                                        <button type="button" class="button" id="generate_hive_key"><?php esc_html_e('Generate New', 'tegatai-secure'); ?></button>
                                        <button type="button" class="button" id="copy_hive_key" style="display: none;"><?php esc_html_e('Copy', 'tegatai-secure'); ?></button>
                                    </div>
                                    <p class="description"><?php esc_html_e('Leave blank to keep the current secret. Generate a new key only if you need to copy it to your wp-config.php.', 'tegatai-secure'); ?></p>
                                <?php endif; ?>
                            </td>
                        </tr>
                        <tr>
                            <th scope="row"><?php esc_html_e('Peer Node URLs', 'tegatai-secure'); ?></th>
                            <td>
                                <textarea name="node_urls" rows="5" class="large-text code" placeholder="https://example.com&#10;https://another-site.net"><?php echo esc_textarea($ops['node_urls']); ?></textarea>
                            </td>
                        </tr>
                    </table>
                    
                    <p class="submit" style="display: flex; gap: 10px; align-items: center;">
                        <button type="submit" class="button button-primary"><?php esc_html_e('Save Hive Configuration', 'tegatai-secure'); ?></button>
                        <button type="button" class="button" id="test_hive_connections"><?php esc_html_e('Test Connections', 'tegatai-secure'); ?></button>
                        <span id="test_spinner" class="spinner" style="float: none; margin: 0;"></span>
                    </p>
                </form>

                <div id="test_results" style="margin-top: 15px; display: none; padding: 10px; background: #f0f0f1; border-left: 4px solid #72aee6;"></div>

                <script>
                document.addEventListener('DOMContentLoaded', function() {
                    const input = document.getElementById('hive_secret_key');
                    const btnGen = document.getElementById('generate_hive_key');
                    const btnCop = document.getElementById('copy_hive_key');
                    const btnTest = document.getElementById('test_hive_connections');
                    const spinner = document.getElementById('test_spinner');
                    const resultsDiv = document.getElementById('test_results');

                    if (btnGen) {
                        btnGen.addEventListener('click', function(e) {
                            e.preventDefault();
                            const pin = prompt('Tegatai Sudo Vault: Please enter your TEGATAI_SUDO_PIN');
                            if (!pin) return;

                            const fd = new FormData();
                            fd.append('action', 'tegatai_sudo_hive');
                            fd.append('pin', pin);
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
                                })
                                .catch(err => alert('Sudo Request failed: ' + err.message));
                        });
                    }

                    if (btnCop) {
                        btnCop.addEventListener('click', function(e) {
                            e.preventDefault();
                            if(input.value === '') return;
                            input.type = 'text'; input.select(); document.execCommand('copy'); input.type = 'password';
                            const orig = this.innerText; this.innerText = '<?php esc_html_e('Copied!', 'tegatai-secure'); ?>';
                            setTimeout(() => this.innerText = orig, 2000);
                        });
                    }

                    if (btnTest) {
                        btnTest.addEventListener('click', function(e) {
                            e.preventDefault();
                            spinner.classList.add('is-active');
                            resultsDiv.style.display = 'block';
                            resultsDiv.innerHTML = '<em><?php esc_html_e('Signing payload and pinging nodes...', 'tegatai-secure'); ?></em>';

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
                                        throw new Error(text.substring(0, 400)); // Wirft den Error zum catch-Block!
                                    }
                                })
                                .then(data => {
                                    spinner.classList.remove('is-active');
                                    if (!data || !data.success) {
                                        let errMsg = (data && data.data) ? data.data : 'Unbekannter Backend-Fehler';
                                        resultsDiv.innerHTML = '<span style="color: #d63638;">✖ ' + errMsg + '</span>';
                                        return;
                                    }
                                    let html = '<strong><?php esc_html_e('Cryptographic Handshake Results:', 'tegatai-secure'); ?></strong><br><ul style="margin-top: 5px; margin-bottom: 0;">';
                                    data.data.forEach(item => {
                                        const color = item.status === 'success' ? '#00a32a' : '#d63638';
                                        const icon = item.status === 'success' ? '✔' : '✖';
                                        html += '<li style="color: ' + color + ';">' + icon + ' ' + item.url + ' &rarr; ' + item.msg + '</li>';
                                    });
                                    resultsDiv.innerHTML = html + '</ul>';
                                })
                                .catch(err => {
                                    spinner.classList.remove('is-active');
                                    resultsDiv.innerHTML = '<div style="background:#ffebe8; border-left:4px solid #c00; padding:10px; margin-top:10px;"><strong>Verbindungsfehler oder ungültige Server-Antwort:</strong><br><pre style="white-space:pre-wrap; margin:0; font-size:11px; color:#333;">' + err.message + '</pre></div>';
                                });
                        });
                    }
                });
                </script>
            </div>
        </div>
        <?php
    }
}
