<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */
/* TEGATAI_DASHBOARD_TOP5_FORCE_V1 */
/* TEGATAI_SERVER_STATUS_EXPANDED_V1 */
/* TEGATAI_TRUSTED_DEVICES_PATCH_V2 */
/* TEGATAI_ADMIN_MOJIBAKE_REPAIR_V1 applied */
/* TEGATAI_ADMIN_EMBEDDED_I18N_FIX_V1 applied */
/* TEGATAI_ADMIN_PARSE_FIX_V1 applied */
/* TEGATAI_FIX_MOJIBAKE_QUICK_ACCESS_V1 applied */
/* TEGATAI_I18N_MOJIBAKE_FIX_V1 applied */
/* TEGATAI_I18N_DE_EN_V1 applied */
/* TEGATAI_HEADERS_CONFLICT_FIX_PLUS_PROBE_V2 applied */
/* TEGATAI_ADMIN_ROOT_WRITABLE_CHECK_V1 applied */
/* TEGATAI_FORCE_RULES_TO_WP_ROOT_V1 applied */
/* TEGATAI_ADMIN_INTEGRATION_CHECK_V1 applied */
/* TEGATAI_ADMIN_UI_TILES_V1 applied */
/* TEGATAI_SYNTAX_HEAL_FINAL_V1 applied */
/* TEGATAI_FROXLOR_TABS_UI_V1 applied */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Admin {
    private $options_slug = 'tegatai_options';
    
    private $all_fields = [
        'enable_waf', 'block_fake_bots', 'block_ai_bots', 'block_seo_bots', 'enable_upload_guard', 'enable_rate_limit', 'blacklist_ips', 'whitelist_ips', 'enable_404_block', 
        'hide_wp_version', 'disable_xmlrpc', 'disable_file_editor', 'block_user_enum', 'hide_login_errors', 
        'header_xfo', 'header_nosniff', 'header_xss', 'header_hsts', 'header_ref', 'header_csp', 'header_permissions', 
        'enable_2fa', 
        'custom_login_slug', 'block_default_login', 'block_dash_access', 'enable_idle_logout', 'block_wp_admin_hide', 
        'enable_login_limit', 'enable_trusted_devices', 'disable_app_passwords', 'enable_single_session',
        'enable_ip_guard', 'enable_browser_guard', 'session_max_lifetime', 
        'server_disable_indexing', 'server_protect_files', 'server_block_xmlrpc', 'server_hide_system_files', 'server_block_dotfiles',
        'enable_honeypot', 'enable_bot_timer', 'spam_max_links', 'spam_block_trashmail', 'spam_check_referrer',
        'enable_auto_backup', 'backup_frequency',
        'disable_rest_api', 'enable_copy_protection', 'enable_rightclick_disable',
        'geoip_mode', 'geoip_list', 'geoip_login_only',
        'enable_email_alerts', 'alert_email', 'waf_whitelist_urls',
        'server_disable_php_uploads', 'server_filter_bad_bots',
        'server_hotlink_protection', 'server_hotlink_whitelist', 'server_protected_dirs', 'scanner_exclusions',
        'enable_magic_links', 'enable_admin_honeypot', 'enable_role_guard', 'enable_turnstile', 'enable_auto_quarantine'
    ];

    public function __construct() {
        add_action('wp_ajax_teg_restore_quarantine', [$this, 'ajax_restore_quarantine']);
        add_action('wp_ajax_teg_delete_cron', [$this, 'ajax_delete_cron']);
        add_action('admin_post_tegatai_export_config', [$this, 'export_config']);
        add_action('wp_ajax_teg_import_config', [$this, 'ajax_import_config']);
        add_action('wp_ajax_teg_deep_clean', [$this, 'ajax_deep_clean']);
        add_action('wp_ajax_teg_heal_core', [$this, 'ajax_heal_core']);

        add_action('admin_menu', [$this, 'add_menu']);
        add_action('wp_dashboard_setup', [$this, 'add_dashboard_widgets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('wp_ajax_teg_toggle_option', [$this, 'ajax_toggle_option']);
        add_action('wp_ajax_teg_save_form', [$this, 'ajax_save_form']);
        add_action('admin_post_tegatai_write_rules', [$this, 'handle_write_rules']);
    }

    public function add_menu() {
        add_menu_page('Tegatai', 'Tegatai Secure', 'manage_options', 'tegatai-secure', [$this, 'render_page'], 'dashicons-shield-alt', 100);
    }

    public function register_settings() { register_setting('tegatai_group', $this->options_slug); }

    public function handle_write_rules() {
        check_admin_referer('teg_write_nonce');
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        Tegatai_Server::force_update();
        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=server&msg=rules_written'));
        exit;
    }

    public function ajax_toggle_option() {
        check_ajax_referer('teg_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Forbidden');
        $key = sanitize_text_field($_POST['key'] ?? ''); $val = sanitize_text_field($_POST['val'] ?? '');
        if (!$key || !in_array($key, $this->all_fields, true)) { wp_send_json_error('Invalid key'); }
        $ops = get_option($this->options_slug, []); $ops[$key] = ($val === '1') ? 1 : 0;
        if ($key === 'enable_trusted_devices' || $key === 'trusted_devices') {
            $ops['enable_trusted_devices'] = ($val === '1') ? 1 : 0;
            $ops['trusted_devices'] = ($val === '1') ? 1 : 0;
        }
        update_option($this->options_slug, $ops);
        if (strpos($key, 'server_') === 0) Tegatai_Server::force_update();
        wp_send_json_success(['message' => __('Saved successfully', 'tegatai-secure')]);
    }

    public function ajax_save_form() {
        check_ajax_referer('teg_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Forbidden');
        parse_str($_POST['form_data'] ?? '', $form_vars);
        $current_ops = get_option($this->options_slug, []); if (!is_array($current_ops)) $current_ops = [];
        $new_data = isset($form_vars['tegatai_options']) ? $form_vars['tegatai_options'] : [];
        if (!empty($new_data) && is_array($new_data)) {
            foreach ($new_data as $key => $value) {
                if (is_array($value)) $value = array_map('sanitize_text_field', $value);
                else $value = (strpos($key, 'ips') !== false || strpos($key, 'list') !== false || strpos($key, 'urls') !== false || strpos($key, 'whitelist') !== false || strpos($key, 'dirs') !== false || strpos($key, 'exclusions') !== false) ? sanitize_textarea_field($value) : sanitize_text_field($value);
                $current_ops[$key] = $value;
            }
            update_option($this->options_slug, $current_ops);
            wp_send_json_success(['message' => __('Data saved!', 'tegatai-secure')]);
        } else wp_send_json_error(['message' => __('No data provided.', 'tegatai-secure')]);
    }

    private function get_opt($key, $default = 0) {
        $ops = get_option($this->options_slug, []);
        return isset($ops[$key]) ? $ops[$key] : $default;
    }

    public function render_page() {
        $tab = $_GET['tab'] ?? 'dashboard';
        
        if (isset($_POST['teg_action']) && $_POST['teg_action'] == 'clear_logs') {
            check_admin_referer('teg_act_nonce'); Tegatai_Logger::clear();
        }
        if (isset($_POST['action']) && $_POST['action'] == 'tegatai_clear_history') {
             check_admin_referer('teg_hist_nonce'); Tegatai_UserHistory::clear_history();
        }

        // GRUPPEN UND TABS DEFINITION
        $nav_groups = [
            'protection' => [
                'title' => __('Protection & Firewall', 'tegatai-secure'),
                'icon' => 'dashicons-shield',
                'desc' => __('WAF, Login Guard, Anti-Spam, GeoIP Block', 'tegatai-secure'),
                'tabs' => [
                    'firewall' => __('WAF Firewall', 'tegatai-secure'),
                    'login' => __('Login Protection', 'tegatai-secure'),
                    'spam' => __('Anti-Spam', 'tegatai-secure'),
                    'geoip' => __('GeoIP Block', 'tegatai-secure')
                ]
            ],
            'server' => [
                'title' => __('Server & System', 'tegatai-secure'),
                'icon' => 'dashicons-networking',
                'desc' => __('Server Rules, HTTP Headers, System Hardening', 'tegatai-secure'),
                'tabs' => [
                    'server' => __('Server Rules', 'tegatai-secure'),
                    'headers' => __('HTTP Headers', 'tegatai-secure'),
                    'hardening' => __('Hardening', 'tegatai-secure')
                ]
            ],
            'scanner' => [
                'title' => __('Scanner & Checks', 'tegatai-secure'),
                'icon' => 'dashicons-search',
                'desc' => __('Malware, WP Core, FIM, Database, Uploads', 'tegatai-secure'),
                'tabs' => [
                    'scanner' => __('Main Scanner', 'tegatai-secure'),
                    'malware' => __('Malware', 'tegatai-secure'),
                    'core' => __('Core', 'tegatai-secure'),
                    'fim' => __('FIM', 'tegatai-secure'),
                    'dbscan' => __('DB XSS', 'tegatai-secure'),
                    'options' => __('Options', 'tegatai-secure'),
                    'cron' => __('Cron', 'tegatai-secure'),
                    'uploads' => __('Uploads', 'tegatai-secure'),
                    'perms' => __('Perms', 'tegatai-secure')
                ]
            ],
            'management' => [
                'title' => __('Management', 'tegatai-secure'),
                'icon' => 'dashicons-admin-generic',
                'desc' => __('IP Prison, Sessions, Backups, Extras & API', 'tegatai-secure'),
                'tabs' => [
                    'bans' => __('IP Prison', 'tegatai-secure'),
                    'sessions' => __('Sessions', 'tegatai-secure'),
                    'backups' => __('Backups', 'tegatai-secure'),
                    'extras' => __('Extras & API', 'tegatai-secure')
                ]
            ],
            'logs' => [
                'title' => __('Logs & Events', 'tegatai-secure'),
                'icon' => 'dashicons-list-view',
                'desc' => __('Live Traffic, Block Events, Security Timeline', 'tegatai-secure'),
                'tabs' => [
                    'logs' => __('Live Traffic', 'tegatai-secure'),
                    'timeline' => __('Timeline', 'tegatai-secure')
                ]
            ]
        ];

        $current_group = null;
        if ($tab !== 'dashboard') {
            foreach ($nav_groups as $g_id => $group) {
                if (array_key_exists($tab, $group['tabs'])) {
                    $current_group = $g_id;
                    break;
                }
            }
        }
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
            
            /* Kachel-Optik (Tile UI) für Content */
            .teg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 16px; align-items: start; }
            .teg-card { background: var(--teg-card); border-radius: 6px; padding: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid var(--teg-border); }
            .teg-card h3 { margin-top: 0; font-size: 12px; font-weight: 700; border-bottom: 1px solid var(--teg-border); padding-bottom: 10px; margin-bottom: 12px; text-transform: uppercase; color: var(--teg-muted); letter-spacing: 0.5px; }
            
            /* Main Dashboard Category Tiles */
            .teg-section-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-bottom: 30px; }
            .teg-section-card { background: var(--teg-surface); border: 1px solid var(--teg-border); border-radius: 10px; padding: 24px; text-decoration: none; color: inherit; display: flex; align-items: flex-start; gap: 16px; transition: all 0.2s; box-shadow: 0 2px 5px rgba(0,0,0,0.02); }
            .teg-section-card:hover { border-color: var(--teg-primary); box-shadow: 0 8px 20px rgba(6,182,212,0.1); transform: translateY(-3px); }
            .teg-section-icon { background: rgba(6,182,212,0.1); color: var(--teg-primary); width: 48px; height: 48px; border-radius: 12px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
            .teg-section-icon .dashicons { font-size: 24px; width: 24px; height: 24px; }
            .teg-section-info h3 { margin: 0 0 6px 0; font-size: 16px; font-weight: 700; color: var(--teg-text); }
            .teg-section-info p { margin: 0; font-size: 12px; color: var(--teg-muted); line-height: 1.5; }

            /* Horizontal Inner Nav */
            .teg-inner-nav { display: flex; align-items: center; background: var(--teg-surface); padding: 12px 20px; border-radius: 10px; border: 1px solid var(--teg-border); margin-bottom: 24px; overflow-x: auto; box-shadow: 0 1px 3px rgba(0,0,0,0.02); gap: 20px; }
            .teg-back-btn { display: inline-flex; align-items: center; gap: 6px; text-decoration: none; color: var(--teg-text); font-weight: 700; font-size: 13px; border-right: 1px solid var(--teg-border); padding-right: 20px; transition: 0.2s; white-space: nowrap; }
            .teg-back-btn:hover { color: var(--teg-primary); }
            .teg-horizontal-tabs { display: flex; align-items: center; gap: 10px; }
            .teg-h-tab { padding: 8px 16px; border-radius: 6px; text-decoration: none; color: var(--teg-muted); font-size: 13px; font-weight: 600; white-space: nowrap; transition: 0.2s; border: 1px solid transparent; }
            .teg-h-tab:hover { background: var(--teg-bg); color: var(--teg-text); }
            .teg-h-tab.active { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); color: #fff; border-color: transparent; }

            .teg-stat-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 15px; }
            .teg-stat-box { background: var(--teg-bg); padding: 12px; border-radius: 6px; text-align: center; border: 1px solid var(--teg-border); }
            .teg-stat-num { font-size: 24px; font-weight: 800; display: block; line-height: 1.2; }
            .teg-stat-label { font-size: 11px; text-transform: uppercase; font-weight: 700; color: var(--teg-muted); margin-top: 4px; }
            
            /* Forms, Switches & Tooltips */
            .teg-switch-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; padding-bottom: 8px; border-bottom: 1px solid #f8fafc; }
            .teg-switch-row:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
            .teg-switch-label { font-size: 13px; font-weight: 600; color: var(--teg-text); display: flex; align-items: center; gap: 4px; }
            
            form .teg-switch-desc, .teg-card > .teg-switch-desc { font-size: 11px; color: var(--teg-muted); line-height: 1.4; margin-bottom: 10px; display: block; }
            .teg-help-icon { color: var(--teg-primary); font-size: 14px; width: 14px; height: 14px; cursor: help; opacity: 0.7; transition: opacity 0.2s; }
            .teg-help-icon:hover { opacity: 1; }

            .switch { position: relative; display: inline-block; width: 36px; height: 20px; flex-shrink: 0; margin: 0; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--teg-border); transition: .3s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 14px; width: 14px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 1px 3px rgba(0,0,0,0.2); }
            input:checked + .slider { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); }
            input:checked + .slider:before { transform: translateX(16px); }
            
            .teg-form-input { width: 100%; padding: 8px 10px; border: 1px solid var(--teg-border); border-radius: 6px; font-size: 13px; margin-bottom: 8px; background: var(--teg-bg); color: var(--teg-text); transition: all 0.2s; box-sizing: border-box; }
            .teg-form-input:focus { border-color: var(--teg-primary); outline: none; background: var(--teg-surface); box-shadow: 0 0 0 2px rgba(6, 182, 212, 0.15); }
            textarea.teg-form-input { min-height: 60px; font-family: monospace; font-size: 12px; line-height: 1.4; resize: vertical; }
            textarea.teg-form-input:focus { min-height: 120px; }

            .button-primary { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)) !important; border: none !important; padding: 6px 16px !important; border-radius: 6px !important; font-weight:600 !important; color:#fff !important; text-shadow: none !important; }
            .button-secondary { background: var(--teg-surface) !important; border: 1px solid var(--teg-border) !important; padding: 6px 16px !important; border-radius: 6px !important; font-weight:600 !important; color: var(--teg-text) !important; text-shadow: none !important; }
            
            .teg-table { width:100%; border-collapse:collapse; font-size:12px; border-radius: 6px; overflow: hidden; border: 1px solid var(--teg-border); }
            .teg-table th { text-align:left; padding:10px 12px; background: var(--teg-bg); color: var(--teg-muted); font-weight:700; border-bottom:1px solid var(--teg-border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
            .teg-table td { padding:10px 12px; border-bottom:1px solid var(--teg-border); color: var(--teg-text); background: var(--teg-surface); }
            
            #teg-toast { visibility: hidden; min-width: 200px; background: var(--teg-text); color: var(--teg-surface); text-align: center; border-radius: 6px; padding: 10px 16px; position: fixed; z-index: 99999; left: 50%; transform: translateX(-50%); bottom: 40px; font-size: 13px; font-weight:600; opacity: 0; transition: opacity 0.3s; box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
            #teg-toast.show { visibility: visible; opacity: 1; }

            /* Scoped dashboard stats */
            .teg-dash-grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; margin-top:16px; }
            @media (max-width: 1100px){.teg-dash-grid{grid-template-columns:1fr;}}
            .teg-dash-card { padding:16px; }
            .teg-dash-title { display:flex; align-items:center; gap:8px; margin:0 0 10px 0; font-size:13px; letter-spacing:.2px; text-transform: uppercase; }
            .teg-dash-title .dashicons { font-size:16px; line-height:16px; width:16px; height:16px; opacity:.9; }
            .teg-dash-sub { margin:-4px 0 12px 0; color:#6b7280; font-size:11px; }
            .teg-pill { display:inline-flex; align-items:center; gap:6px; padding:2px 8px; border-radius:999px; font-weight:800; font-size:11px; border:1px solid rgba(0,0,0,.06); background:#fff; }
            .teg-dot { width:6px; height:6px; border-radius:999px; display:inline-block; }
            .teg-kv { display:grid; grid-template-columns:1fr 140px; gap:8px; align-items:center; font-size:12px; }
            .teg-kv .k { font-weight:650; }
            .teg-kv .v { text-align:right; }
            .teg-kv code { font-size:11px; }
            .teg-actions { margin-top:12px; display:flex; gap:8px; flex-wrap:wrap; }
            .teg-actions .button { border-radius:6px; font-size:11px !important; padding: 4px 10px !important; }
            .teg-mini { font-size:11px; color:#6b7280; margin-top:10px; }
        </style>
        <script>
            function tegToggle(key, elem) {
                var val = elem.checked ? '1' : '0';
                var data = new FormData(); data.append('action', 'teg_toggle_option'); data.append('nonce', '<?php echo wp_create_nonce("teg_ajax_nonce"); ?>'); data.append('key', key); data.append('val', val);
                fetch(ajaxurl, { method: 'POST', body: data }).then(res => res.json()).then(res => { if(res.success) showToast("<?php echo esc_js(__('Saved successfully', 'tegatai-secure')); ?>"); else { alert("<?php echo esc_js(__('Error', 'tegatai-secure')); ?>"); elem.checked = !elem.checked; } });
            }
            function tegSaveForm(form, event) {
                event.preventDefault(); var btn = form.querySelector('input[type="submit"]'); var old=btn.value; btn.value="..."; btn.disabled=true;
                var data = new FormData(); data.append('action', 'teg_save_form'); data.append('nonce', '<?php echo wp_create_nonce("teg_ajax_nonce"); ?>'); data.append('form_data', new URLSearchParams(new FormData(form)).toString());
                fetch(ajaxurl, { method: 'POST', body: data }).then(res => res.json()).then(res => { btn.value=old; btn.disabled=false; if(res.success) showToast("<?php echo esc_js(__('Data saved!', 'tegatai-secure')); ?>"); else alert("<?php echo esc_js(__('Error', 'tegatai-secure')); ?>"); });
            }
            function showToast(msg) { var x=document.getElementById("teg-toast"); x.innerText=msg; x.className="show"; setTimeout(function(){ x.className=x.className.replace("show",""); }, 2000); }
        </script>
        <div id="teg-toast"></div>
        <div class="teg-wrap">
            <div class="teg-header">
                <div class="teg-title"><span class="dashicons dashicons-shield-alt" style="font-size:32px;"></span> Tegatai Security</div>
                <div class="teg-badge">v1.2</div>
            </div>

            <?php if ($tab == 'dashboard'): ?>
                
                <div class="teg-section-grid">
                    <?php foreach ($nav_groups as $g_id => $group): 
                        // Link zur ersten Unterseite der Gruppe
                        $first_tab = array_key_first($group['tabs']);
                    ?>
                        <a href="?page=tegatai-secure&tab=<?php echo esc_attr($first_tab); ?>" class="teg-section-card">
                            <div class="teg-section-icon"><span class="dashicons <?php echo esc_attr($group['icon']); ?>"></span></div>
                            <div class="teg-section-info">
                                <h3><?php echo esc_html($group['title']); ?></h3>
                                <p><?php echo esc_html($group['desc']); ?></p>
                            </div>
                        </a>
                    <?php endforeach; ?>
                </div>

                <hr style="margin: 40px 0 20px 0; border:0; border-top: 1px solid var(--teg-border);">
                <h2 style="font-size: 18px; margin-bottom: 0;">System Overview</h2>

                <?php
                  $ops = get_option($this->options_slug, []);
                  if (!is_array($ops)) { $ops = []; }

                  $pill = function($on) {
                    $c = $on ? 'var(--teg-success)' : '#9ca3af';
                    $t = $on ? __('ON', 'tegatai-secure') : __('OFF', 'tegatai-secure');
                    return '<span class="teg-pill" style="color:'.$c.';"><span class="teg-dot" style="background:'.$c.';"></span>'.esc_html($t).'</span>';
                  };

                  $sess_opt = get_option('tegatai_sessions', null);
                  $sess_count = is_array($sess_opt) ? count($sess_opt) : null;
                  $td_opt = get_option('tegatai_trusted_devices', null);
                  $td_count = is_array($td_opt) ? count($td_opt) : null;
                  $stats2 = class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_stats') ? Tegatai_Logger::get_stats() : ['blocked'=>0,'total'=>0];
                ?>

                <div class="teg-dash-grid">
                  <div class="teg-card teg-dash-card">
                    <h3 class="teg-dash-title"><span class="dashicons dashicons-yes-alt"></span><?php echo esc_html__('Security status', 'tegatai-secure'); ?></h3>
                    <p class="teg-dash-sub"><?php echo esc_html__('At-a-glance view of the most important protections.', 'tegatai-secure'); ?></p>

                    <?php
                      $items = [
                        ['enable_waf',             __('WAF', 'tegatai-secure')],
                        ['enable_login_limit',     __('Login limit', 'tegatai-secure')],
                        ['enable_trusted_devices', __('Trusted Devices', 'tegatai-secure')],
                        ['enable_2fa',             __('2FA', 'tegatai-secure')],
                        ['enable_single_session',  __('Single session', 'tegatai-secure')],
                        ['enable_upload_guard',    __('Upload guard', 'tegatai-secure')],
                      ];
                    ?>
                    <div class="teg-kv">
                      <?php foreach ($items as $it): $k=$it[0]; $label=$it[1]; $on=!empty($ops[$k]); ?>
                        <div class="k"><?php echo esc_html($label); ?></div>
                        <div class="v"><?php echo $pill($on); ?></div>
                      <?php endforeach; ?>
                    </div>
                  </div>

                  <div class="teg-card teg-dash-card">
                    <h3 class="teg-dash-title"><span class="dashicons dashicons-shield-alt"></span><?php echo esc_html__('Attack & block overview', 'tegatai-secure'); ?></h3>
                    <p class="teg-dash-sub"><?php echo esc_html__('Quick stats + top IPs (last 24 hours).', 'tegatai-secure'); ?></p>

                    <?php
                      $rows2 = (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_logs')) ? Tegatai_Logger::get_logs(250) : [];
                      
                      $cut24 = time() - 86400;
                      $blocks_24h = 0; $fails_24h  = 0;

                      foreach ($rows2 as $rr) {
                        $tstr = isset($rr['time']) ? (string)$rr['time'] : '';
                        $tt   = $tstr ? strtotime($tstr) : 0;
                        if (!$tt || $tt < $cut24) { continue; }

                        $typ = isset($rr['type']) ? strtoupper((string)$rr['type']) : '';
                        $msg = isset($rr['message']) ? strtolower((string)$rr['message']) : '';

                        if (strpos($typ, 'BLOCK') !== false || strpos($typ, 'WAF') !== false || strpos($msg, 'blocked') !== false) { $blocks_24h++; }
                        if (strpos($typ, 'LOGIN_FAIL') !== false || (strpos($typ, 'LOGIN') !== false && strpos($typ, 'FAIL') !== false) || strpos($msg, 'failed login') !== false || strpos($msg, 'invalid password') !== false || strpos($msg, 'login attempt') !== false) { $fails_24h++; }
                      }
                      
                      $cut = time() - 86400;
                      $ip_counts = [];
                      foreach ($rows2 as $r) {
                        $type = isset($r['type']) ? (string)$r['type'] : '';
                        $ip = isset($r['ip']) ? (string)$r['ip'] : '';
                        $t = isset($r['time']) ? strtotime((string)$r['time']) : 0;
                        if (in_array($type, ['LOGIN','INFO','BACKUP','AUTH'], true)) { continue; }
                        if ($ip && $t && $t >= $cut) { $ip_counts[$ip] = ($ip_counts[$ip] ?? 0) + 1; }
                      }
                      arsort($ip_counts);
                      $top_ips = array_slice($ip_counts, 0, 3, true);
                    ?>
                    <div class="teg-kv" style="margin-bottom:12px;">
                      <div class="k"><?php echo esc_html__('Blocked (total)', 'tegatai-secure'); ?></div>
                      <div class="v"><code><?php echo esc_html((string)intval($stats2['blocked'] ?? 0)); ?></code></div>
                      <div class="k"><?php echo esc_html__('Blocks (24h)', 'tegatai-secure'); ?></div>
                      <div class="v"><code><?php echo esc_html((string)intval($blocks_24h ?? 0)); ?></code></div>
                      <div class="k"><?php echo esc_html__('Failed logins (24h)', 'tegatai-secure'); ?></div>
                      <div class="v"><code><?php echo esc_html((string)intval($fails_24h ?? 0)); ?></code></div>
                    </div>

                    <div class="teg-kv" style="grid-template-columns:1fr 80px;">
                      <div class="k"><?php echo esc_html__('Top IPs (24h)', 'tegatai-secure'); ?></div><div></div>
                      <?php if (empty($top_ips)): ?>
                        <div class="teg-muted"><?php echo esc_html__('No data yet.', 'tegatai-secure'); ?></div><div></div>
                      <?php else: ?>
                        <?php foreach ($top_ips as $ip => $cnt): ?>
                          <div><code><?php echo esc_html($ip); ?></code></div>
                          <div class="v"><code><?php echo esc_html((string)$cnt); ?></code></div>
                        <?php endforeach; ?>
                      <?php endif; ?>
                    </div>
                  </div>
                </div>

            <?php else: ?>
                <?php if ($current_group && isset($nav_groups[$current_group])): ?>
                    <div class="teg-inner-nav">
                        <a href="?page=tegatai-secure&tab=dashboard" class="teg-back-btn">
                            <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Dashboard', 'tegatai-secure'); ?>
                        </a>
                        <div class="teg-horizontal-tabs">
                            <?php foreach ($nav_groups[$current_group]['tabs'] as $t_id => $t_label): ?>
                                <a href="?page=tegatai-secure&tab=<?php echo esc_attr($t_id); ?>" class="teg-h-tab <?php echo ($tab == $t_id) ? 'active' : ''; ?>">
                                    <?php echo esc_html($t_label); ?>
                                </a>
                            <?php endforeach; ?>
                        </div>
                    </div>
                <?php endif; ?>
                
                <?php $this->render_full_tabs($tab); ?>

            <?php endif; ?>
        </div>
        <?php
    }

    private function render_toggle($key, $label, $desc = '') {
        $val = $this->get_opt($key);
        $checked = $val ? 'checked' : '';
        $help = $desc ? "<span class='dashicons dashicons-info-outline teg-help-icon' title='".esc_attr(strip_tags($desc))."'></span>" : "";
        echo "<div class='teg-switch-row'><div><span class='teg-switch-label'>$label $help</span></div><label class='switch'><input type='checkbox' class='teg-toggle-checkbox' onchange=\"tegToggle('$key', this)\" $checked><span class='slider'></span></label></div>";
    }

    private function render_full_tabs($tab) {
        if ($tab == 'firewall') { echo '
<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('WAF Settings', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_waf', esc_html__('Enable WAF', 'tegatai-secure'), esc_html__('Activates the Web Application Firewall to block malicious requests.', 'tegatai-secure')); $this->render_toggle('block_fake_bots', esc_html__('Block Bad Bots', 'tegatai-secure'), esc_html__('Blocks known malicious bots, scrapers, and automated attack tools.', 'tegatai-secure')); $this->render_toggle('enable_rate_limit', esc_html__('Rate Limit', 'tegatai-secure'), esc_html__('Prevents brute-force attacks by limiting requests per minute.', 'tegatai-secure')); $this->render_toggle('enable_404_block', esc_html__('404 Trap', 'tegatai-secure'), esc_html__('Bans IPs that generate too many 404 Not Found errors.', 'tegatai-secure')); $this->render_toggle('block_ai_bots', esc_html__('Block AI Bots', 'tegatai-secure'), esc_html__('Stops OpenAI, ChatGPT, and other AI scrapers from crawling your content.', 'tegatai-secure')); $this->render_toggle('block_seo_bots', esc_html__('Block SEO Bots', 'tegatai-secure'), esc_html__('Blocks aggressive SEO crawlers like Ahrefs or Semrush.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('WAF Whitelist', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Allowed URLs', 'tegatai-secure') . '</label><textarea name="tegatai_options[waf_whitelist_urls]" class="teg-form-input">'.esc_textarea($this->get_opt('waf_whitelist_urls', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Custom Rules', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Custom Regex Filters', 'tegatai-secure') . '</label><p class="teg-switch-desc">' . wp_kses_post(__('One regex per line (e.g., <code>/bad-bot/i</code>).', 'tegatai-secure')) . '</p><textarea name="tegatai_options[custom_waf_blocklist]" class="teg-form-input">'.esc_textarea($this->get_opt('custom_waf_blocklist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('IP Lists', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Whitelist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[whitelist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('whitelist_ips', '')).'</textarea><label class="teg-switch-label">' . esc_html__('Blacklist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[blacklist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('blacklist_ips', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'server') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Server Rules', 'tegatai-secure') . '</h3>'; $this->render_toggle('server_disable_indexing', esc_html__('Disable Directory Browsing', 'tegatai-secure'), esc_html__('Prevents attackers from seeing lists of your files.', 'tegatai-secure')); $this->render_toggle('server_protect_files', esc_html__('Protect Sensitive Files', 'tegatai-secure'), esc_html__('Blocks access to .env, .sql, .bak, .log, and .git files.', 'tegatai-secure')); $this->render_toggle('server_hide_system_files', esc_html__('Block System Files', 'tegatai-secure'), esc_html__('Hides readme.html, license.txt, and wp-config.php from the web.', 'tegatai-secure')); $this->render_toggle('server_block_dotfiles', esc_html__('Block Dotfiles', 'tegatai-secure'), esc_html__('Denies access to hidden files (e.g., .htaccess).', 'tegatai-secure')); $this->render_toggle('server_block_xmlrpc', esc_html__('Block XML-RPC', 'tegatai-secure'), esc_html__('Disables xmlrpc.php to prevent DDoS and brute-force attacks.', 'tegatai-secure')); $this->render_toggle('server_disable_php_uploads', esc_html__('Disable PHP in Uploads', 'tegatai-secure'), esc_html__('Prevents execution of malicious backdoors in your media folder.', 'tegatai-secure')); $this->render_toggle('server_filter_bad_bots', esc_html__('Ultimate Bad Bot Filter', 'tegatai-secure'), esc_html__('Strict Nginx-level blocking for hacking tools.', 'tegatai-secure')); $this->render_toggle('server_hotlink_protection', esc_html__('Hotlink Protection', 'tegatai-secure'), esc_html__('Prevents other sites from embedding your images and stealing bandwidth.', 'tegatai-secure')); echo '<div style="background:#f9fafb; padding:12px; border-radius:6px; margin-top:16px; border:1px solid #e5e7eb;"><form method="post" action="'.admin_url('admin-post.php').'"><input type="hidden" name="action" value="tegatai_write_rules">'.wp_nonce_field('teg_write_nonce','_wpnonce',true,false).'<input type="submit" class="button button-primary" value="' . esc_attr__('Write rules to config', 'tegatai-secure') . '" ></form></div></div><div class="teg-card"><h3>' . esc_html__('Custom Protection', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Protected Directories', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[server_protected_dirs]" value="'.esc_attr($this->get_opt('server_protected_dirs', '')).'" class="teg-form-input">
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Block Specific Files', 'tegatai-secure') . '</label>
<p class="teg-switch-desc">' . wp_kses_post(__('Paths from root (e.g., <code>/secret.zip</code>).', 'tegatai-secure')) . '</p>
<textarea name="tegatai_options[server_custom_files_list]" class="teg-form-input" placeholder="/geheim.zip&#10;/custom/info.php">'.esc_textarea($this->get_opt('server_custom_files_list', '')).'</textarea>
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Hotlink Whitelist', 'tegatai-secure') . '</label><textarea name="tegatai_options[server_hotlink_whitelist]" class="teg-form-input">'.esc_textarea($this->get_opt('server_hotlink_whitelist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" style="margin-top:8px;" ></form></div></div>'; }
        elseif ($tab == 'login') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Login Protection', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_login_limit', esc_html__('Login Limit', 'tegatai-secure'), esc_html__('Locks out IPs after multiple failed login attempts.', 'tegatai-secure')); $this->render_toggle('disable_app_passwords', esc_html__('Disable App Passwords', 'tegatai-secure'), esc_html__('Turns off the WordPress application passwords feature.', 'tegatai-secure'));
        $this->render_toggle('enable_trusted_devices', esc_html__('Trusted Devices', 'tegatai-secure'), esc_html__('Warns via email upon logins from unknown devices.', 'tegatai-secure')); $this->render_toggle('block_default_login', esc_html__('Block wp-login.php', 'tegatai-secure'), esc_html__('Disables the default login route (requires Custom Slug).', 'tegatai-secure')); $this->render_toggle('block_wp_admin_hide', esc_html__('Hide /wp-admin/', 'tegatai-secure'), esc_html__('Redirects unauthenticated users away from the admin area.', 'tegatai-secure')); $this->render_toggle('enable_idle_logout', esc_html__('Idle Logout (60m)', 'tegatai-secure'), esc_html__('Automatically logs out inactive administrators after 60 minutes.', 'tegatai-secure')); $this->render_toggle('enable_magic_links', esc_html__('Enable Magic Links', 'tegatai-secure'), esc_html__('Allows passwordless login via a secure email link.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('Custom Login Slug', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><input type="text" name="tegatai_options[custom_login_slug]" value="'.esc_attr($this->get_opt('custom_login_slug', '')).'" class="teg-form-input" placeholder="mein-login"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'spam') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Spam & Bots', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_honeypot', esc_html__('Enable Honeypot', 'tegatai-secure'), esc_html__('Adds an invisible field to catch automated spam bots.', 'tegatai-secure')); $this->render_toggle('enable_bot_timer', esc_html__('Minimum Fill Time', 'tegatai-secure'), esc_html__('Blocks forms submitted too quickly.', 'tegatai-secure')); $this->render_toggle('spam_check_referrer', esc_html__('Referrer Check', 'tegatai-secure'), esc_html__('Ensures form submissions come from your own site.', 'tegatai-secure')); $this->render_toggle('spam_block_trashmail', esc_html__('Block Trash Mails', 'tegatai-secure'), esc_html__('Rejects disposable email addresses during registration.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Max. Links', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[spam_max_links]" value="'.esc_attr($this->get_opt('spam_max_links')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Cloudflare Turnstile', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_turnstile', esc_html__('Enable Turnstile', 'tegatai-secure'), esc_html__('Privacy-friendly Cloudflare CAPTCHA for login and comments.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Site Key', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[turnstile_site_key]" value="'.esc_attr($this->get_opt('turnstile_site_key')).'" class="teg-form-input" placeholder="0x4A..."><label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Secret Key', 'tegatai-secure') . '</label><input type="password" name="tegatai_options[turnstile_secret_key]" value="'.esc_attr($this->get_opt('turnstile_secret_key')).'" class="teg-form-input" placeholder="0x4A..."><input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'geoip') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3><span class="dashicons dashicons-admin-site-alt3" style="vertical-align:middle;"></span> ' . esc_html__('GeoIP Configuration', 'tegatai-secure') . '</h3>';
            
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<label class="teg-switch-label">' . esc_html__('Operation Mode', 'tegatai-secure') . '</label>';
            echo '<select name="tegatai_options[geoip_mode]" class="teg-form-input" style="margin-bottom: 15px;">';
            echo '<option value="disabled" ' . selected($this->get_opt('geoip_mode'), 'disabled', false) . '>' . esc_html__('Disabled', 'tegatai-secure') . '</option>';
            echo '<option value="blacklist" ' . selected($this->get_opt('geoip_mode'), 'blacklist', false) . '>' . esc_html__('Blacklist (Block listed countries)', 'tegatai-secure') . '</option>';
            echo '<option value="whitelist" ' . selected($this->get_opt('geoip_mode'), 'whitelist', false) . '>' . esc_html__('Whitelist (Allow ONLY listed countries)', 'tegatai-secure') . '</option>';
            echo '</select>';
            
            $this->render_toggle('geoip_login_only', esc_html__('Protect Login Only', 'tegatai-secure'), esc_html__('If enabled, the GeoIP filter only applies to wp-login.php and XML-RPC. If disabled, it blocks the entire website.', 'tegatai-secure'));
            
            echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save Settings', 'tegatai-secure') . '" style="margin-top:10px;" >';
            echo '</form>';
            echo '</div>';

            echo '<div class="teg-card">';
            echo '<h3><span class="dashicons dashicons-location" style="vertical-align:middle;"></span> ' . esc_html__('Country Codes', 'tegatai-secure') . '</h3>';
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<label class="teg-switch-label">' . esc_html__('ISO Alpha-2 Codes', 'tegatai-secure') . '</label>';
            echo '<p class="teg-switch-desc">' . esc_html__('One code per line (e.g. EN, DE).', 'tegatai-secure') . '</p>';
            echo '<textarea name="tegatai_options[geoip_list]" class="teg-form-input" placeholder="EN&#10;DE" style="min-height: 120px;">'.esc_textarea($this->get_opt('geoip_list', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save Codes', 'tegatai-secure') . '">';
            echo '</form>';
            echo '</div></div>';
        }
        elseif ($tab == 'hardening') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('System', 'tegatai-secure') . '</h3>'; $this->render_toggle('hide_wp_version', esc_html__('Hide WP Version', 'tegatai-secure'), esc_html__('Removes the WordPress version number from your source code.', 'tegatai-secure')); $this->render_toggle('disable_xmlrpc', esc_html__('Disable XML-RPC', 'tegatai-secure'), esc_html__('Turns off the XML-RPC API internally.', 'tegatai-secure')); $this->render_toggle('disable_file_editor', esc_html__('Disable File Editor', 'tegatai-secure'), esc_html__('Prevents editing plugins and themes via the WP dashboard.', 'tegatai-secure')); $this->render_toggle('block_user_enum', esc_html__('Block Enumeration', 'tegatai-secure'), esc_html__('Stops attackers from discovering your usernames.', 'tegatai-secure'));
        echo '<hr style="margin:16px 0; border:0; border-top:1px solid #f1f5f9;">';
        $this->render_toggle('enable_admin_honeypot', esc_html__('Admin Honeypot', 'tegatai-secure'), esc_html__('Permanently bans anyone trying to log in as admin.', 'tegatai-secure'));
        $this->render_toggle('enable_role_guard', esc_html__('Privilege Guard', 'tegatai-secure'), esc_html__('Prevents unauthorized users from upgrading to Administrator.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('Notifications', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_email_alerts', esc_html__('Enable Email Alerts', 'tegatai-secure'), esc_html__('Receive notifications for critical security events.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">
        <label class="teg-switch-label">' . esc_html__('Recipient Email', 'tegatai-secure') . '</label>
        <input type="email" name="tegatai_options[alert_email]" value="'.esc_attr($this->get_opt('alert_email', get_option('admin_email'))).'" class="teg-form-input">
        <label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Webhook URL', 'tegatai-secure') . '</label>
        <input type="url" name="tegatai_options[alert_webhook_url]" value="'.esc_attr($this->get_opt('alert_webhook_url', '')).'" class="teg-form-input" placeholder="https://discord.com/api/webhooks/...">
        <input type="submit" class="button button-primary" style="margin-top:8px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >
    </form></div><div class="teg-card"><h3>' . esc_html__('2FA', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_2fa', esc_html__('Enable 2FA', 'tegatai-secure'), esc_html__('Enforces Two-Factor Authentication for administrators.', 'tegatai-secure'));
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Preferred Method', 'tegatai-secure') . '</label>';
        echo '<select name="tegatai_options[twofa_mode]" class="teg-form-input">';
        echo '<option value="email" '.selected($this->get_opt('twofa_mode'), 'email', false).'>' . esc_html__('Email Code Only', 'tegatai-secure') . '</option>';
        echo '<option value="app" '.selected($this->get_opt('twofa_mode'), 'app', false).'>' . esc_html__('App Only', 'tegatai-secure') . '</option>';
        echo '<option value="both" '.selected($this->get_opt('twofa_mode', 'both'), 'both', false).'>' . esc_html__('Both', 'tegatai-secure') . '</option>';
        echo '</select>';
        echo '<input type="submit" class="button button-primary" style="margin-top:8px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '</div>'; 
        
        // --- CARD 4: Deep Clean (fixed quotes) ---
        echo '<div class="teg-card" style="grid-column: 1 / -1;">';
        echo '<h3><span class="dashicons dashicons-database" style="vertical-align:middle;"></span> ' . esc_html__('System Deep Clean', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . wp_kses_post(__('Manual database cleanup. Deletes expired transients, spam comments, old post revisions, and optimizes table overhead.', 'tegatai-secure')) . '</p>';
        echo '<button id="teg-run-clean" class="button button-primary"><span class="dashicons dashicons-update-alt" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Run Deep Clean', 'tegatai-secure') . '</button>';
        echo '<div id="teg-clean-results" style="display:none; margin-top:12px; padding:12px; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; color:#166534; font-size:12px; line-height:1.6;"></div>';
        echo '<script>
        jQuery(document).ready(function($) {
            $("#teg-run-clean").on("click", function(e) {
                e.preventDefault();
                var btn = $(this);
                if (!confirm(\'' . esc_js(__('Do you want to clean the database now? (This may take a few seconds on large sites)', 'tegatai-secure')) . '\')) return;
                btn.prop("disabled", true).html("<span class=\'dashicons dashicons-update\' style=\'vertical-align:middle; margin-top:3px;\'></span> Cleaning...");
                $("#teg-clean-results").slideUp();
                
                $.post(ajaxurl, { action: "teg_deep_clean", _ajax_nonce: "' . wp_create_nonce('teg_admin_nonce') . '" }, function(r) {
                    btn.prop("disabled", false).html("<span class=\'dashicons dashicons-update-alt\' style=\'vertical-align:middle; margin-top:3px;\'></span> " + \'' . esc_js(__('Run Deep Clean', 'tegatai-secure')) . '\');
                    if (r.success) {
                        var html = "<strong>\'' . esc_js(__('Cleanup successful! Statistics:', 'tegatai-secure')) . '\'</strong><br><ul style=\'margin-top:6px; margin-bottom:0;\'>";
                        $.each(r.data.stats, function(i, stat) { html += "<li>" + stat + "</li>"; });
                        html += "</ul>";
                        $("#teg-clean-results").html(html).slideDown();
                    } else {
                        alert(\'' . esc_js(__('Error during cleanup.', 'tegatai-secure')) . '\');
                    }
                });
            });
        });
        </script>';
        echo '</div>'; 
        echo '</div>'; 
        }
        elseif ($tab == 'headers') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('HTTP Security Headers', 'tegatai-secure') . '</h3>'; $this->render_toggle('header_xfo', esc_html__('X-Frame-Options', 'tegatai-secure'), esc_html__('Clickjacking protection.', 'tegatai-secure')); $this->render_toggle('header_nosniff', esc_html__('X-Content-Type-Options', 'tegatai-secure'), esc_html__('Stops browsers from MIME-sniffing.', 'tegatai-secure')); $this->render_toggle('header_xss', esc_html__('X-XSS-Protection', 'tegatai-secure'), esc_html__('Enables legacy browser XSS filtering.', 'tegatai-secure')); $this->render_toggle('header_hsts', esc_html__('HSTS (SSL)', 'tegatai-secure'), esc_html__('Enforces strict HTTPS connections.', 'tegatai-secure')); $this->render_toggle('header_ref', esc_html__('Referrer Policy', 'tegatai-secure'), esc_html__('Controls referrer information.', 'tegatai-secure')); $this->render_toggle('header_permissions', esc_html__('Permissions-Policy', 'tegatai-secure'), esc_html__('Restricts access to browser features (camera, mic).', 'tegatai-secure')); $this->render_toggle('header_csp', esc_html__('Content Security Policy', 'tegatai-secure'), esc_html__('Mitigates XSS.', 'tegatai-secure')); echo '</div></div>'; }
        elseif ($tab == 'backups') { 
        echo '<div class="teg-grid">';
        
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Backup Config', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('enable_auto_backup', esc_html__('Auto backup', 'tegatai-secure'), esc_html__('Automatically creates backups based on frequency.', 'tegatai-secure')); 
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:12px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Frequency', 'tegatai-secure') . '</label>';
        echo '<select name="tegatai_options[backup_frequency]" class="teg-form-input">';
        echo '<option value="daily" ' . selected($this->get_opt('backup_frequency'), 'daily', false) . '>' . esc_html__('Daily', 'tegatai-secure') . '</option>';
        echo '<option value="weekly" ' . selected($this->get_opt('backup_frequency'), 'weekly', false) . '>' . esc_html__('Weekly', 'tegatai-secure') . '</option>';
        echo '</select>';
        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" style="margin-top:8px;">';
        echo '</form>';
        echo '</div>';
        
        echo '<div class="teg-card" style="grid-column: span 2;">';
        echo '<h3>' . esc_html__('Local Backups', 'tegatai-secure') . '</h3>';
        echo '<form method="post" action="' . admin_url('admin-post.php') . '">';
        echo '<input type="hidden" name="action" value="tegatai_create_backup">';
        echo wp_nonce_field('teg_backup_nonce', '_wpnonce', true, false);
        echo '<input type="submit" class="button button-secondary" value="' . esc_attr__('Create Backup Now', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '<hr style="margin:16px 0; border:0; border-top:1px solid #eee;">';
        
        echo '<div style="overflow-x:auto;">';
        echo '<table class="teg-table" style="table-layout: fixed; width: 100%; min-width: 400px;">';
        echo '<thead>';
        echo '<tr>';
        echo '<th style="width: 45%;">' . esc_html__('File', 'tegatai-secure') . '</th>';
        echo '<th style="width: 15%;">' . esc_html__('Size', 'tegatai-secure') . '</th>';
        echo '<th style="width: 15%;">' . esc_html__('Date', 'tegatai-secure') . '</th>';
        echo '<th style="width: 25%; text-align:right;">' . esc_html__('Action', 'tegatai-secure') . '</th>';
        echo '</tr>';
        echo '</thead>';
        echo '<tbody>';
        
        $backups = Tegatai_Backup::get_backups(); 
        if (empty($backups)) {
            echo '<tr><td colspan="4" style="color:#999; text-align:center;">' . esc_html__('No backups available.', 'tegatai-secure') . '</td></tr>';
        } else {
            foreach ($backups as $b) { 
                echo '<tr>';
                echo '<td style="word-break: break-all; overflow-wrap: break-word;"><strong>' . esc_html($b['name']) . '</strong></td>';
                echo '<td style="white-space: nowrap;">' . esc_html($b['size']) . '</td>';
                echo '<td style="white-space: nowrap;">' . esc_html($b['date']) . '</td>';
                
                echo '<td style="text-align:right; white-space: nowrap;">';
                echo '<form method="post" action="' . admin_url('admin-post.php') . '" style="display:inline; margin-right: 4px;">';
                echo '<input type="hidden" name="action" value="tegatai_download_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce('teg_backup_nonce') . '">';
                echo '<input type="submit" class="button button-secondary" value="' . esc_attr__('DL', 'tegatai-secure') . '" >';
                echo '</form>';
                
                echo '<form method="post" action="' . admin_url('admin-post.php') . '" style="display:inline;">';
                echo '<input type="hidden" name="action" value="tegatai_delete_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce('teg_backup_nonce') . '">';
                echo '<input type="submit" class="button button-secondary" value="X" style="color:var(--teg-danger);">';
                echo '</form>';
                echo '</td>';
                echo '</tr>';
            } 
        }
        echo '</tbody>';
        echo '</table>';
        echo '</div>';
        echo '</div>'; 
        
        echo '<div class="teg-card" style="grid-column: 1 / -1; background: #fafafa; border: 1px solid #e5e7eb;">';
        echo '<h3 style="border-bottom:1px solid #e5e7eb; padding-bottom:10px;"><span class="dashicons dashicons-cloud-upload"></span> ' . esc_html__('Remote FTP Setup (Encrypted)', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . wp_kses_post(__('Send your backups automatically to an external FTP server. All credentials are encrypted with <strong>AES-256-CBC</strong> in your database.', 'tegatai-secure')) . '</p>';
        
        $key = defined('SECURE_AUTH_KEY') ? SECURE_AUTH_KEY : 'tegatai_fallback_key';
        $ops = get_option('tegatai_ftp_settings', []);
        $dec = function($data) use ($key) {
            if (empty($data)) return '';
            $d = base64_decode($data);
            if (strpos($d, '::') === false) return $data;
            list($enc, $iv) = explode('::', $d, 2);
            return openssl_decrypt($enc, 'AES-256-CBC', md5($key), 0, $iv);
        };
        
        $host = !empty($ops['host']) ? $dec($ops['host']) : '';
        $user = !empty($ops['user']) ? $dec($ops['user']) : '';
        $pass = !empty($ops['pass']) ? $dec($ops['pass']) : '';
        $port = !empty($ops['port']) ? $ops['port'] : '21';
        
        echo '<form method="post" action="' . admin_url('admin-post.php') . '">';
        echo wp_nonce_field('teg_ftp_nonce', '_wpnonce', true, false);
        echo '<input type="hidden" name="action" value="tegatai_save_ftp">';
        echo '<div class="teg-stat-row" style="grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); margin-bottom:10px; gap: 16px;">';
        echo '<div><label class="teg-switch-label">' . esc_html__('FTP Server', 'tegatai-secure') . '</label><input type="password" name="ftp_host" value="' . esc_attr($host) . '" class="teg-form-input" placeholder="ftp.deinserver.de"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('FTP Port', 'tegatai-secure') . '</label><input type="number" name="ftp_port" value="' . esc_attr($port) . '" class="teg-form-input"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('Username', 'tegatai-secure') . '</label><input type="password" name="ftp_user" value="' . esc_attr($user) . '" class="teg-form-input"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('Password', 'tegatai-secure') . '</label><input type="password" name="ftp_pass" value="' . esc_attr($pass) . '" class="teg-form-input"></div>';
        echo '</div>';
        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save Encrypted', 'tegatai-secure') . '" >';
        if (isset($_GET['updated']) && $_GET['updated'] == '1') {
            echo '<span style="color:var(--teg-success); margin-left:12px; font-weight:bold; font-size:12px;">' . esc_html__('Data saved securely!', 'tegatai-secure') . '</span>';
        }
        echo '</form>';
        echo '</div>'; 
        
        echo '</div>'; 
    }
        elseif ($tab == 'scanner') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Malware & Integrity Scanner', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('enable_auto_quarantine', esc_html__('Auto-Quarantine (IPS)', 'tegatai-secure'), esc_html__('Automatically moves detected malware to a safe location.', 'tegatai-secure')); 
        $status = get_option('teg_scan_status'); $is_running = isset($status['running']) && $status['running']; if ($is_running) { echo '<div style="padding:16px; background:#e0f2fe; border:1px solid #bae6fd; color:#0369a1; border-radius:6px; margin-bottom:16px;">' . esc_html__('Scan running...', 'tegatai-secure') . '</div>'; echo '<script>setTimeout(function(){ window.location.href="'.admin_url('admin-post.php?action=tegatai_scan_process').'"; }, 1500);</script>'; } else { echo '<form method="post" action="'.admin_url('admin-post.php').'"><input type="hidden" name="action" value="tegatai_scan_start">'.wp_nonce_field('teg_scan_nonce', '_wpnonce', true, false).'<input type="submit" class="button button-primary" value="' . esc_attr__('Start New Scan', 'tegatai-secure') . '"  style="padding:8px 16px;"></form>';

echo '<form method="post" action="'.admin_url('admin-post.php').'" style="display:inline-block; margin-top:8px;">
<input type="hidden" name="action" value="tegatai_scan_snapshot">
' . wp_nonce_field('teg_scan_nonce', '_wpnonce', true, false) . '
<input type="submit"
class="button button-secondary"
value="📸 ' . esc_attr__('Create File Snapshot', 'tegatai-secure') . '"
style="padding:8px 16px;"
onclick="return confirm(\'' . esc_js(__('Save current state as a safe baseline?', 'tegatai-secure')) . '\');">
</form>';
    } if (isset($status['last_scan'])) { echo '<hr style="margin:16px 0; border:0; border-top:1px solid #eee;">'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:8px; font-size:12px;"><strong>' . esc_html__('Last Result:', 'tegatai-secure') . '</strong> <span>' . $status['last_scan'] . '</span></div>'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:16px; font-size:12px;"><strong>' . esc_html__('Files Checked:', 'tegatai-secure') . '</strong> <span>' . intval($status['files_checked']) . '</span></div>'; if (!empty($status['bad_files'])) { echo '<table class="teg-table"><thead><tr><th>Datei</th><th>' . esc_html__('Issue', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach ($status['bad_files'] as $bad) echo '<tr><td style="color:var(--teg-danger);">' . esc_html($bad['file']) . '</td><td>' . esc_html($bad['issue']) . '</td></tr>'; echo '</tbody></table>'; } else { echo '<div style="padding:12px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px;">✅ Sauber.</div>'; } } echo '</div><div class="teg-card"><h3>' . esc_html__('Scanner Configuration', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Exclude from Scan', 'tegatai-secure') . '</label><textarea name="tegatai_options[scanner_exclusions]" class="teg-form-input" placeholder="/pfad/zum/cache/">'.esc_textarea($this->get_opt('scanner_exclusions', '/kontentsu/appurodo/avyspp_cache')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'sessions') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Session Security', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_ip_guard', esc_html__('IP Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users IP address changes.', 'tegatai-secure')); $this->render_toggle('enable_browser_guard', esc_html__('Browser Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users browser changes.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:16px;"><label class="teg-switch-label">' . esc_html__('Max Session (Min)', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[session_max_lifetime]" value="'.esc_attr($this->get_opt('session_max_lifetime')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card" style="grid-column: 1 / -1;"><h3>' . esc_html__('Active Sessions', 'tegatai-secure') . '</h3><div style="overflow-x:auto;"><table class="teg-table"><thead><tr><th>' . esc_html__('User', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Browser', 'tegatai-secure') . '</th><th>' . esc_html__('Action', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_SessionManager::get_all_sessions() as $s): echo "<tr><td>".esc_html($s['username'])."</td><td><code>".esc_html($s['ip'])."</code></td><td><span style='font-size:11px; color:#666;'>".esc_html(substr($s['ua'],0,40))."...</span></td><td><form method='post' action='".admin_url('admin-post.php')."'><input type='hidden' name='action' value='tegatai_kill_session'><input type='hidden' name='user_id' value='{$s['user_id']}'><input type='hidden' name='verifier' value='".esc_attr($s['verifier'])."'><input type='hidden' name='_wpnonce' value='".wp_create_nonce('teg_session_nonce')."'><input type='submit' class='button button-secondary' style='color:var(--teg-danger);' value='" . esc_attr__('Kill', 'tegatai-secure') . "'></form></td></tr>"; endforeach; echo '</tbody></table></div></div></div>'; }
        elseif ($tab == 'extras') { 
        echo '<div class="teg-grid">';
        
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Extras & API', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('disable_rest_api', esc_html__('Restrict REST API', 'tegatai-secure'), esc_html__('Requires authentication for REST endpoints.', 'tegatai-secure')); 
        $this->render_toggle('enable_rightclick_disable', esc_html__('Disable Right-Click', 'tegatai-secure'), esc_html__('Prevents basic right-clicking.', 'tegatai-secure')); 
        $this->render_toggle('enable_copy_protection', esc_html__('Enable Copy Protection', 'tegatai-secure'), esc_html__('Stops users from copying text.', 'tegatai-secure')); 
        echo '</div>';
        
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Temp Admin Accounts', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Creates a temporary admin account with a secure link.', 'tegatai-secure') . '</p>';
        
        if (isset($_GET['msg']) && $_GET['msg'] == 'temp_created') {
            echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:4px; margin-bottom:12px; border:1px solid #bbf7d0; font-size:12px;">' . esc_html__('Access generated and email sent!', 'tegatai-secure') . '</div>';
        }
        
        echo '<form method="post" action="' . admin_url('admin-post.php') . '">';
        echo wp_nonce_field('teg_temp_admin_nonce', '_wpnonce', true, false);
        echo '<input type="hidden" name="action" value="tegatai_create_temp_admin">';
        
        echo '<label class="teg-switch-label">' . esc_html__('Recipient Email', 'tegatai-secure') . '</label>';
        echo '<input type="email" name="temp_email" class="teg-form-input" placeholder="support@beispiel.de" required>';
        
        echo '<label class="teg-switch-label" style="margin-top:8px;">' . esc_html__('Validity (hours)', 'tegatai-secure') . '</label>';
        echo '<input type="number" name="temp_hours" class="teg-form-input" value="24" min="1" max="168" required>';
        
        echo '<input type="submit" class="button button-primary" style="margin-top:8px;" value="' . esc_attr__('Generate Access', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '</div>'; 
        
        echo '<div class="teg-card" style="grid-column: 1 / -1;">';
        echo '<h3 style="border-bottom:1px solid #e5e7eb; padding-bottom:10px;"><span class="dashicons dashicons-download"></span> ' . esc_html__('Configuration Export & Import', 'tegatai-secure') . '</h3>';
        
        echo '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap:16px;">';
        
        echo '<div style="background:#f9fafb; padding:16px; border-radius:6px; border:1px solid #e5e7eb;">';
        echo '<h4>' . esc_html__('Export Settings', 'tegatai-secure') . '</h4>';
        echo '<p style="font-size:11px; color:#6b7280; margin-bottom:12px;">' . esc_html__('Downloads a .json file with all settings.', 'tegatai-secure') . '</p>';
        echo '<a href="' . admin_url('admin-post.php?action=tegatai_export_config&_wpnonce=' . wp_create_nonce('teg_export_nonce')) . '" class="button button-secondary"><span class="dashicons dashicons-download" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Download (.json)', 'tegatai-secure') . '</a>';
        echo '</div>';
        
        echo '<div style="background:#f9fafb; padding:16px; border-radius:6px; border:1px solid #e5e7eb;">';
        echo '<h4>' . esc_html__('Import Settings', 'tegatai-secure') . '</h4>';
        echo '<p style="font-size:11px; color:#6b7280; margin-bottom:12px;">' . esc_html__('Select a .json file to apply instantly.', 'tegatai-secure') . '</p>';
        echo '<input type="file" id="teg-import-file" accept=".json" style="margin-bottom:8px; font-size:12px; max-width:100%;">';
        echo '<br><button id="teg-run-import" class="button button-primary"><span class="dashicons dashicons-upload" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Import', 'tegatai-secure') . '</button>';
        echo '</div>';
        
        echo '</div>'; 
        
        echo '<script>
        jQuery(document).ready(function($) {
            $("#teg-run-import").on("click", function(e) {
                e.preventDefault();
                var fileInput = document.getElementById("teg-import-file");
                if (fileInput.files.length === 0) { alert(\'' . esc_js(__('Please select a .json file first!', 'tegatai-secure')) . '\'); return; }
                if (!confirm(\'' . esc_js(__('WARNING: This will overwrite all settings. Continue?', 'tegatai-secure')) . '\')) return;
                
                var file = fileInput.files[0];
                var reader = new FileReader();
                var btn = $(this);
                btn.prop("disabled", true).text("Importing...");
                
                reader.onload = function(e) {
                    var jsonContent = e.target.result;
                    $.post(ajaxurl, { action: "teg_import_config", json: jsonContent, _ajax_nonce: "' . wp_create_nonce('teg_admin_nonce') . '" }, function(r) {
                        if (r.success) {
                            alert(\'' . esc_js(__('Successfully imported! Reloading.', 'tegatai-secure')) . '\');
                            location.reload();
                        } else {
                            alert(\'' . esc_js(__('Import error: ', 'tegatai-secure')) . '\' + (r.data.msg || "Error"));
                            btn.prop("disabled", false).html("<span class=\'dashicons dashicons-upload\' style=\'vertical-align:middle; margin-top:3px;\'></span> Import");
                        }
                    });
                };
                reader.readAsText(file);
            });
        });
        </script>';
        
        echo '</div>'; 
        
        echo '</div>'; 
    }
        elseif ($tab == 'logs') { echo '<div class="teg-card"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;"><h3>' . esc_html__('Live Traffic Log', 'tegatai-secure') . '</h3><form method="post"><input type="hidden" name="teg_action" value="clear_logs">'.wp_nonce_field('teg_act_nonce','_wpnonce',true,false).'<input type="submit" class="button button-secondary" value="' . esc_attr__('Clear Logs', 'tegatai-secure') . '"  onclick="return confirm(\'' . esc_js(__('Are you sure?', 'tegatai-secure')) . '\');"></form></div><div style="max-height:600px; overflow-y:auto; border:1px solid var(--teg-border); border-radius:6px;"><table class="teg-table"><thead><tr><th>' . esc_html__('Time', 'tegatai-secure') . '</th><th>' . esc_html__('Type', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Message', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_Logger::get_logs(200) as $l): $c = in_array($l['type'], ['WAF','FLOOD','BAN-404','AUTH-BAN','SPAM','GEO-BLK'])?'var(--teg-danger)':'var(--teg-text)'; echo "<tr><td>".esc_html($l['time'])."</td><td style='font-weight:bold; color:$c;'>".esc_html($l['type'])."</td><td><code>".esc_html($l['ip'])."</code></td><td>".esc_html($l['message'])."</td></tr>"; endforeach; echo '</tbody></table></div></div>'; }
    
        elseif ($tab == 'fim') {
            if (isset($_POST['teg_fim_build']) && function_exists('check_admin_referer') && check_admin_referer('teg_fim_build')) {
                if (class_exists('Tegatai_FIM')) {
                    Tegatai_FIM::build_snapshot();
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Baseline snapshot created.', 'tegatai-secure') . '</p></div>';
                }
            }

            $res = null;
            if (isset($_POST['teg_fim_check']) && function_exists('check_admin_referer') && check_admin_referer('teg_fim_check')) {
                if (class_exists('Tegatai_FIM')) {
                    $res = Tegatai_FIM::check_integrity();
                }
            }

            $last = class_exists('Tegatai_FIM') ? get_option(Tegatai_FIM::OPT_LASTRUN, []) : [];
            $lt = !empty($last['time']) ? date_i18n('Y-m-d H:i', intval($last['time'])) : '-';

            echo '<div class="teg-grid">';
            echo '<div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('File Integrity Monitor (FIM)', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Tracks file changes in Plugins, MU-Plugins and Themes.', 'tegatai-secure') . '</p>';

            echo '<div style="display:flex; gap:10px; flex-wrap:wrap;">';
            echo '<form method="post">';
            echo wp_nonce_field('teg_fim_build', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_fim_build" value="1">' . esc_html__('Create baseline', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post">';
            echo wp_nonce_field('teg_fim_check', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_fim_check" value="1">' . esc_html__('Check now', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '</div>';

            echo '<p class="teg-muted" style="margin-top:10px; font-size:11px;">' . esc_html(sprintf(__('Last run: %s', 'tegatai-secure'), $lt)) . '</p>';

            if (is_array($res) && !empty($res['ok'])) {
                $c_changed = is_array($res['changed'] ?? null) ? count($res['changed']) : 0;
                $c_new     = is_array($res['new'] ?? null) ? count($res['new']) : 0;
                $c_del     = is_array($res['deleted'] ?? null) ? count($res['deleted']) : 0;

                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-danger);">'.$c_changed.'</span><span class="teg-stat-label">Changed</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-primary);">'.$c_new.'</span><span class="teg-stat-label">New</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-muted);">'.$c_del.'</span><span class="teg-stat-label">Deleted</span></div>';
                echo '</div>';

                $show = function($label, $arr) {
                    if (empty($arr) || !is_array($arr)) return;
                    echo '<h4 style="margin-top:14px;">' . esc_html($label) . '</h4>';
                    echo '<div class="teg-table" style="max-height: 250px; overflow-y: auto;"><table class="widefat striped"><tbody>';
                    $i = 0;
                    foreach ($arr as $k => $v) {
                        if ($i++ >= 60) break;
                        $file = is_array($v) ? ($v['rel'] ?? $k) : $k;
                        if (is_array($v) && isset($v['old']['rel'])) $file = $v['old']['rel'];
                        echo '<tr><td><code>' . esc_html((string)$file) . '</code></td></tr>';
                    }
                    echo '</tbody></table></div>';
                };

                $show(__('Changed files', 'tegatai-secure'), $res['changed'] ?? []);
                $show(__('New files', 'tegatai-secure'), $res['new'] ?? []);
                $show(__('Deleted files', 'tegatai-secure'), $res['deleted'] ?? []);
            } elseif (is_array($res) && !empty($res['error'])) {
                echo '<div style="padding:10px; background:#fffbeb; color:#b45309; border:1px solid #fde68a; border-radius:6px; margin-top:15px; font-size:12px;">' . esc_html__('No baseline exists yet. Click “Create baseline” first.', 'tegatai-secure') . '</div>';
            }

            echo '</div></div>';
        }


        elseif ($tab == 'dbscan') {
            $result = null;
            if (isset($_POST['teg_dbscan_run']) && function_exists('check_admin_referer') && check_admin_referer('teg_dbscan_run')) {
                if (class_exists('Tegatai_DBScan')) {
                    $result = Tegatai_DBScan::scan_stored_xss(200);
                }
            }

            echo '<div class="teg-grid">';
            echo '<div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('Stored-XSS Database Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Read-only scan of common WP tables for suspicious HTML/JS patterns.', 'tegatai-secure') . '</p>';

            echo '<form method="post">';
            echo wp_nonce_field('teg_dbscan_run', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_dbscan_run" value="1">' . esc_html__('Run scan', 'tegatai-secure') . '</button>';
            echo '</form>';

            if (is_array($result)) {
                $hits = $result['hits'] ?? [];
                
                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="font-size:16px;">'.$result['prefix'].'</span><span class="teg-stat-label">Prefix</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num">'.$result['rows_checked'].'</span><span class="teg-stat-label">Rows Checked</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:'.(count($hits) > 0 ? 'var(--teg-danger)' : 'var(--teg-success)').'">'.count($hits).'</span><span class="teg-stat-label">Hits</span></div>';
                echo '</div>';

                if (empty($hits)) {
                    echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px;">✅ ' . esc_html__('No suspicious patterns found.', 'tegatai-secure') . '</div>';
                } else {
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:200px;">' . esc_html__('Table', 'tegatai-secure') . '</th>';
                    echo '<th style="width:80px;">' . esc_html__('ID', 'tegatai-secure') . '</th>';
                    echo '<th style="width:120px;">' . esc_html__('Field', 'tegatai-secure') . '</th>';
                    echo '<th>' . esc_html__('Snippet', 'tegatai-secure') . '</th>';
                    echo '</tr></thead><tbody>';

                    $max = 400;
                    $i = 0;
                    foreach ($hits as $h) {
                        if ($i++ >= $max) break;
                        echo '<tr>';
                        echo '<td><code>' . esc_html((string)($h['table'] ?? '')) . '</code></td>';
                        echo '<td><code>' . esc_html((string)($h['id'] ?? '')) . '</code></td>';
                        echo '<td><code>' . esc_html((string)($h['field'] ?? '')) . '</code></td>';
                        echo '<td style="word-break:break-word; font-size:11px;">' . esc_html((string)($h['snippet'] ?? '')) . '</td>';
                        echo '</tr>';
                    }
                    echo '</tbody></table></div>';
                }
            }
            echo '</div></div>';
        }


        elseif ($tab == 'malware') {
            $limit = isset($_POST['teg_mw_limit']) ? intval($_POST['teg_mw_limit']) : 1200;
            if ($limit < 200) $limit = 200;
            if ($limit > 3000) $limit = 3000;

            $result = null;

            
            if (isset($_POST['teg_mw_quarantine']) && check_admin_referer('teg_mw_quarantine')) {
                $prog = get_option('teg_mw_progress_v1', []);
                $hits_q = isset($prog['hits']) && is_array($prog['hits']) ? $prog['hits'] : [];
                $count_ok = 0; $count_fail = 0;
                if (class_exists('Tegatai_Malware_Scanner')) {
                    foreach ($hits_q as $h) {
                        $r = Tegatai_Malware_Scanner::quarantine_hit(is_array($h) ? $h : []);
                        if (!empty($r['ok'])) { $count_ok++; } else { $count_fail++; }
                        if (($count_ok + $count_fail) >= 50) { break; }
                    }
                }
                echo '<div style="padding:10px; background:#fffbeb; color:#b45309; border:1px solid #fde68a; border-radius:6px; margin-bottom:15px; font-size:12px;">' . esc_html(sprintf(__('Quarantine done: %d ok, %d failed (max 50 per click).', 'tegatai-secure'), $count_ok, $count_fail)) . '</div>';
            }
            if (isset($_POST['teg_mw_reset']) && check_admin_referer('teg_mw_reset')) {
                if (class_exists('Tegatai_Malware_Scanner')) { Tegatai_Malware_Scanner::reset(); }
                echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; margin-bottom:15px; border:1px solid #bbf7d0; font-size:12px;">' . esc_html__('State reset.', 'tegatai-secure') . '</div>';
            }

            if (isset($_POST['teg_mw_run']) && check_admin_referer('teg_mw_run')) {
                if (class_exists('Tegatai_Malware_Scanner')) {
                    $result = Tegatai_Malware_Scanner::run(['limit' => $limit, 'reset' => !empty($_POST['teg_mw_fresh'])]);
                }
            } else {
                $result = get_option('teg_mw_progress_v1', null);
            }

            echo '<div class="teg-grid"><div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('Malware / Backdoor Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:15px;">' . esc_html__('Signature-based scan for common malware/backdoor patterns.', 'tegatai-secure') . '</p>';

            echo '<div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">';
            echo '<form method="post" style="display:flex; gap:10px; align-items:center;">';
            echo wp_nonce_field('teg_mw_run', '_wpnonce', true, false);
            echo '<input type="number" name="teg_mw_limit" value="' . esc_attr((string)$limit) . '" class="teg-form-input" style="width:80px; margin:0;" />';
            echo '<label style="font-size:12px; font-weight:600;"><input type="checkbox" name="teg_mw_fresh" value="1" /> ' . esc_html__('Fresh scan', 'tegatai-secure') . '</label>';
            echo '<button class="button button-primary" name="teg_mw_run" value="1">' . esc_html__('Run', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post">';
            echo wp_nonce_field('teg_mw_reset', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_mw_reset" value="1">' . esc_html__('Reset', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '</div>';

            if (is_array($result)) {
                $hits = isset($result['hits']) && is_array($result['hits']) ? $result['hits'] : [];
                $checked = isset($result['checked']) ? intval($result['checked']) : 0;
                $total = isset($result['total_files']) ? intval($result['total_files']) : 0;
                $done = !empty($result['done']);

                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num">'.$checked.' / '.$total.'</span><span class="teg-stat-label">Progress</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:'.(count($hits) > 0 ? 'var(--teg-danger)' : 'var(--teg-success)').'">'.count($hits).'</span><span class="teg-stat-label">Findings</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:'.($done ? 'var(--teg-success)' : 'var(--teg-primary)').'">'.($done ? 'DONE' : 'RUNNING').'</span><span class="teg-stat-label">Status</span></div>';
                echo '</div>';

                $cnt = count($hits);
                if ($cnt === 0 && $done) {
                    echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px;">✅ ' . esc_html__('Clean.', 'tegatai-secure') . '</div>';
                } elseif ($cnt > 0) {
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:50px;">' . esc_html__('Sev', 'tegatai-secure') . '</th>';
                    echo '<th style="width:100px;">' . esc_html__('Rule', 'tegatai-secure') . '</th>';
                    echo '<th style="width:300px;">' . esc_html__('File', 'tegatai-secure') . '</th>';
                    echo '<th>' . esc_html__('Snippet', 'tegatai-secure') . '</th>';
                    echo '</tr></thead><tbody>';

                    $max = 250;
                    for ($i = 0; $i < min($max, $cnt); $i++) {
                        $h = $hits[$i];
                        $sev = (int)($h['sev'] ?? 0);
                        $sev_color = ($sev >= 5) ? 'var(--teg-danger)' : (($sev >= 4) ? '#d97706' : '#6b7280');

                        echo '<tr>';
                        echo '<td><strong style="color:' . esc_attr($sev_color) . ';">' . esc_html((string)$sev) . '</strong></td>';
                        echo '<td><code>' . esc_html((string)($h['rule'] ?? '')) . '</code></td>';
                        echo '<td><code>' . esc_html((string)($h['file'] ?? '')) . '</code></td>';
                        echo '<td style="word-break:break-word; font-size:11px;"><code>' . esc_html((string)($h['snippet'] ?? '')) . '</code></td>';
                        echo '</tr>';
                    }
                    echo '</tbody></table></div>';
                }
            }
            echo '</div></div>';
        }


        elseif ($tab == 'timeline') {
            echo '<div class="teg-grid"><div class="teg-card" style="grid-column: span 2;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">';
            echo '<h3 style="margin:0; border:none; padding:0;">' . esc_html__('Security Timeline', 'tegatai-secure') . '</h3>';
            
            if (class_exists('Tegatai_Timeline')) {
                if (isset($_POST['teg_tl_clear']) && check_admin_referer('teg_tl_clear')) {
                    Tegatai_Timeline::clear();
                }
                echo '<form method="post" style="margin:0;">';
                echo wp_nonce_field('teg_tl_clear', '_wpnonce', true, false);
                echo '<button class="button button-secondary" name="teg_tl_clear" value="1" onclick="return confirm(\'' . esc_js(__('Clear?', 'tegatai-secure')) . '\');">' . esc_html__('Clear', 'tegatai-secure') . '</button>';
                echo '</form>';
            }
            echo '</div>';
            
            if (class_exists('Tegatai_Timeline')) {
                $events = Tegatai_Timeline::get(250);
                if (empty($events)) {
                    echo '<p class="teg-muted">' . esc_html__('No events yet.', 'tegatai-secure') . '</p>';
                } else {
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:140px;">' . esc_html__('Time', 'tegatai-secure') . '</th>';
                    echo '<th style="width:120px;">' . esc_html__('Type', 'tegatai-secure') . '</th>';
                    echo '<th>' . esc_html__('Message', 'tegatai-secure') . '</th>';
                    echo '</tr></thead><tbody>';
                    foreach ($events as $e) {
                        $t = !empty($e['time']) ? date_i18n('Y-m-d H:i', intval($e['time'])) : '-';
                        echo '<tr>';
                        echo '<td><code>' . esc_html($t) . '</code></td>';
                        echo '<td><code>' . esc_html((string)($e['type'] ?? '')) . '</code></td>';
                        echo '<td style="word-break:break-word;">' . esc_html((string)($e['msg'] ?? '')) . '</td>';
                        echo '</tr>';
                    }
                    echo '</tbody></table></div>';
                }
            }
            echo '</div></div>';
        }
        elseif ($tab == 'core') {
            echo '<div class="teg-grid"><div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('WordPress Core Integrity', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Compares wp-admin/wp-includes core files against official WP checksums.', 'tegatai-secure') . '</p>';
            $res = null;
            if (isset($_POST['teg_core_check']) && check_admin_referer('teg_core_check')) {
                if (class_exists('Tegatai_Core_Integrity')) { $res = Tegatai_Core_Integrity::check(); }
            }
            echo '<form method="post" style="margin:12px 0;">';
            echo wp_nonce_field('teg_core_check', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_core_check" value="1">' . esc_html__('Run check', 'tegatai-secure') . '</button>';
            echo '</form>';
            if (is_array($res)) {
                $bad = $res['bad'] ?? [];
                $missing = $res['missing'] ?? [];
                $extra = $res['extra'] ?? [];
                
                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-danger);">'.count($bad).'</span><span class="teg-stat-label">Modified</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:#d97706;">'.count($missing).'</span><span class="teg-stat-label">Missing</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-primary);">'.count($extra).'</span><span class="teg-stat-label">Extra</span></div>';
                echo '</div>';
                
                if (!empty($bad) || !empty($missing)) {
                    $corrupted = array_unique(array_merge($bad, $missing));
                    echo '<h4 style="margin-top:20px; border-bottom:1px solid #eee; padding-bottom:8px;">' . esc_html__('Corrupted Files', 'tegatai-secure') . '</h4>';
                    echo '<div class="teg-table"><table class="widefat striped"><tbody>';
                    foreach ($corrupted as $b) {
                        echo '<tr>';
                        echo '<td><code>' . esc_html($b) . '</code></td>';
                        echo '<td style="width:100px; text-align:right;"><a href="#" class="teg-heal-core" data-file="'.esc_attr($b).'" style="color:var(--teg-success); font-weight:bold; text-decoration:none;"><span class="dashicons dashicons-admin-tools" style="vertical-align:middle;"></span> Heal</a></td>';
                        echo '</tr>';
                    }
                    echo '</tbody></table></div>';
                    
                    echo '<script>
                    jQuery(document).ready(function($) {
                        $(".teg-heal-core").on("click", function(e) {
                            e.preventDefault();
                            if(!confirm(\'' . esc_js(__('Do you want to overwrite this file with the clean original version from WordPress.org?', 'tegatai-secure')) . '\')) return;
                            var btn = $(this);
                            var file = btn.data("file");
                            btn.html("<span class=\'dashicons dashicons-update\' style=\'vertical-align:middle;\'></span> Healing...");
                            
                            $.post(ajaxurl, { action: "teg_heal_core", file: file, _ajax_nonce: "' . wp_create_nonce('teg_admin_nonce') . '" }, function(r) {
                                if (r.success) {
                                    btn.closest("tr").css("background", "#dcfce7").fadeOut(800);
                                } else {
                                    alert(\'' . esc_js(__('Repair error: ', 'tegatai-secure')) . '\' + (r.data.msg || "Unknown"));
                                    btn.html("<span class=\'dashicons dashicons-admin-tools\' style=\'vertical-align:middle;\'></span> Heal");
                                }
                            });
                        });
                    });
                    </script>';
                } else {
                    echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px; margin-top:10px;">✅ WP Core ' . esc_html($res['version'] ?? '') . ' ist sauber.</div>';
                }
            }
            echo '</div></div>';
        }
        elseif ($tab == 'options') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Dangerous Options Scanner', 'tegatai-secure') . '</h3>';
            $res = null;
            if (isset($_POST['teg_opt_scan']) && check_admin_referer('teg_opt_scan')) {
                if (class_exists('Tegatai_Option_Scanner')) { $res = Tegatai_Option_Scanner::scan(2500); }
            }
            echo '<form method="post" style="margin:12px 0;">';
            echo wp_nonce_field('teg_opt_scan', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_opt_scan" value="1">' . esc_html__('Scan options', 'tegatai-secure') . '</button>';
            echo '</form>';
            if (is_array($res)) {
                $hits = $res['hits'] ?? [];
                echo '<p><strong>' . esc_html__('Hits', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($hits)) . '</code></p>';
            }
            echo '</div><div class="teg-card">';
            echo '<h3>' . esc_html__('Whitelist (Exceptions)', 'tegatai-secure') . '</h3>';
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<textarea name="tegatai_options[option_whitelist_names]" class="teg-form-input" placeholder="_transient_&#10;elementor_">'.esc_textarea($this->get_opt('option_whitelist_names', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" >';
            echo '</form>';
            echo '</div>'; 
            echo '</div>'; 
        }
        elseif ($tab == 'cron') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Suspicious Cron Monitor', 'tegatai-secure') . '</h3>';
            $res = class_exists('Tegatai_Cron_Monitor') ? Tegatai_Cron_Monitor::inspect() : [];
            $all = $res['all'] ?? [];
            $hits = $res['hits'] ?? [];
            echo '<p><strong>' . esc_html__('Total hooks', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($all)) . '</code>';
            echo ' &nbsp;|&nbsp; <strong>' . esc_html__('Flagged', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($hits)) . '</code></p>';
            echo '</div><div class="teg-card">';
            echo '<h3>' . esc_html__('Whitelist (Exceptions)', 'tegatai-secure') . '</h3>';
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<textarea name="tegatai_options[cron_whitelist_hooks]" class="teg-form-input" placeholder="mailpoet&#10;woocommerce">'.esc_textarea($this->get_opt('cron_whitelist_hooks', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '">';
            echo '</form>';
            echo '</div>';
            echo '<div style="grid-column: 1 / -1;">';
            $this->render_cron_list(); 
            echo '</div></div>';
        }
        elseif ($tab == 'uploads') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Uploads Monitor', 'tegatai-secure') . '</h3>';
            if (isset($_POST['teg_up_scan']) && check_admin_referer('teg_up_scan')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { Tegatai_Uploads_Monitor::scan(2000); }
            }
            if (isset($_POST['teg_up_quarantine']) && check_admin_referer('teg_up_quarantine')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { Tegatai_Uploads_Monitor::quarantine_hits(50); }
            }
            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            echo wp_nonce_field('teg_up_scan', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_up_scan" value="1">' . esc_html__('Scan uploads', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '<form method="post" style="margin:0 0 12px 0;">';
            echo wp_nonce_field('teg_up_quarantine', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_up_quarantine" value="1">' . esc_html__('Quarantine flagged (max 50)', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '</div></div>';
        }
        elseif ($tab == 'perms') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Permission Monitor', 'tegatai-secure') . '</h3>';
            $res = class_exists('Tegatai_Perm_Monitor') ? Tegatai_Perm_Monitor::check() : [];
            $rows = $res['rows'] ?? [];
            echo '<p><strong>' . esc_html__('Checked', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($rows)) . '</code></p>';
            echo '</div></div>';
        }

}

    public function add_dashboard_widgets() {
        wp_add_dashboard_widget('tegatai_dashboard_widget', __('🛡️ Tegatai Security Status', 'tegatai-secure'), [$this, 'render_dashboard_widget']);
    }

    public function render_dashboard_widget() {
        $stats = Tegatai_Logger::get_stats();
        $scan_status = get_option('teg_scan_status');
        $last_scan = isset($scan_status['last_scan']) ? $scan_status['last_scan'] : __('Never', 'tegatai-secure');
        $scan_res = (isset($scan_status['bad_files']) && empty($scan_status['bad_files'])) ? '<span style="color:#10b981;font-weight:bold;">' . esc_html__('Clean ✅', 'tegatai-secure') . '</span>' : '<span style="color:#ef4444;font-weight:bold;">' . esc_html__('Scan required...', 'tegatai-secure') . '</span>';
        
        echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:center;margin-bottom:15px;">';
        echo '<div style="background:#f3f4f6;padding:10px;border-radius:5px;"><strong>' . esc_html__('Blocked', 'tegatai-secure') . '</strong><br><span style="font-size:20px;color:#ef4444;">' . intval($stats['blocked']) . '</span></div>';
        echo '<div style="background:#f3f4f6;padding:10px;border-radius:5px;"><strong>' . esc_html__('Traffic', 'tegatai-secure') . '</strong><br><span style="font-size:20px;color:#4f46e5;">' . intval($stats['total']) . '</span></div>';
        echo '</div>';
        
        echo '<div style="border-top:1px solid #eee;padding-top:10px;font-size:13px;">';
        echo '<strong>' . esc_html__('Last Scan:', 'tegatai-secure') . '</strong> ' . esc_html($last_scan) . '<br>';
        echo '<strong>' . esc_html__('Result:', 'tegatai-secure') . '</strong> ' . $scan_res;
        echo '</div>';
        
        echo '<div style="margin-top:15px;text-align:right;">';
        echo '<a href="admin.php?page=tegatai-secure" class="button button-primary">' . esc_html__('Go to Dashboard', 'tegatai-secure') . '</a>';
        echo '</div>';
    }



    public function ajax_restore_quarantine() {
        check_ajax_referer('teg_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        $id = sanitize_text_field($_POST['id'] ?? '');
        if (!$id || !class_exists('Tegatai_Quarantine')) wp_send_json_error();
        $res = Tegatai_Quarantine::restore_file($id);
        if ($res['ok']) wp_send_json_success();
        else wp_send_json_error(['msg' => $res['error']]);
    }

    
    public function render_cron_list() {
        echo '<div class="teg-card" style="margin-top:0;">';
        echo '<h3 style="margin-top:0;"><span class="dashicons dashicons-clock" style="vertical-align:middle;"></span> ' . esc_html__('Active WP-Cron Jobs', 'tegatai-secure') . '</h3>';
        echo '<table class="teg-table" style="margin-top:10px;">';
        echo '<thead><tr><th>' . esc_html__('Next Run', 'tegatai-secure') . '</th><th>' . esc_html__('Hook', 'tegatai-secure') . '</th><th>' . esc_html__('Schedule', 'tegatai-secure') . '</th><th>' . esc_html__('Action', 'tegatai-secure') . '</th></tr></thead>';
        echo '<tbody>';

        $crons = _get_cron_array();
        $events = [];
        if (!empty($crons)) {
            foreach ($crons as $time => $hooks) {
                foreach ($hooks as $hook => $handlers) {
                    foreach ($handlers as $handler_key => $handler) {
                        $events[] = [
                            'time' => $time,
                            'hook' => $hook,
                            'schedule' => empty($handler['schedule']) ? 'Single Event' : $handler['schedule'],
                            'args' => !empty($handler['args']) ? wp_json_encode($handler['args']) : 'None'
                        ];
                    }
                }
            }
        }

        usort($events, function($a, $b) { return $a['time'] <=> $b['time']; });
        $time_format = get_option('date_format') . ' ' . get_option('time_format');
        $now = time();

        if (empty($events)) {
            echo '<tr><td colspan="4">' . esc_html__('No cron jobs found.', 'tegatai-secure') . '</td></tr>';
        } else {
            foreach ($events as $e) {
                $in_seconds = $e['time'] - $now;
                $in_text = $in_seconds > 0 ? human_time_diff($now, $e['time']) . ' from now' : 'Running';
                $color = $in_seconds < 0 ? 'color:var(--teg-danger);font-weight:bold;' : 'color:var(--teg-primary);';

                echo '<tr>';
                echo '<td><strong style="'.$color.'">' . esc_html(wp_date($time_format, $e['time'])) . '</strong><br><small>(' . esc_html($in_text) . ')</small></td>';
                echo '<td><code>' . esc_html($e['hook']) . '</code></td>';
                echo '<td>' . esc_html(ucfirst($e['schedule'])) . '</td>';
                echo '<td><a href="#" class="teg-delete-cron" data-hook="' . esc_attr($e['hook']) . '" style="color:var(--teg-danger); text-decoration:none;"><span class="dashicons dashicons-trash" style="vertical-align:middle;"></span> Delete</a></td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table></div>';

        echo "<script>
        jQuery(document).ready(function($) {
            $('.teg-delete-cron').on('click', function(e) {
                e.preventDefault();
                if (!confirm('Warning: Deleting a WP cron can affect plugin functionality. Proceed?')) return;
                var btn = $(this);
                var hook = btn.data('hook');
                btn.text('Deleting...');
                $.post(ajaxurl, { action: 'teg_delete_cron', hook: hook, _ajax_nonce: '" . wp_create_nonce('teg_admin_nonce') . "' }, function(r) {
                    if (r.success) { btn.closest('tr').fadeOut(); }
                    else { alert('Error: ' + (r.data.msg || 'Unknown error')); btn.text('Delete'); }
                });
            });
        });
        </script>";
    }

    
    public function export_config() {
        if (!current_user_can('manage_options') || !isset($_GET['_wpnonce']) || !wp_verify_nonce($_GET['_wpnonce'], 'teg_export_nonce')) wp_die('Forbidden');
        $ops = get_option($this->options_slug, []);
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="tegatai-config-'.date('Y-m-d').'.json"');
        echo wp_json_encode($ops);
        exit;
    }

    public function ajax_import_config() {
        check_ajax_referer('teg_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        $json = stripslashes($_POST['json'] ?? '');
        $data = json_decode($json, true);
        if (!$data || !is_array($data)) wp_send_json_error(['msg' => __('Invalid JSON format.', 'tegatai-secure')]);
        update_option($this->options_slug, $data);
        wp_send_json_success();
    }

    public function ajax_deep_clean() {
        check_ajax_referer('teg_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        global $wpdb;
        $stats = [];
        
        // 1. Expired Transients
        $time = time();
        $sql = "SELECT option_name FROM {$wpdb->options} WHERE option_name LIKE '\_transient\_timeout\_%' AND option_value < %d";
        $expired = $wpdb->get_col($wpdb->prepare($sql, $time));
        $del_trans = 0;
        foreach ($expired as $t) {
            $key = str_replace('_transient_timeout_', '', $t);
            delete_transient($key);
            $del_trans++;
        }
        if ($del_trans > 0) $stats[] = sprintf(__('🗑️ <strong>%d</strong> expired transients deleted.', 'tegatai-secure'), $del_trans);

        // 2. Spam & Trash Kommentare
        $spam_del = $wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam' OR comment_approved = 'trash'");
        if ($spam_del > 0) $stats[] = sprintf(__('🗑️ <strong>%d</strong> spam/trash comments removed.', 'tegatai-secure'), $spam_del);

        // 3. Post Revisions
        $rev_del = $wpdb->query("DELETE a,b,c FROM {$wpdb->posts} a LEFT JOIN {$wpdb->term_relationships} b ON ( a.ID = b.object_id ) LEFT JOIN {$wpdb->postmeta} c ON ( a.ID = c.post_id ) WHERE a.post_type = 'revision'");
        if ($rev_del > 0) $stats[] = sprintf(__('🗑️ <strong>%d</strong> old post revisions cleaned.', 'tegatai-secure'), $rev_del);

        // 4. Optimize Tables
        $tables = $wpdb->get_col("SHOW TABLES");
        foreach ($tables as $table) {
            $wpdb->query("OPTIMIZE TABLE `$table`");
        }
        $stats[] = __('⚡ Database tables defragmented (overhead released).', 'tegatai-secure');

        if (empty($stats)) $stats[] = __('Everything was already spotless! No cleanup needed.', 'tegatai-secure');

        wp_send_json_success(['stats' => $stats]);
    }

    
    public function ajax_heal_core() {
        check_ajax_referer('teg_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        $file = sanitize_text_field($_POST['file'] ?? '');
        if (!$file || !class_exists('Tegatai_Core_Integrity')) wp_send_json_error();
        $res = Tegatai_Core_Integrity::heal_file($file);
        if (isset($res['ok']) && $res['ok']) wp_send_json_success();
        else wp_send_json_error(['msg' => $res['error'] ?? 'Unbekannter Fehler']);
    }

    public function ajax_delete_cron() {
        check_ajax_referer('teg_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        $hook = sanitize_text_field($_POST['hook'] ?? '');
        if (!$hook) wp_send_json_error(['msg' => 'Hook fehlt']);
        
        $crons = _get_cron_array();
        $found = false;
        foreach ($crons as $time => $hooks) {
            if (isset($hooks[$hook])) {
                foreach ($hooks[$hook] as $key => $data) {
                    wp_unschedule_event($time, $hook, $data['args'] ?? []);
                    $found = true;
                }
            }
        }
        if ($found) wp_send_json_success();
        else wp_send_json_error(['msg' => 'Cron nicht gefunden']);
    }

}
