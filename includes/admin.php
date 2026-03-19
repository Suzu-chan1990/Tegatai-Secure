<?php

/* TEGATAI_RECOMMENDATIONS_PATCH_V1 */


/* TEGATAI_DASHBOARD_TOP5_FORCE_V1 */


/* TEGATAI_SERVER_STATUS_EXPANDED_V1 */


/* TEGATAI_TRUSTED_DEVICES_PATCH_V2 */


/* TEGATAI_ADMIN_MOJIBAKE_REPAIR_V1 applied 2026-02-26 22:56:23 */
/* TEGATAI_ADMIN_EMBEDDED_I18N_FIX_V1 applied 2026-02-26 22:35:46 */

/* TEGATAI_ADMIN_PARSE_FIX_V1 applied 2026-02-26 22:33:01 */








/* TEGATAI_FIX_MOJIBAKE_QUICK_ACCESS_V1 applied 2026-02-26 22:21:40 */
/* TEGATAI_I18N_MOJIBAKE_FIX_V1 applied 2026-02-26 22:16:58 */
/* TEGATAI_I18N_DE_EN_V1 applied 2026-02-26 22:09:36 */
/* TEGATAI_HEADERS_CONFLICT_FIX_PLUS_PROBE_V2 applied 2026-02-26 22:01:45 */
/* TEGATAI_ADMIN_ROOT_WRITABLE_CHECK_V1 applied 2026-02-26 21:47:54 */
/* TEGATAI_FORCE_RULES_TO_WP_ROOT_V1 applied 2026-02-26 21:43:03 */
/* TEGATAI_ADMIN_INTEGRATION_CHECK_V1 applied 2026-02-26 20:39:58 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Admin {
    private $options_slug = 'tegatai_options';
    
    // ALLE FELDER
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

    public function register_settings() {
        register_setting('tegatai_group', $this->options_slug);
    }

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
        /* TEGATAI_TD_WHITELIST */
        if (!$key || !in_array($key, $this->all_fields, true)) { wp_send_json_error('Invalid key'); }
 
        $ops = get_option($this->options_slug, []); $ops[$key] = ($val === '1') ? 1 : 0;
        /* TEGATAI_TD_KEY_SYNC */
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
            .teg-header { background: linear-gradient(135deg, #0f1720 0%, #1e293b 100%); color: white; padding: 25px 30px; border-radius: 16px; margin-bottom: 25px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.1); }
            .teg-title { font-size: 24px; font-weight: 800; display: flex; align-items: center; gap: 12px; }
            .teg-badge { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); padding: 4px 12px; border-radius: 20px; font-size: 12px; font-weight: 700; color: #fff; border: 1px solid rgba(255,255,255,0.2); }
            
            /* NEU: Das Sidebar Grid-Layout */
            .teg-layout { display: grid; grid-template-columns: 240px 1fr; gap: 24px; align-items: start; }
            .teg-sidebar { background: var(--teg-surface); border: 1px solid var(--teg-border); border-radius: 14px; padding: 16px; position: sticky; top: 40px; box-shadow: 0 4px 20px rgba(0,0,0,0.03); }
            .teg-menu-group { font-size: 11px; text-transform: uppercase; font-weight: 800; color: var(--teg-muted); margin: 20px 0 8px 8px; letter-spacing: 0.5px; }
            .teg-menu-group:first-child { margin-top: 0; }
            .teg-tab { display: flex; align-items: center; gap: 10px; padding: 10px 12px; text-decoration: none; color: var(--teg-text); font-weight: 600; font-size: 13px; border-radius: 10px; transition: all 0.2s; margin-bottom: 2px; border: 1px solid transparent; }
            .teg-tab:hover { background: rgba(6, 182, 212, 0.08); color: var(--teg-primary); }
            .teg-tab.active { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); color: #fff; box-shadow: 0 4px 12px rgba(6, 182, 212, 0.25); border-color: transparent; }
            .teg-tab .dashicons { font-size: 16px; width: 16px; height: 16px; }
            
            /* Anpassung der bestehenden Cards an das neue Design */
            .teg-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 20px; }
            .teg-card { background: var(--teg-card); border-radius: 14px; padding: 25px; box-shadow: 0 8px 24px rgba(2,6,23,0.04); border: 1px solid var(--teg-border); }
            .teg-card h3 { margin-top: 0; font-size: 15px; font-weight: 800; border-bottom: 1px solid var(--teg-border); padding-bottom: 15px; margin-bottom: 20px; text-transform: uppercase; color: var(--teg-text); }
            .teg-stat-row { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; margin-bottom: 25px; }
            .teg-stat-box { background: var(--teg-surface); padding: 20px; border-radius: 12px; text-align: center; border: 1px solid var(--teg-border); box-shadow: 0 4px 12px rgba(0,0,0,0.02); }
            .teg-stat-num { font-size: 28px; font-weight: 800; display: block; line-height: 1.2; }
            .teg-stat-label { font-size: 12px; text-transform: uppercase; font-weight: 700; color: var(--teg-muted); margin-top: 5px; }
            
            /* Formulare & Buttons */
            .teg-form-input { width: 100%; padding: 10px 12px; border: 1px solid var(--teg-border); border-radius: 8px; font-size: 14px; margin-bottom: 10px; background: var(--teg-bg); color: var(--teg-text); transition: all 0.2s; }
            .teg-form-input:focus { border-color: var(--teg-primary); outline: none; background: var(--teg-surface); box-shadow: 0 0 0 3px rgba(6, 182, 212, 0.15); }
            textarea.teg-form-input { min-height: 100px; font-family: monospace; font-size: 13px; }
            .button-primary { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)) !important; border: none !important; padding: 8px 20px !important; border-radius: 8px !important; font-weight:600 !important; color:#fff !important; box-shadow: 0 4px 12px rgba(6, 182, 212, 0.2) !important; text-shadow: none !important; }
            .button-secondary { background: var(--teg-surface) !important; border: 1px solid var(--teg-border) !important; padding: 8px 20px !important; border-radius: 8px !important; font-weight:600 !important; color: var(--teg-text) !important; text-shadow: none !important; }
            
            /* Switches & Tables */
            .teg-switch-row { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px dashed var(--teg-border); }
            .teg-switch-label { font-size: 14px; font-weight: 700; display: block; margin-bottom: 2px; color: var(--teg-text); }
            .teg-switch-desc { font-size: 12px; color: var(--teg-muted); display: block; max-width: 90%; }
            .switch { position: relative; display: inline-block; width: 44px; height: 24px; flex-shrink: 0; }
            .switch input { opacity: 0; width: 0; height: 0; }
            .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: var(--teg-border); transition: .3s; border-radius: 34px; }
            .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .3s; border-radius: 50%; box-shadow: 0 2px 4px rgba(0,0,0,0.2); }
            input:checked + .slider { background: linear-gradient(90deg, var(--teg-primary), var(--teg-accent)); }
            input:checked + .slider:before { transform: translateX(20px); }
            
            .teg-table { width:100%; border-collapse:collapse; font-size:13px; border-radius: 12px; overflow: hidden; border: 1px solid var(--teg-border); }
            .teg-table th { text-align:left; padding:12px 14px; background: var(--teg-bg); color: var(--teg-muted); font-weight:700; border-bottom:1px solid var(--teg-border); text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }
            .teg-table td { padding:12px 14px; border-bottom:1px solid var(--teg-border); color: var(--teg-text); background: var(--teg-surface); }
            
            #teg-toast { visibility: hidden; min-width: 200px; background: var(--teg-text); color: var(--teg-surface); text-align: center; border-radius: 8px; padding: 12px 20px; position: fixed; z-index: 99999; left: 50%; transform: translateX(-50%); bottom: 40px; font-size: 14px; font-weight:600; opacity: 0; transition: opacity 0.3s; box-shadow: 0 10px 25px rgba(0,0,0,0.2); }
            #teg-toast.show { visibility: visible; opacity: 1; }
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
            <div class="teg-header"><div class="teg-title"><span class="dashicons dashicons-shield-alt" style="font-size:32px;"></span> Tegatai Security</div><div class="teg-badge">PRO v3.4</div></div>
            <div class="teg-layout">
            <aside class="teg-sidebar">
                <div class="teg-menu-group"><?php echo esc_html__('Overview', 'tegatai-secure'); ?></div>
                <a href="?page=tegatai-secure&tab=dashboard" class="teg-tab <?php echo $tab=='dashboard'?'active':''; ?>"><span class="dashicons dashicons-dashboard"></span> <?php echo esc_html__('Dashboard', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=timeline" class="teg-tab <?php echo $tab=='timeline'?'active':''; ?>"><span class="dashicons dashicons-clock"></span> <?php echo esc_html__('Timeline', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=logs" class="teg-tab <?php echo $tab=='logs'?'active':''; ?>"><span class="dashicons dashicons-list-view"></span> <?php echo esc_html__('Logs & Traffic', 'tegatai-secure'); ?></a>

                <div class="teg-menu-group"><?php echo esc_html__('Protection & Firewall', 'tegatai-secure'); ?></div>
                <a href="?page=tegatai-secure&tab=firewall" class="teg-tab <?php echo $tab=='firewall'?'active':''; ?>"><span class="dashicons dashicons-shield"></span> <?php echo esc_html__('WAF Firewall', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=login" class="teg-tab <?php echo $tab=='login'?'active':''; ?>"><span class="dashicons dashicons-lock"></span> <?php echo esc_html__('Login Protection', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=spam" class="teg-tab <?php echo $tab=='spam'?'active':''; ?>"><span class="dashicons dashicons-email-alt"></span> <?php echo esc_html__('Anti-Spam', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=geoip" class="teg-tab <?php echo $tab=='geoip'?'active':''; ?>"><span class="dashicons dashicons-admin-site-alt3"></span> <?php echo esc_html__('GeoIP Block', 'tegatai-secure'); ?></a>

                <div class="teg-menu-group"><?php echo esc_html__('Server & System', 'tegatai-secure'); ?></div>
                <a href="?page=tegatai-secure&tab=server" class="teg-tab <?php echo $tab=='server'?'active':''; ?>"><span class="dashicons dashicons-networking"></span> <?php echo esc_html__('Server Rules', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=headers" class="teg-tab <?php echo $tab=='headers'?'active':''; ?>"><span class="dashicons dashicons-heading"></span> <?php echo esc_html__('HTTP Headers', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=hardening" class="teg-tab <?php echo $tab=='hardening'?'active':''; ?>"><span class="dashicons dashicons-admin-generic"></span> <?php echo esc_html__('Hardening', 'tegatai-secure'); ?></a>

                <div class="teg-menu-group"><?php echo esc_html__('Scanner & Checks', 'tegatai-secure'); ?></div>
                <a href="?page=tegatai-secure&tab=scanner" class="teg-tab <?php echo $tab=='scanner'?'active':''; ?>"><span class="dashicons dashicons-search"></span> <?php echo esc_html__('Main Scanner', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=malware" class="teg-tab <?php echo $tab=='malware'?'active':''; ?>"><span class="dashicons dashicons-bug"></span> <?php echo esc_html__('Malware Scan', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=core" class="teg-tab <?php echo $tab=='core'?'active':''; ?>"><span class="dashicons dashicons-wordpress"></span> <?php echo esc_html__('WP Core Scan', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=fim" class="teg-tab <?php echo $tab=='fim'?'active':''; ?>"><span class="dashicons dashicons-media-code"></span> <?php echo esc_html__('File Monitor (FIM)', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=dbscan" class="teg-tab <?php echo $tab=='dbscan'?'active':''; ?>"><span class="dashicons dashicons-database"></span> <?php echo esc_html__('DB XSS Scan', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=options" class="teg-tab <?php echo $tab=='options'?'active':''; ?>"><span class="dashicons dashicons-admin-settings"></span> <?php echo esc_html__('Options Scan', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=cron" class="teg-tab <?php echo $tab=='cron'?'active':''; ?>"><span class="dashicons dashicons-update-alt"></span> <?php echo esc_html__('Cron Monitor', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=uploads" class="teg-tab <?php echo $tab=='uploads'?'active':''; ?>"><span class="dashicons dashicons-upload"></span> <?php echo esc_html__('Uploads Scan', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=perms" class="teg-tab <?php echo $tab=='perms'?'active':''; ?>"><span class="dashicons dashicons-admin-network"></span> <?php echo esc_html__('File Permissions', 'tegatai-secure'); ?></a>

                <div class="teg-menu-group"><?php echo esc_html__('Management', 'tegatai-secure'); ?></div>
                <a href="?page=tegatai-secure&tab=bans" class="teg-tab <?php echo $tab=='bans'?'active':''; ?>"><span class="dashicons dashicons-warning"></span> <?php echo esc_html__('IP Prison', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=sessions" class="teg-tab <?php echo $tab=='sessions'?'active':''; ?>"><span class="dashicons dashicons-groups"></span> <?php echo esc_html__('Sessions', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=backups" class="teg-tab <?php echo $tab=='backups'?'active':''; ?>"><span class="dashicons dashicons-backup"></span> <?php echo esc_html__('Backups', 'tegatai-secure'); ?></a>
                <a href="?page=tegatai-secure&tab=extras" class="teg-tab <?php echo $tab=='extras'?'active':''; ?>"><span class="dashicons dashicons-plus-alt"></span> <?php echo esc_html__('Extras & API', 'tegatai-secure'); ?></a>
            </aside>
            <div class="teg-content">
            <?php if ($tab == 'dashboard'): ?>

<style>
/* Scoped dashboard polish */
.teg-dash-grid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px;}
@media (max-width: 1100px){.teg-dash-grid{grid-template-columns:1fr;}}
.teg-dash-card{padding:18px;}
.teg-dash-title{display:flex;align-items:center;gap:10px;margin:0 0 12px 0;font-size:14px;letter-spacing:.2px;}
.teg-dash-title .dashicons{font-size:18px;line-height:18px;width:18px;height:18px;opacity:.9}
.teg-dash-sub{margin:-6px 0 14px 0;color:#6b7280;font-size:12px}
.teg-pill{display:inline-flex;align-items:center;gap:8px;padding:4px 10px;border-radius:999px;font-weight:800;font-size:12px;border:1px solid rgba(0,0,0,.06);background:#fff}
.teg-dot{width:8px;height:8px;border-radius:999px;display:inline-block}
.teg-kv{display:grid;grid-template-columns:1fr 160px;gap:10px;align-items:center}
.teg-kv .k{font-weight:650}
.teg-kv .v{text-align:right}
.teg-kv code{font-size:12px}
.teg-actions{margin-top:12px;display:flex;gap:8px;flex-wrap:wrap}
.teg-actions .button{border-radius:10px}
.teg-mini{font-size:12px;color:#6b7280;margin-top:10px}
.teg-table{border:1px solid rgba(0,0,0,.08);border-radius:12px;overflow:hidden}
.teg-table table{margin:0;border:0}
.teg-table thead th{background:#f9fafb}
.teg-table td,.teg-table th{vertical-align:top}
.teg-muted{color:#6b7280}
</style>

<?php
  $ops = get_option($this->options_slug, []);
  if (!is_array($ops)) { $ops = []; }

  $pill = function($on) {
    $c = $on ? 'var(--teg-success)' : '#9ca3af';
    $t = $on ? __('ON', 'tegatai-secure') : __('OFF', 'tegatai-secure');
    return '<span class="teg-pill" style="color:'.$c.';"><span class="teg-dot" style="background:'.$c.';"></span>'.esc_html($t).'</span>';
  };

  // Best-effort counts (fallback to "-")
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

    <div class="teg-actions">
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=waf')); ?>"><?php echo esc_html__('Open WAF', 'tegatai-secure'); ?></a>
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=login')); ?>"><?php echo esc_html__('Open Login', 'tegatai-secure'); ?></a>
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=scanner')); ?>"><?php echo esc_html__('Open Scanner', 'tegatai-secure'); ?></a>
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=logs')); ?>"><?php echo esc_html__('Open Logs', 'tegatai-secure'); ?></a>
    </div>
    <p class="teg-mini"><?php echo esc_html__('Tip: Keep WAF + Login limit + Upload guard enabled. Use 2FA for all admins.', 'tegatai-secure'); ?></p>
  </div>

  <div class="teg-card teg-dash-card">
    <h3 class="teg-dash-title"><span class="dashicons dashicons-list-view"></span><?php echo esc_html__('Recent security events', 'tegatai-secure'); ?></h3>
    <p class="teg-dash-sub"><?php echo esc_html__('Latest events recorded by Tegatai.', 'tegatai-secure'); ?></p>
    <?php $rows = (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_logs')) ? Tegatai_Logger::get_logs(8) : []; ?>
    <?php if (empty($rows)) : ?>
      <p class="teg-muted" style="margin:0;"><?php echo esc_html__('No log entries yet.', 'tegatai-secure'); ?></p>
    <?php else : ?>
      <div class="teg-table">
        <table class="widefat striped">
          <thead>
            <tr>
              <th style="width:160px;"><?php echo esc_html__('Time', 'tegatai-secure'); ?></th>
              <th style="width:120px;"><?php echo esc_html__('Type', 'tegatai-secure'); ?></th>
              <th style="width:140px;"><?php echo esc_html__('IP', 'tegatai-secure'); ?></th>
              <th><?php echo esc_html__('Message', 'tegatai-secure'); ?></th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($rows as $r): ?>
              <tr>
                <td><code><?php echo esc_html($r['time'] ?? ''); ?></code></td>
                <td><code><?php echo esc_html($r['type'] ?? ''); ?></code></td>
                <td><code><?php echo esc_html($r['ip'] ?? ''); ?></code></td>
                <td style="word-break:break-word;"><?php echo esc_html($r['message'] ?? ''); ?></td>
              </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    <?php endif; ?>
  </div>
</div>

<div class="teg-dash-grid">
  <div class="teg-card teg-dash-card">
    <h3 class="teg-dash-title"><span class="dashicons dashicons-shield-alt"></span><?php echo esc_html__('Attack & block overview', 'tegatai-secure'); ?></h3>
    <p class="teg-dash-sub"><?php echo esc_html__('Quick stats + top IPs (last 24 hours).', 'tegatai-secure'); ?></p>

    <div class="teg-kv" style="margin-bottom:12px;">
      <div class="k"><?php echo esc_html__('Blocked (total)', 'tegatai-secure'); ?>
      <div class="k"><?php echo esc_html__('Blocks (24h)', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html((string)intval($blocks_24h ?? 0)); ?></code></div>

      <div class="k"><?php echo esc_html__('Failed logins (24h)', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html((string)intval($fails_24h ?? 0)); ?></code></div>
    
    </div>
      <div class="v"><code><?php echo esc_html((string)intval($stats2['blocked'] ?? 0)); ?></code></div>

      <div class="k"><?php echo esc_html__('Traffic (total)', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html((string)intval($stats2['total'] ?? 0)); ?></code></div>
    </div>

    <?php
      $rows2 = (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_logs')) ? Tegatai_Logger::get_logs(250) : [];
      
      /* TEGATAI_DASH_24H_METRICS_V1 */
      // --- 24h metrics (best-effort: type names differ across builds) ---
      $cut24 = time() - 86400;
      $blocks_24h = 0;
      $fails_24h  = 0;

      foreach ($rows2 as $rr) {
        $tstr = isset($rr['time']) ? (string)$rr['time'] : '';
        $tt   = $tstr ? strtotime($tstr) : 0;
        if (!$tt || $tt < $cut24) { continue; }

        $typ = isset($rr['type']) ? strtoupper((string)$rr['type']) : '';
        $msg = isset($rr['message']) ? strtolower((string)$rr['message']) : '';

        // Blocks: common types or messages
        if (strpos($typ, 'BLOCK') !== false || strpos($typ, 'WAF') !== false || strpos($msg, 'blocked') !== false) {
          $blocks_24h++;
        }

        // Failed logins: common types or messages
        if (
          strpos($typ, 'LOGIN_FAIL') !== false ||
          (strpos($typ, 'LOGIN') !== false && strpos($typ, 'FAIL') !== false) ||
          strpos($msg, 'failed login') !== false ||
          strpos($msg, 'invalid password') !== false ||
          strpos($msg, 'login attempt') !== false
        ) {
          $fails_24h++;
        }
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
      $top_ips = array_slice($ip_counts, 0, 6, true);
    ?>

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

    <div class="teg-actions">
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=logs')); ?>">
        <?php echo esc_html__('Open logs', 'tegatai-secure'); ?>
      </a>
    </div>
  </div>

  <div class="teg-card teg-dash-card">
    <h3 class="teg-dash-title"><span class="dashicons dashicons-search"></span><?php echo esc_html__('Scanner status', 'tegatai-secure'); ?></h3>
    <p class="teg-dash-sub"><?php echo esc_html__('Quick view of the last scan run.', 'tegatai-secure'); ?></p>
    <?php
      $st = get_option('teg_scan_status', []);
      $running = is_array($st) && !empty($st['running']);
      $phase = is_array($st) && !empty($st['phase']) ? (string)$st['phase'] : '';
      $files_checked = is_array($st) && isset($st['files_checked']) ? intval($st['files_checked']) : 0;
      $bad_count = is_array($st) && !empty($st['bad_files']) && is_array($st['bad_files']) ? count($st['bad_files']) : 0;
      $start_time = is_array($st) && !empty($st['start_time']) ? intval($st['start_time']) : 0;

      $run_pill = $running
        ? '<span class="teg-pill" style="color:var(--teg-success)"><span class="teg-dot" style="background:var(--teg-success)"></span>'.esc_html__('RUNNING', 'tegatai-secure').'</span>'
        : '<span class="teg-pill" style="color:#9ca3af"><span class="teg-dot" style="background:#9ca3af"></span>'.esc_html__('IDLE', 'tegatai-secure').'</span>';

      $find_pill = $bad_count > 0
        ? '<span class="teg-pill" style="color:#b32d2e"><span class="teg-dot" style="background:#b32d2e"></span>'.esc_html($bad_count).' '.esc_html__('finding(s)', 'tegatai-secure').'</span>'
        : '<span class="teg-pill" style="color:var(--teg-success)"><span class="teg-dot" style="background:var(--teg-success)"></span>0 '.esc_html__('findings', 'tegatai-secure').'</span>';
    ?>
    <div class="teg-kv">
      <div class="k"><?php echo esc_html__('Status', 'tegatai-secure'); ?></div>
      <div class="v"><?php echo $run_pill; ?></div>

      <div class="k"><?php echo esc_html__('Phase', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html($phase ?: '-'); ?></code></div>

      <div class="k"><?php echo esc_html__('Files checked', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html((string)$files_checked); ?></code></div>

      <div class="k"><?php echo esc_html__('Findings', 'tegatai-secure'); ?></div>
      <div class="v"><?php echo $find_pill; ?></div>

      <div class="k"><?php echo esc_html__('Started', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo $start_time ? esc_html(date_i18n('Y-m-d H:i', $start_time)) : '-'; ?></code></div>
    </div>

    <div class="teg-actions">
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=scanner')); ?>">
        <?php echo esc_html__('Open scanner', 'tegatai-secure'); ?>
      </a>
    </div>
  </div>
</div>

<div class="teg-dash-grid">
  <div class="teg-card teg-dash-card">
    <h3 class="teg-dash-title"><span class="dashicons dashicons-lock"></span><?php echo esc_html__('Login security', 'tegatai-secure'); ?></h3>
    <p class="teg-dash-sub"><?php echo esc_html__('Sessions, trusted devices and key login hardening signals.', 'tegatai-secure'); ?></p>

    <div class="teg-kv">
      <div class="k"><?php echo esc_html__('2FA', 'tegatai-secure'); ?></div>
      <div class="v"><?php echo $pill(!empty($ops['enable_2fa'])); ?></div>

      <div class="k"><?php echo esc_html__('Trusted Devices', 'tegatai-secure'); ?></div>
      <div class="v"><?php echo $pill(!empty($ops['enable_trusted_devices']) || !empty($ops['trusted_devices'])); ?></div>

      <div class="k"><?php echo esc_html__('Single session', 'tegatai-secure'); ?></div>
      <div class="v"><?php echo $pill(!empty($ops['enable_single_session'])); ?></div>

      <div class="k"><?php echo esc_html__('Active sessions', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html($sess_count === null ? '-' : (string)$sess_count); ?></code></div>

      <div class="k"><?php echo esc_html__('Trusted devices (count)', 'tegatai-secure'); ?></div>
      <div class="v"><code><?php echo esc_html($td_count === null ? '-' : (string)$td_count); ?></code></div>
    </div>

    <div class="teg-actions">
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=login')); ?>">
        <?php echo esc_html__('Open Login', 'tegatai-secure'); ?>
      </a>
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=sessions')); ?>">
        <?php echo esc_html__('Open Sessions', 'tegatai-secure'); ?>
      </a>
      <a class="button button-secondary" href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=twofa')); ?>">
        <?php echo esc_html__('Open 2FA', 'tegatai-secure'); ?>
      </a>
    </div>
  </div>

  <div class="teg-card teg-dash-card">
    <h3 class="teg-dash-title"><span class="dashicons dashicons-info"></span><?php echo esc_html__('Server status', 'tegatai-secure'); ?></h3>
    <p class="teg-dash-sub"><?php echo esc_html__('Environment details useful for troubleshooting.', 'tegatai-secure'); ?></p>
    <ul style="list-style:none;padding:0;margin:0;line-height:2;">
      <li><strong>IP:</strong> <?php echo esc_html($_SERVER['REMOTE_ADDR'] ?? ''); ?></li>
      <li><strong>Server:</strong> <?php echo esc_html(class_exists('Tegatai_Server') ? Tegatai_Server::detect_server() : ''); ?></li>
      <li><strong>Server Software:</strong> <?php echo esc_html($_SERVER['SERVER_SOFTWARE'] ?? ''); ?></li>
      <li><strong>Hostname:</strong> <?php echo esc_html(function_exists('gethostname') ? gethostname() : php_uname('n')); ?></li>
      <li><strong>OS:</strong> <?php echo esc_html(php_uname('s') . ' ' . php_uname('r')); ?></li>
      <li><strong>PHP:</strong> <?php echo esc_html(PHP_VERSION); ?></li>
      <li><strong>WordPress:</strong> <?php echo esc_html(get_bloginfo('version')); ?></li>
      <li><strong>Memory Limit:</strong> <?php echo esc_html(ini_get('memory_limit')); ?></li>
      <li><strong>Max Execution:</strong> <?php echo esc_html(ini_get('max_execution_time')); ?>s</li>
      <li><strong>Upload Max:</strong> <?php echo esc_html(ini_get('upload_max_filesize')); ?></li>
      <li><strong>Post Max:</strong> <?php echo esc_html(ini_get('post_max_size')); ?></li>
      <li><strong>DB Version:</strong> <?php global $wpdb; echo isset($wpdb) ? esc_html($wpdb->db_version()) : ''; ?></li>
      <li><strong>Disk Free (WP Root):</strong> <?php echo (function_exists('disk_free_space') && defined('ABSPATH')) ? esc_html(size_format(@disk_free_space(ABSPATH))) : 'n/a'; ?></li>
    </ul>
  </div>
</div>

<?php elseif ($tab == 'geoip'): ?>
                 <div class="teg-grid">
                    <div class="teg-card">
                        <h3><span class="dashicons dashicons-globe"></span> <?php echo esc_html__('GeoIP Settings', 'tegatai-secure'); ?></h3>
                        <p class="teg-switch-desc" style="margin-bottom:15px;"><?php echo esc_html__('Control who can access your site.', 'tegatai-secure'); ?></p>
                        
                        <div style="background:#e0f2fe; padding:15px; border-radius:6px; border:1px solid #bae6fd; color:#0369a1; margin-bottom:20px;">
                            <strong><?php echo esc_html__('Your current detection:', 'tegatai-secure'); ?></strong><br>
                            IP: <code><?php echo $_SERVER['REMOTE_ADDR']; ?></code><br>
                            <?php echo esc_html__('If this is not your real IP, check your proxy settings.', 'tegatai-secure'); ?>
                        </div>

                        <?php $this->render_toggle('geoip_login_only', esc_html__('Protect login area only', 'tegatai-secure'), esc_html__('If disabled, the entire website will be blocked for the selected countries.', 'tegatai-secure')); ?>
                        <hr style="margin:20px 0; border:0; border-top:1px solid #eee;">

                        <form onsubmit="tegSaveForm(this, event)">
<label class="teg-switch-label"><?php echo esc_html__('GeoIP Mode', 'tegatai-secure'); ?></label>
                            <select name="tegatai_options[geoip_mode]" class="teg-form-input">
                                <option value="off" <?php selected($this->get_opt('geoip_mode'), 'off'); ?>>⚪ <?php echo esc_html__('Off (Disabled)', 'tegatai-secure'); ?></option>
                                <option value="blacklist" <?php selected($this->get_opt('geoip_mode'), 'blacklist'); ?>>🚫 <?php echo esc_html__('Blacklist (Block selected)', 'tegatai-secure'); ?></option>
                                <option value="whitelist" <?php selected($this->get_opt('geoip_mode'), 'whitelist'); ?>>✅ <?php echo esc_html__('Whitelist (Allow selected only)', 'tegatai-secure'); ?></option>
                            </select>
                            
                            <label class="teg-switch-label" style="margin-top:15px;"><?php echo esc_html__('Country Codes (Comma separated)', 'tegatai-secure'); ?></label>
                            <input type="text" name="tegatai_options[geoip_list]" value="<?php echo esc_attr($this->get_opt('geoip_list', '')); ?>" class="teg-form-input" placeholder="DE, AT, CH, FR (2-stellige ISO Codes)">
                            <p class="teg-switch-desc"><?php echo esc_html__('Example: "US, UK, CA" allows only English speaking countries.', 'tegatai-secure'); ?></p>
                            
                            <input type="submit" class="button button-primary" value="<?php echo esc_attr__('Save Settings', 'tegatai-secure'); ?>" style="margin-top:10px;">
                        </form>
                    </div>
                </div>
            
            <?php elseif ($tab == 'bans'): ?>
                <div class="teg-grid">
                    <div class="teg-card" style="grid-column: 1 / -1;">
                        <h3><span class="dashicons dashicons-lock"></span> <?php echo esc_html__('Active IP Bans (Prison)', 'tegatai-secure'); ?></h3>
                        <p class="teg-switch-desc" style="margin-bottom:20px;"><?php echo esc_html__('Here you can see all currently banned IPs (Login Rate, Firewall, Honeypot). You can unban them early.', 'tegatai-secure'); ?></p>
                        
                        <?php
                        // Unban Action Handler
                        if (isset($_POST['teg_action']) && $_POST['teg_action'] == 'unban_ip') {
                            check_admin_referer('teg_ban_nonce');
                            $transient_name = sanitize_text_field($_POST['transient'] ?? '');
                            if ($transient_name) {
                                $real_key = str_replace('_transient_timeout_', '', $transient_name);
                                delete_transient($real_key);
                                // Delete RAM-First Cache File
                                $cache_file = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/' . $real_key . '.txt';
                                
            // Security: strict key validation + ensure path stays inside cache directory
            if (!preg_match('/^[a-zA-Z0-9_\:\-]{1,128}$/', $real_key)) {
                wp_die('Invalid cache key.');
            }
            $cache_dir = wp_upload_dir()['basedir'] . '/tegatai-logs/cache/';
            $real_cache_dir = realpath($cache_dir);
            $real_cache_file = realpath($cache_file);
            if ($real_cache_dir === false || $real_cache_file === false || strpos($real_cache_file, $real_cache_dir) !== 0) {
                wp_die('Unsafe file path.');
            }
@unlink($cache_file);
                                // APCu/WP-Cache
                                if (function_exists('apcu_delete')) @apcu_delete($real_key);
                                if (wp_using_ext_object_cache()) wp_cache_delete($real_key, 'tegatai');
                                
                                echo '<div class=\"notice notice-success is-dismissible\"><p>' . esc_html__('IP successfully unbanned!', 'tegatai-secure') . '</p></div>';
                            }
                        }

                        // Gesperrte IPs auslesen (Direkter DB Zugriff nötig für Transients)
                        global $wpdb;
                        // Wir suchen nach Transients die mit '_transient_teg_' beginnen (unsere Keys)
                        // Timeout keys: _transient_timeout_teg_...
                        $sql = "SELECT option_name, option_value FROM $wpdb->options WHERE option_name LIKE '\_transient\_timeout\_teg\_%'";
                        $timeouts = $wpdb->get_results($sql);
                        
                        if (empty($timeouts)) {
                            echo '<div style="padding:40px;text-align:center;color:#6b7280;background:#f9fafb;border-radius:8px;">✅ ' . esc_html__('No active bans found.', 'tegatai-secure') . '</div>';
                        } else {
                            echo '<table class="teg-table"><thead><tr><th>IP (Hash/Key)</th><th>' . esc_html__('Reason / Type', 'tegatai-secure') . '</th><th>' . esc_html__('Expires in', 'tegatai-secure') . '</th><th>' . esc_html__('Action', 'tegatai-secure') . '</th></tr></thead><tbody>';
                            
                            foreach ($timeouts as $t) {
                                $time_left = intval($t->option_value) - time();
                                if ($time_left < 0) continue; // Sollte WP eigentlich löschen
                                
                                // Der echte Key ohne "timeout"
                                $real_key = str_replace('_transient_timeout_', '', $t->option_name);
                                $val = get_transient($real_key); // Wert holen (z.B. Counter)
                                
                                // Versuch den Typ zu erraten anhand des Namens
                                $type = 'Unbekannt';
                                $display_ip = 'Hash: ' . substr($real_key, -10); // Fallback
                                
                                if (strpos($real_key, 'teg_404_') !== false) { $type = 'Firewall / 404 Ban'; }
                                elseif (strpos($real_key, 'teg_login_lock_') !== false) { $type = 'Login Brute Force'; }
                                elseif (strpos($real_key, 'teg_rl_') !== false) { $type = 'Rate Limit'; }
                                
                                // Zeit formatieren
                                $minutes = floor($time_left / 60);
                                $seconds = $time_left % 60;
                                
                                echo '<tr>';
                                echo '<td><code>' . esc_html($real_key) . '</code></td>';
                                echo '<td><span class="teg-badge" style="color:#fff;background:#ef4444;">' . $type . '</span> <small>(Level: '.$val.')</small></td>';
                                echo '<td>' . $minutes . ' ' . esc_html__('Min', 'tegatai-secure') . ' ' . $seconds . ' ' . esc_html__('Sec', 'tegatai-secure') . '</td>';
                                echo '<td>';
                                echo '<form method="post" style="display:inline;">';
                                echo '<input type="hidden" name="teg_action" value="unban_ip">';
                                echo '<input type="hidden" name="transient" value="' . esc_attr($t->option_name) . '">';
                                echo wp_nonce_field('teg_ban_nonce', '_wpnonce', true, false);
                                echo '<input type="submit" class="button button-small" value="' . esc_attr__('Unban', 'tegatai-secure') . '">';
                                echo '</form>';
            echo '<form method="post" style="margin:0 0 12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            echo wp_nonce_field('teg_mw_quarantine', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_mw_quarantine" value="1">' . esc_html__('Quarantine ALL hits', 'tegatai-secure') . '</button>';
            echo '</form>';

                                echo '</td>';
                                echo '</tr>';
                            }
                            echo '</tbody></table>';
                        }
                        ?>
                    </div>
                </div>

            <?php else: $this->render_full_tabs($tab); endif; ?>
        </div></div></div>
        <?php
    }

    private function render_full_tabs($tab) {
        // (Gleicher Code wie vorher, nur gekürzt für das Skript, da unverändert)
        if ($tab == 'firewall') { echo '
<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('WAF Settings', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_waf', esc_html__('Enable WAF', 'tegatai-secure'), esc_html__('Activates the Web Application Firewall to block malicious requests.', 'tegatai-secure')); $this->render_toggle('block_fake_bots', esc_html__('Block Bad Bots', 'tegatai-secure'), esc_html__('Blocks known malicious bots, scrapers, and automated attack tools.', 'tegatai-secure')); $this->render_toggle('enable_rate_limit', esc_html__('Rate Limit', 'tegatai-secure'), esc_html__('Prevents brute-force attacks by limiting requests per minute.', 'tegatai-secure')); $this->render_toggle('enable_404_block', esc_html__('404 Trap', 'tegatai-secure'), esc_html__('Bans IPs that generate too many 404 Not Found errors.', 'tegatai-secure')); $this->render_toggle('block_ai_bots', esc_html__('Block AI Bots', 'tegatai-secure'), esc_html__('Stops OpenAI, ChatGPT, and other AI scrapers from crawling your content.', 'tegatai-secure')); $this->render_toggle('block_seo_bots', esc_html__('Block SEO Bots', 'tegatai-secure'), esc_html__('Blocks aggressive SEO crawlers like Ahrefs or Semrush.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('WAF Whitelist', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Allowed URLs', 'tegatai-secure') . '</label><textarea name="tegatai_options[waf_whitelist_urls]" class="teg-form-input">'.esc_textarea($this->get_opt('waf_whitelist_urls', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Custom Rules (Regex)', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Custom Regex Filters', 'tegatai-secure') . '</label><p class="teg-switch-desc">' . wp_kses_post(__('One regex per line (e.g., <code>/bad-bot/i</code>).', 'tegatai-secure')) . '</p><textarea name="tegatai_options[custom_waf_blocklist]" class="teg-form-input">'.esc_textarea($this->get_opt('custom_waf_blocklist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('IP Lists', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Whitelist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[whitelist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('whitelist_ips', '')).'</textarea><label class="teg-switch-label">' . esc_html__('Blacklist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[blacklist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('blacklist_ips', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'server') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Server Rules', 'tegatai-secure') . '</h3>'; $this->render_toggle('server_disable_indexing', esc_html__('Disable Directory Browsing', 'tegatai-secure'), esc_html__('Prevents attackers from seeing lists of your files.', 'tegatai-secure')); $this->render_toggle('server_protect_files', esc_html__('Protect Sensitive Files', 'tegatai-secure'), esc_html__('Blocks access to .env, .sql, .bak, .log, and .git files.', 'tegatai-secure')); $this->render_toggle('server_hide_system_files', esc_html__('Block System Files', 'tegatai-secure'), esc_html__('Hides readme.html, license.txt, and wp-config.php from the web.', 'tegatai-secure')); $this->render_toggle('server_block_dotfiles', esc_html__('Block Dotfiles', 'tegatai-secure'), esc_html__('Denies access to hidden files (e.g., .htaccess).', 'tegatai-secure')); $this->render_toggle('server_block_xmlrpc', esc_html__('Block XML-RPC', 'tegatai-secure'), esc_html__('Disables xmlrpc.php to prevent DDoS and brute-force attacks.', 'tegatai-secure')); $this->render_toggle('server_disable_php_uploads', esc_html__('Disable PHP in Uploads', 'tegatai-secure'), esc_html__('Prevents execution of malicious backdoors in your media folder.', 'tegatai-secure')); $this->render_toggle('server_filter_bad_bots', esc_html__('Ultimate Bad Bot Filter', 'tegatai-secure'), esc_html__('Strict Nginx-level blocking for hacking tools.', 'tegatai-secure')); $this->render_toggle('server_hotlink_protection', esc_html__('Hotlink Protection', 'tegatai-secure'), esc_html__('Prevents other sites from embedding your images and stealing bandwidth.', 'tegatai-secure')); echo '<div style="background:#f9fafb; padding:15px; border-radius:8px; margin-top:20px; border:1px solid #e5e7eb;"><form method="post" action="'.admin_url('admin-post.php').'"><input type="hidden" name="action" value="tegatai_write_rules">'.wp_nonce_field('teg_write_nonce','_wpnonce',true,false).'<input type="submit" class="button button-primary" value="' . esc_attr__('Write rules to server config', 'tegatai-secure') . '" ></form></div></div><div class="teg-card"><h3>' . esc_html__('Custom Protection', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Protected Directories', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[server_protected_dirs]" value="'.esc_attr($this->get_opt('server_protected_dirs', '')).'" class="teg-form-input">
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Block Specific Files', 'tegatai-secure') . '</label>
<p class="teg-switch-desc">' . wp_kses_post(__('Paths from root (e.g., <code>/secret.zip</code>). One file per line.', 'tegatai-secure')) . '</p>
<textarea name="tegatai_options[server_custom_files_list]" class="teg-form-input" style="height:80px;" placeholder="/geheim.zip&#10;/custom/info.php">'.esc_textarea($this->get_opt('server_custom_files_list', '')).'</textarea>
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Hotlink Whitelist', 'tegatai-secure') . '</label><textarea name="tegatai_options[server_hotlink_whitelist]" class="teg-form-input">'.esc_textarea($this->get_opt('server_hotlink_whitelist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        // ... Logik für Login, Spam, Hardening, Headers, Backups, Scanner, Sessions, Extras, Logs (siehe v3.3)
        elseif ($tab == 'login') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Login Protection', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_login_limit', esc_html__('Login Limit', 'tegatai-secure'), esc_html__('Locks out IPs after multiple failed login attempts.', 'tegatai-secure')); $this->render_toggle('disable_app_passwords', esc_html__('Disable App Passwords', 'tegatai-secure'), esc_html__('Turns off the WordPress application passwords feature.', 'tegatai-secure'));
        $this->render_toggle('enable_trusted_devices', esc_html__('Trusted Devices', 'tegatai-secure'), esc_html__('Warns via email upon logins from unknown devices.', 'tegatai-secure')); $this->render_toggle('block_default_login', esc_html__('Block wp-login.php', 'tegatai-secure'), esc_html__('Disables the default login route (requires Custom Slug).', 'tegatai-secure')); $this->render_toggle('block_wp_admin_hide', esc_html__('Hide /wp-admin/', 'tegatai-secure'), esc_html__('Redirects unauthenticated users away from the admin area.', 'tegatai-secure')); $this->render_toggle('enable_idle_logout', esc_html__('Idle Logout (60m)', 'tegatai-secure'), esc_html__('Automatically logs out inactive administrators after 60 minutes.', 'tegatai-secure')); $this->render_toggle('enable_magic_links', esc_html__('Enable Magic Links', 'tegatai-secure'), esc_html__('Allows passwordless login via a secure email link.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('Custom Login Slug', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><input type="text" name="tegatai_options[custom_login_slug]" value="'.esc_attr($this->get_opt('custom_login_slug', '')).'" class="teg-form-input" placeholder="mein-login"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'spam') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Spam & Bots', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_honeypot', esc_html__('Enable Honeypot', 'tegatai-secure'), esc_html__('Adds an invisible field to catch automated spam bots.', 'tegatai-secure')); $this->render_toggle('enable_bot_timer', esc_html__('Minimum Fill Time', 'tegatai-secure'), esc_html__('Blocks forms submitted too quickly (typical bot behavior).', 'tegatai-secure')); $this->render_toggle('spam_check_referrer', esc_html__('Referrer Check', 'tegatai-secure'), esc_html__('Ensures form submissions come from your own site.', 'tegatai-secure')); $this->render_toggle('spam_block_trashmail', esc_html__('Block Trash Mails', 'tegatai-secure'), esc_html__('Rejects disposable email addresses during registration.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Max. Links', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[spam_max_links]" value="'.esc_attr($this->get_opt('spam_max_links')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Cloudflare Turnstile', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_turnstile', esc_html__('Enable Turnstile CAPTCHA', 'tegatai-secure'), esc_html__('Privacy-friendly Cloudflare CAPTCHA for login and comments.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Site Key', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[turnstile_site_key]" value="'.esc_attr($this->get_opt('turnstile_site_key')).'" class="teg-form-input" placeholder="0x4A..."><label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Secret Key', 'tegatai-secure') . '</label><input type="password" name="tegatai_options[turnstile_secret_key]" value="'.esc_attr($this->get_opt('turnstile_secret_key')).'" class="teg-form-input" placeholder="0x4A..."><input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'hardening') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('System', 'tegatai-secure') . '</h3>'; $this->render_toggle('hide_wp_version', esc_html__('Hide WP Version', 'tegatai-secure'), esc_html__('Removes the WordPress version number from your source code.', 'tegatai-secure')); $this->render_toggle('disable_xmlrpc', esc_html__('Disable XML-RPC (WP Core)', 'tegatai-secure'), esc_html__('Turns off the XML-RPC API internally.', 'tegatai-secure')); $this->render_toggle('disable_file_editor', esc_html__('Disable File Editor', 'tegatai-secure'), esc_html__('Prevents editing plugins and themes via the WP dashboard.', 'tegatai-secure')); $this->render_toggle('block_user_enum', esc_html__('Block User Enumeration', 'tegatai-secure'), esc_html__('Stops attackers from discovering your usernames.', 'tegatai-secure'));
        echo '<hr style="margin:20px 0; border:0; border-top:1px solid #eee;"><h3>' . esc_html__('Enterprise Protection', 'tegatai-secure') . '</h3>';
        $this->render_toggle('enable_admin_honeypot', esc_html__('Admin Honeypot', 'tegatai-secure'), esc_html__('Permanently bans anyone trying to log in as admin.', 'tegatai-secure'));
        $this->render_toggle('enable_role_guard', esc_html__('Privilege Escalation Guard', 'tegatai-secure'), esc_html__('Prevents unauthorized users from upgrading to Administrator.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('Notifications', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_email_alerts', esc_html__('Enable Email Alerts', 'tegatai-secure'), esc_html__('Receive notifications for critical security events.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">
        <label class="teg-switch-label">' . esc_html__('Recipient Email', 'tegatai-secure') . '</label>
        <input type="email" name="tegatai_options[alert_email]" value="'.esc_attr($this->get_opt('alert_email', get_option('admin_email'))).'" class="teg-form-input">
        <label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Discord / Slack Webhook URL', 'tegatai-secure') . '</label>
        <input type="url" name="tegatai_options[alert_webhook_url]" value="'.esc_attr($this->get_opt('alert_webhook_url', '')).'" class="teg-form-input" placeholder="https://discord.com/api/webhooks/...">
        <input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >
    </form></div><div class="teg-card"><h3>' . esc_html__('2FA', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_2fa', esc_html__('Enable 2FA', 'tegatai-secure'), esc_html__('Enforces Two-Factor Authentication for administrators.', 'tegatai-secure'));
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Preferred 2FA Method', 'tegatai-secure') . '</label>';
        echo '<select name="tegatai_options[twofa_mode]" class="teg-form-input">';
        echo '<option value="email" '.selected($this->get_opt('twofa_mode'), 'email', false).'>' . esc_html__('Email Code Only', 'tegatai-secure') . '</option>';
        echo '<option value="app" '.selected($this->get_opt('twofa_mode'), 'app', false).'>' . esc_html__('Authenticator App Only', 'tegatai-secure') . '</option>';
        echo '<option value="both" '.selected($this->get_opt('twofa_mode', 'both'), 'both', false).'>' . esc_html__('Both (App + Email Fallback)', 'tegatai-secure') . '</option>';
        echo '</select>';
        echo '<input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '</div></div>'; }
        elseif ($tab == 'headers') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('HTTP Security Headers', 'tegatai-secure') . '</h3>'; $this->render_toggle('header_xfo', esc_html__('X-Frame-Options', 'tegatai-secure'), esc_html__('Prevents your site from being framed (Clickjacking protection).', 'tegatai-secure')); $this->render_toggle('header_nosniff', esc_html__('X-Content-Type-Options', 'tegatai-secure'), esc_html__('Stops browsers from MIME-sniffing.', 'tegatai-secure')); $this->render_toggle('header_xss', esc_html__('X-XSS-Protection', 'tegatai-secure'), esc_html__('Enables legacy browser XSS filtering.', 'tegatai-secure')); $this->render_toggle('header_hsts', esc_html__('HSTS (SSL)', 'tegatai-secure'), esc_html__('Enforces strict HTTPS connections.', 'tegatai-secure')); $this->render_toggle('header_ref', esc_html__('Referrer Policy', 'tegatai-secure'), esc_html__('Controls how much referrer information is passed to external sites.', 'tegatai-secure')); $this->render_toggle('header_permissions', esc_html__('Permissions-Policy', 'tegatai-secure'), esc_html__('Restricts access to browser features (camera, microphone).', 'tegatai-secure')); $this->render_toggle('header_csp', esc_html__('Content Security Policy', 'tegatai-secure'), esc_html__('Mitigates XSS by controlling resource loading sources.', 'tegatai-secure')); echo '</div></div>'; }
        elseif ($tab == 'backups') { 
        echo '<div class="teg-grid">';
        
        // --- CARD 1: Backup Konfiguration ---
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Backup Configuration', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('enable_auto_backup', esc_html__('Auto backup', 'tegatai-secure'), esc_html__('Automatically creates backups based on your configured frequency.', 'tegatai-secure')); 
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:20px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Frequency', 'tegatai-secure') . '</label>';
        echo '<select name="tegatai_options[backup_frequency]" class="teg-form-input">';
        echo '<option value="daily" ' . selected($this->get_opt('backup_frequency'), 'daily', false) . '>' . esc_html__('Daily', 'tegatai-secure') . '</option>';
        echo '<option value="weekly" ' . selected($this->get_opt('backup_frequency'), 'weekly', false) . '>' . esc_html__('Weekly', 'tegatai-secure') . '</option>';
        echo '</select>';
        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '</div>';
        
        // --- CARD 2: Lokale Backups ---
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Local Backups', 'tegatai-secure') . '</h3>';
        echo '<form method="post" action="' . admin_url('admin-post.php') . '">';
        echo '<input type="hidden" name="action" value="tegatai_create_backup">';
        echo wp_nonce_field('teg_backup_nonce', '_wpnonce', true, false);
        echo '<input type="submit" class="button button-secondary" style="width:100%;" value="' . esc_attr__('Create Backup Now', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '<hr style="margin:20px 0; border:0; border-top:1px solid #eee;">';
        echo '<h4>' . esc_html__('Available Backups', 'tegatai-secure') . '</h4>';
        
        // TABELLEN FIX: table-layout fixed, definierte Breiten und word-break
        echo '<table class="teg-table" style="table-layout: fixed; width: 100%;">';
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
                
                // Dateiname hart umbrechen lassen, damit das Layout nicht explodiert
                echo '<td style="word-break: break-all; overflow-wrap: break-word;"><strong>' . esc_html($b['name']) . '</strong></td>';
                
                // Größe & Datum festnageln (kein ungewollter Umbruch)
                echo '<td style="white-space: nowrap;">' . esc_html($b['size']) . '</td>';
                echo '<td style="white-space: nowrap;">' . esc_html($b['date']) . '</td>';
                
                // Buttons nebeneinander zwingen
                echo '<td style="text-align:right; white-space: nowrap;">';
                
                echo '<form method="post" action="' . admin_url('admin-post.php') . '" style="display:inline; margin-right: 4px;">';
                echo '<input type="hidden" name="action" value="tegatai_download_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce('teg_backup_nonce') . '">';
                echo '<input type="submit" class="button button-small" value="' . esc_attr__('Download', 'tegatai-secure') . '" >';
                echo '</form>';
                
                echo '<form method="post" action="' . admin_url('admin-post.php') . '" style="display:inline;">';
                echo '<input type="hidden" name="action" value="tegatai_delete_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . wp_create_nonce('teg_backup_nonce') . '">';
                echo '<input type="submit" class="button button-small" value="X" style="color:red;">';
                echo '</form>';
                
                echo '</td>';
                echo '</tr>';
            } 
        }
        echo '</tbody>';
        echo '</table>';
        echo '</div>'; // Ende Card 2
        
        // --- CARD 3: FTP Panel ---
        echo '<div class="teg-card" style="grid-column: 1 / -1; background: #fafafa; border: 1px solid #e5e7eb;">';
        echo '<h3 style="border-bottom:1px solid #e5e7eb; padding-bottom:10px;"><span class="dashicons dashicons-cloud-upload"></span> ' . esc_html__('Remote FTP Setup (Encrypted)', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="margin-bottom:15px;">Sende deine Backups automatisch auf einen externen FTP-Server. Alle Zugangsdaten werden mit <strong>AES-256-CBC</strong> in deiner Datenbank verschlüsselt abgelegt.</p>';
        
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
        echo '<div class="teg-stat-row" style="grid-template-columns: 1fr 1fr; margin-bottom:10px; gap: 20px;">';
        echo '<div><label class="teg-switch-label">' . esc_html__('FTP Server (Host / IP)', 'tegatai-secure') . '</label><input type="password" name="ftp_host" value="' . esc_attr($host) . '" class="teg-form-input" placeholder="ftp.deinserver.de"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('FTP Port', 'tegatai-secure') . '</label><input type="number" name="ftp_port" value="' . esc_attr($port) . '" class="teg-form-input"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('Username', 'tegatai-secure') . '</label><input type="password" name="ftp_user" value="' . esc_attr($user) . '" class="teg-form-input"></div>';
        echo '<div><label class="teg-switch-label">' . esc_html__('Password', 'tegatai-secure') . '</label><input type="password" name="ftp_pass" value="' . esc_attr($pass) . '" class="teg-form-input"></div>';
        echo '</div>';
        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save Encrypted', 'tegatai-secure') . '" >';
        if (isset($_GET['updated']) && $_GET['updated'] == '1') {
            echo '<span style="color:#10b981; margin-left:15px; font-weight:bold;">' . esc_html__('Data saved securely!', 'tegatai-secure') . '</span>';
        }
        echo '</form>';
        echo '</div>'; // Ende Card 3
        
        echo '</div>'; // Ende teg-grid
    }
        elseif ($tab == 'scanner') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Malware & Integrity Scanner', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('enable_auto_quarantine', esc_html__('Auto-Quarantine (IPS)', 'tegatai-secure'), esc_html__('Automatically moves detected malware to a safe location.', 'tegatai-secure')); 
        $status = get_option('teg_scan_status'); $is_running = isset($status['running']) && $status['running']; if ($is_running) { echo '<div style="padding:20px; background:#e0f2fe; border:1px solid #bae6fd; color:#0369a1; border-radius:6px; margin-bottom:20px;">' . esc_html__('Scan running...', 'tegatai-secure') . '</div>'; echo '<script>setTimeout(function(){ window.location.href="'.admin_url('admin-post.php?action=tegatai_scan_process').'"; }, 1500);</script>'; } else { echo '<form method="post" action="'.admin_url('admin-post.php').'"><input type="hidden" name="action" value="tegatai_scan_start">'.wp_nonce_field('teg_scan_nonce', '_wpnonce', true, false).'<input type="submit" class="button button-primary" value="' . esc_attr__('Start New Scan', 'tegatai-secure') . '"  style="padding:10px 20px; font-size:16px;"></form>';
        echo '<form method="post" action="'.admin_url('admin-post.php').'" style="display:inline-block; margin-left:10px;"><input type="hidden" name="action" value="tegatai_scan_snapshot">'.wp_nonce_field('teg_scan_nonce', '_wpnonce', true, false).'<input type="submit" class="button button-secondary" value="📸 ' . esc_attr__('Create File Snapshot', 'tegatai-secure') . '"  style="padding:10px 20px; font-size:16px;" onclick="return confirm(\'' . esc_attr__('Save current state as a safe baseline?', 'tegatai-secure') . '\');"></form>';
    } if (isset($status['last_scan'])) { echo '<hr style="margin:20px 0; border:0; border-top:1px solid #eee;">'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:10px;"><strong>' . esc_html__('Last Result:', 'tegatai-secure') . '</strong> <span>' . $status['last_scan'] . '</span></div>'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:20px;"><strong>' . esc_html__('Files Checked:', 'tegatai-secure') . '</strong> <span>' . intval($status['files_checked']) . '</span></div>'; if (!empty($status['bad_files'])) { echo '<table class="teg-table"><thead><tr><th>Datei</th><th>' . esc_html__('Issue', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach ($status['bad_files'] as $bad) echo '<tr><td style="color:var(--teg-danger);">' . esc_html($bad['file']) . '</td><td>' . esc_html($bad['issue']) . '</td></tr>'; echo '</tbody></table>'; } else { echo '<div style="padding:15px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center;">✅ Sauber.</div>'; } } echo '</div><div class="teg-card"><h3>' . esc_html__('Scanner Configuration', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Exclude from Scan (Folders)', 'tegatai-secure') . '</label><textarea name="tegatai_options[scanner_exclusions]" class="teg-form-input" placeholder="/pfad/zum/cache/">'.esc_textarea($this->get_opt('scanner_exclusions', '/kontentsu/appurodo/avyspp_cache')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'sessions') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Session Security', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_ip_guard', esc_html__('IP Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users IP address changes.', 'tegatai-secure')); $this->render_toggle('enable_browser_guard', esc_html__('Browser Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users browser changes.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:20px;"><label class="teg-switch-label">' . esc_html__('Max Session Duration (Min)', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[session_max_lifetime]" value="'.esc_attr($this->get_opt('session_max_lifetime')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card" style="grid-column: 1 / -1;"><h3>' . esc_html__('Active Sessions', 'tegatai-secure') . '</h3><table class="teg-table"><thead><tr><th>' . esc_html__('User', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Browser', 'tegatai-secure') . '</th><th>' . esc_html__('Action', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_SessionManager::get_all_sessions() as $s): echo "<tr><td>".esc_html($s['username'])."</td><td><code>".esc_html($s['ip'])."</code></td><td><span style='font-size:11px; color:#666;'>".esc_html(substr($s['ua'],0,40))."...</span></td><td><form method='post' action='".admin_url('admin-post.php')."'><input type='hidden' name='action' value='tegatai_kill_session'><input type='hidden' name='user_id' value='{$s['user_id']}'><input type='hidden' name='verifier' value='".esc_attr($s['verifier'])."'><input type='hidden' name='_wpnonce' value='".wp_create_nonce('teg_session_nonce')."'><input type='submit' class='button button-small' value='" . esc_attr__('Kill', 'tegatai-secure') . "'></form></td></tr>"; endforeach; echo '</tbody></table></div></div>'; }
        elseif ($tab == 'extras') { 
        echo '<div class="teg-grid">';
        
        // --- CARD 1: Extras & API ---
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Extras & API', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('disable_rest_api', esc_html__('Restrict REST API', 'tegatai-secure'), esc_html__('Requires authentication for most REST API endpoints.', 'tegatai-secure')); 
        $this->render_toggle('enable_rightclick_disable', esc_html__('Disable Right-Click', 'tegatai-secure'), esc_html__('Prevents basic right-clicking on your website content.', 'tegatai-secure')); 
        $this->render_toggle('enable_copy_protection', esc_html__('Enable Copy Protection', 'tegatai-secure'), esc_html__('Stops users from highlighting and copying text.', 'tegatai-secure')); 
        echo '</div>';
        
        // --- CARD 2: Temporäre Support-Zugänge ---
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Temporary Admin Accounts', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="margin-bottom:15px;">Erstelle einen zeitlich begrenzten Admin-Account. Der Nutzer erhält einen sicheren Login-Link per E-Mail. Nach Ablauf der Zeit löscht sich der Account selbstständig restlos.</p>';
        
        if (isset($_GET['msg']) && $_GET['msg'] == 'temp_created') {
            echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:4px; margin-bottom:15px; border:1px solid #bbf7d0; font-weight:600;">' . esc_html__('Temporary access generated and email sent!', 'tegatai-secure') . '</div>';
        }
        
        echo '<form method="post" action="' . admin_url('admin-post.php') . '">';
        echo wp_nonce_field('teg_temp_admin_nonce', '_wpnonce', true, false);
        echo '<input type="hidden" name="action" value="tegatai_create_temp_admin">';
        
        echo '<label class="teg-switch-label">' . esc_html__('Recipient Email', 'tegatai-secure') . '</label>';
        echo '<input type="email" name="temp_email" class="teg-form-input" placeholder="support@beispiel.de" required>';
        
        echo '<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Validity (in hours)', 'tegatai-secure') . '</label>';
        echo '<input type="number" name="temp_hours" class="teg-form-input" value="24" min="1" max="168" required>';
        
        echo '<input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Generate & Send Access', 'tegatai-secure') . '" >';
        echo '</form>';
        echo '</div>';
        
        echo '</div>'; 
    }
        elseif ($tab == 'logs') { echo '<div class="teg-card"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;"><h3>' . esc_html__('Live Traffic Log', 'tegatai-secure') . '</h3><form method="post"><input type="hidden" name="teg_action" value="clear_logs">'.wp_nonce_field('teg_act_nonce','_wpnonce',true,false).'<input type="submit" class="button button-secondary" value="' . esc_attr__('Clear Logs', 'tegatai-secure') . '"  onclick="return confirm(\'' . esc_attr__('Are you sure?', 'tegatai-secure') . '\');"></form></div><div style="max-height:600px; overflow-y:auto; border:1px solid var(--teg-border); border-radius:6px;"><table class="teg-table"><thead><tr><th>' . esc_html__('Time', 'tegatai-secure') . '</th><th>' . esc_html__('Type', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Message', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_Logger::get_logs(200) as $l): $c = in_array($l['type'], ['WAF','FLOOD','BAN-404','AUTH-BAN','SPAM','GEO-BLK'])?'var(--teg-danger)':'var(--teg-text)'; echo "<tr><td>".esc_html($l['time'])."</td><td style='font-weight:bold; color:$c;'>".esc_html($l['type'])."</td><td><code>".esc_html($l['ip'])."</code></td><td>".esc_html($l['message'])."</td></tr>"; endforeach; echo '</tbody></table></div></div>'; }
    
        elseif ($tab == 'fim') {
            // File Integrity Monitor (auto-detected dirs)
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
            echo '<div class="teg-card">';
            echo '<h3>' . esc_html__('File Integrity Monitor (FIM)', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Tracks file changes in Plugins, MU-Plugins and Themes (auto-detected).', 'tegatai-secure') . '</p>';

            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            echo wp_nonce_field('teg_fim_build', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_fim_build" value="1">' . esc_html__('Create baseline', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            echo wp_nonce_field('teg_fim_check', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_fim_check" value="1">' . esc_html__('Check now', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<p class="teg-muted" style="margin-top:10px;">' . esc_html(sprintf(__('Last run: %s', 'tegatai-secure'), $lt)) . '</p>';

            if (is_array($res) && !empty($res['ok'])) {
                $c_changed = is_array($res['changed'] ?? null) ? count($res['changed']) : 0;
                $c_new     = is_array($res['new'] ?? null) ? count($res['new']) : 0;
                $c_del     = is_array($res['deleted'] ?? null) ? count($res['deleted']) : 0;

                echo '<h4 style="margin-top:14px;">' . esc_html__('Results', 'tegatai-secure') . '</h4>';
                echo '<ul style="margin:10px 0 0 18px;">';
                echo '<li><strong>' . esc_html__('Changed', 'tegatai-secure') . ':</strong> ' . esc_html((string)$c_changed) . '</li>';
                echo '<li><strong>' . esc_html__('New', 'tegatai-secure') . ':</strong> ' . esc_html((string)$c_new) . '</li>';
                echo '<li><strong>' . esc_html__('Deleted', 'tegatai-secure') . ':</strong> ' . esc_html((string)$c_del) . '</li>';
                echo '</ul>';

                $show = function($label, $arr) {
                    if (empty($arr) || !is_array($arr)) return;
                    echo '<h4 style="margin-top:14px;">' . esc_html($label) . '</h4>';
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr><th>' . esc_html__('File', 'tegatai-secure') . '</th></tr></thead><tbody>';
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

                echo '<p class="teg-muted" style="margin-top:10px;">' . esc_html__('Tip: If you just updated plugins/themes, create a new baseline.', 'tegatai-secure') . '</p>';
            } elseif (is_array($res) && !empty($res['error'])) {
                echo '<div class="notice notice-warning"><p>' . esc_html__('No baseline exists yet. Click “Create baseline” first.', 'tegatai-secure') . '</p></div>';
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
            echo '<div class="teg-card">';
            echo '<h3>' . esc_html__('Stored-XSS Database Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Read-only scan of common WP tables for suspicious stored HTML/JS patterns. Prefix is auto-detected.', 'tegatai-secure') . '</p>';

            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            echo wp_nonce_field('teg_dbscan_run', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_dbscan_run" value="1">' . esc_html__('Run scan', 'tegatai-secure') . '</button>';
            echo '</form>';

            if (is_array($result)) {
                $hits = $result['hits'] ?? [];
                echo '<p><strong>' . esc_html__('DB prefix', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)($result['prefix'] ?? '')) . '</code>';
                echo ' &nbsp;|&nbsp; <strong>' . esc_html__('Rows checked', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)($result['rows_checked'] ?? 0)) . '</code>';
                echo ' &nbsp;|&nbsp; <strong>' . esc_html__('Hits', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($hits)) . '</code></p>';

                if (empty($hits)) {
                    echo '<div class="notice notice-success"><p>' . esc_html__('No suspicious patterns found in the scanned rows.', 'tegatai-secure') . '</p></div>';
                } else {
                    echo '<div class="notice notice-warning"><p>' . esc_html__('Suspicious patterns detected. Review carefully (false positives are possible).', 'tegatai-secure') . '</p></div>';
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:260px;">' . esc_html__('Table', 'tegatai-secure') . '</th>';
                    echo '<th style="width:120px;">' . esc_html__('ID', 'tegatai-secure') . '</th>';
                    echo '<th style="width:160px;">' . esc_html__('Field', 'tegatai-secure') . '</th>';
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
                        echo '<td style="word-break:break-word;">' . esc_html((string)($h['snippet'] ?? '')) . '</td>';
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
                echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html(sprintf(__('Quarantine done: %d ok, %d failed (max 50 per click).', 'tegatai-secure'), $count_ok, $count_fail)) . '</p></div>';
            }
if (isset($_POST['teg_mw_reset']) && check_admin_referer('teg_mw_reset')) {
                if (class_exists('Tegatai_Malware_Scanner')) { Tegatai_Malware_Scanner::reset(); }
                echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Malware scan state reset.', 'tegatai-secure') . '</p></div>';
            }

            if (isset($_POST['teg_mw_run']) && check_admin_referer('teg_mw_run')) {
                if (class_exists('Tegatai_Malware_Scanner')) {
                    $result = Tegatai_Malware_Scanner::run(['limit' => $limit, 'reset' => !empty($_POST['teg_mw_fresh'])]);
                }
            } else {
                $result = get_option('teg_mw_progress_v1', null);
            }

            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Malware / Backdoor Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Signature-based scan for common malware/backdoor patterns in Plugins, MU-Plugins and Themes (auto-detected).', 'tegatai-secure') . '</p>';

            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;align-items:center;">';
            echo wp_nonce_field('teg_mw_run', '_wpnonce', true, false);
            echo '<input type="number" name="teg_mw_limit" value="' . esc_attr((string)$limit) . '" min="200" max="3000" style="width:120px" />';
            echo '<label style="display:inline-flex;align-items:center;gap:6px;"><input type="checkbox" name="teg_mw_fresh" value="1" /> ' . esc_html__('Fresh scan', 'tegatai-secure') . '</label>';
            echo '<button class="button button-primary" name="teg_mw_run" value="1">' . esc_html__('Run / Continue', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post" style="margin:0 0 12px 0;">';
            echo wp_nonce_field('teg_mw_reset', '_wpnonce', true, false);
            echo '<button class="button button-secondary" name="teg_mw_reset" value="1">' . esc_html__('Reset state', 'tegatai-secure') . '</button>';
            echo '</form>';

            if (is_array($result)) {
                $hits = isset($result['hits']) && is_array($result['hits']) ? $result['hits'] : [];
                $checked = isset($result['checked']) ? intval($result['checked']) : 0;
                $total = isset($result['total_files']) ? intval($result['total_files']) : 0;
                $done = !empty($result['done']);

                echo '<p><strong>' . esc_html__('Progress', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)$checked) . '</code> / <code>' . esc_html((string)$total) . '</code>';
                if ($done) { echo ' <span style="margin-left:10px;color:var(--teg-success);font-weight:800;">' . esc_html__('DONE', 'tegatai-secure') . '</span>'; }
                echo '</p>';

                $roots = isset($result['roots']) && is_array($result['roots']) ? $result['roots'] : [];
                if (!empty($roots)) {
                    echo '<p class="teg-muted" style="margin-top:-6px;">';
                    foreach ($roots as $k => $v) {
                        echo '<span style="display:inline-block;margin-right:10px;"><strong>' . esc_html((string)$k) . ':</strong> <code>' . esc_html((string)$v) . '</code></span>';
                    }
                    echo '</p>';
                }

                $cnt = count($hits);
                if ($cnt === 0 && $done) {
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('No suspicious patterns found.', 'tegatai-secure') . '</p></div>';
                } elseif ($cnt > 0) {
                    echo '<div class="notice notice-warning is-dismissible"><p>' . esc_html__('Suspicious patterns detected. Review carefully (false positives possible).', 'tegatai-secure') . '</p></div>';
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:70px;">' . esc_html__('Sev', 'tegatai-secure') . '</th>';
                    echo '<th style="width:130px;">' . esc_html__('Rule', 'tegatai-secure') . '</th>';
                    echo '<th style="width:420px;">' . esc_html__('File', 'tegatai-secure') . '</th>';
                    echo '<th>' . esc_html__('Snippet', 'tegatai-secure') . '</th>';
                    echo '</tr></thead><tbody>';

                    $max = 250;
                    for ($i = 0; $i < min($max, $cnt); $i++) {
                        $h = $hits[$i];
                        $sev = (int)($h['sev'] ?? 0);
                        $sev_color = ($sev >= 5) ? '#b32d2e' : (($sev >= 4) ? '#d97706' : '#6b7280');

                        echo '<tr>';
                        echo '<td><strong style="color:' . esc_attr($sev_color) . ';">' . esc_html((string)$sev) . '</strong></td>';
                        echo '<td><code>' . esc_html((string)($h['rule'] ?? '')) . '</code></td>';
                        echo '<td><code>' . esc_html((string)($h['file'] ?? '')) . '</code></td>';
                        echo '<td style="word-break:break-word;"><code>' . esc_html((string)($h['snippet'] ?? '')) . '</code></td>';
                        echo '</tr>';
                    }

                    echo '</tbody></table></div>';
                } else {
                    echo '<p class="teg-muted">' . esc_html__('Run the scan to see results.', 'tegatai-secure') . '</p>';
                }
            } else {
                echo '<p class="teg-muted">' . esc_html__('No scan data yet. Click “Run / Continue”.', 'tegatai-secure') . '</p>';
            }

            echo '</div></div>';
        }


        elseif ($tab == 'timeline') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Security Timeline', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Chronological security events: malware hits, quarantines, FIM changes, login honeypot triggers, etc.', 'tegatai-secure') . '</p>';
            if (class_exists('Tegatai_Timeline')) {
                if (isset($_POST['teg_tl_clear']) && check_admin_referer('teg_tl_clear')) {
                    Tegatai_Timeline::clear();
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Timeline cleared.', 'tegatai-secure') . '</p></div>';
                }
                echo '<form method="post" style="margin:12px 0;">';
                echo wp_nonce_field('teg_tl_clear', '_wpnonce', true, false);
                echo '<button class="button button-secondary" name="teg_tl_clear" value="1">' . esc_html__('Clear timeline', 'tegatai-secure') . '</button>';
                echo '</form>';
                $events = Tegatai_Timeline::get(250);
                if (empty($events)) {
                    echo '<p class="teg-muted">' . esc_html__('No events yet.', 'tegatai-secure') . '</p>';
                } else {
                    echo '<div class="teg-table"><table class="widefat striped"><thead><tr>';
                    echo '<th style="width:170px;">' . esc_html__('Time', 'tegatai-secure') . '</th>';
                    echo '<th style="width:140px;">' . esc_html__('Type', 'tegatai-secure') . '</th>';
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
            } else {
                echo '<p class="teg-muted">' . esc_html__('Timeline module not loaded.', 'tegatai-secure') . '</p>';
            }
            echo '</div></div>';
        }
        elseif ($tab == 'core') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('WordPress Core Integrity', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Compares wp-admin/wp-includes core files against official WordPress checksums.', 'tegatai-secure') . '</p>';
            $res = null;
            if (isset($_POST['teg_core_check']) && check_admin_referer('teg_core_check')) {
                if (class_exists('Tegatai_Core_Integrity')) { $res = Tegatai_Core_Integrity::check(); }
            }
            echo '<form method="post" style="margin:12px 0;">';
            echo wp_nonce_field('teg_core_check', '_wpnonce', true, false);
            echo '<button class="button button-primary" name="teg_core_check" value="1">' . esc_html__('Run core check', 'tegatai-secure') . '</button>';
            echo '</form>';
            if (is_array($res)) {
                $bad = $res['bad'] ?? [];
                $missing = $res['missing'] ?? [];
                $extra = $res['extra'] ?? [];
                echo '<p><strong>' . esc_html__('Version', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)($res['version'] ?? '')) . '</code></p>';
                echo '<ul style="margin-left:18px;">';
                echo '<li><strong>' . esc_html__('Modified', 'tegatai-secure') . ':</strong> ' . esc_html((string)count($bad)) . '</li>';
                echo '<li><strong>' . esc_html__('Missing', 'tegatai-secure') . ':</strong> ' . esc_html((string)count($missing)) . '</li>';
                echo '<li><strong>' . esc_html__('Unexpected', 'tegatai-secure') . ':</strong> ' . esc_html((string)count($extra)) . '</li>';
                echo '</ul>';
            } else {
                echo '<p class="teg-muted">' . esc_html__('Run the check to see results.', 'tegatai-secure') . '</p>';
            }
            echo '</div></div>';
        }
        elseif ($tab == 'options') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Dangerous Options Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-muted">' . esc_html__('Scans wp_options for suspicious stored payloads (eval/base64/script/iframe).', 'tegatai-secure') . '</p>';
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
            } else {
                echo '<p class="teg-muted">' . esc_html__('Run the scan to see results.', 'tegatai-secure') . '</p>';
            }
            
            echo '<hr style="margin:20px 0; border:0; border-top:1px solid #eee;">';
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<label class="teg-switch-label">' . esc_html__('Options Whitelist (Exceptions)', 'tegatai-secure') . '</label>';
            echo '<p class="teg-switch-desc">Pro Zeile ein Teil des Options-Namens (z.B. <code>_transient_</code> oder <code>wp_cache</code>). Optionen, die diese Wörter enthalten, werden vom Scanner ignoriert.</p>';
            echo '<textarea name="tegatai_options[option_whitelist_names]" class="teg-form-input" style="height:100px;" placeholder="_transient_&#10;elementor_">'.esc_textarea($this->get_opt('option_whitelist_names', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="Ausnahmen Speichern" style="margin-top:10px;">';
            echo '</form>';
            
            echo '</div></div>';
        }
        elseif ($tab == 'cron') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Suspicious Cron Monitor', 'tegatai-secure') . '</h3>';
            $res = class_exists('Tegatai_Cron_Monitor') ? Tegatai_Cron_Monitor::inspect() : [];
            $all = $res['all'] ?? [];
            $hits = $res['hits'] ?? [];
            echo '<p><strong>' . esc_html__('Total hooks', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($all)) . '</code>';
            echo ' &nbsp;|&nbsp; <strong>' . esc_html__('Flagged', 'tegatai-secure') . ':</strong> <code>' . esc_html((string)count($hits)) . '</code></p>';

            echo '<hr style="margin:20px 0; border:0; border-top:1px solid #eee;">';
            echo '<form onsubmit="tegSaveForm(this, event)">';
            echo '<label class="teg-switch-label">' . esc_html__('Cron Hooks Whitelist (Exceptions)', 'tegatai-secure') . '</label>';
            echo '<p class="teg-switch-desc">Pro Zeile ein Suchbegriff (z.B. <code>wp_mail</code> oder <code>backup</code>). Cron-Hooks, die diese Wörter enthalten, werden vom Scanner komplett ignoriert.</p>';
            echo '<textarea name="tegatai_options[cron_whitelist_hooks]" class="teg-form-input" style="height:100px;" placeholder="mailpoet&#10;woocommerce">'.esc_textarea($this->get_opt('cron_whitelist_hooks', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="Ausnahmen Speichern" style="margin-top:10px;">';
            echo '</form>';
            
            echo '</div></div>';
        }
        elseif ($tab == 'uploads') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Uploads Monitor', 'tegatai-secure') . '</h3>';
            $res = null;
            if (isset($_POST['teg_up_scan']) && check_admin_referer('teg_up_scan')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { $res = Tegatai_Uploads_Monitor::scan(2000); }
            }
            if (isset($_POST['teg_up_quarantine']) && check_admin_referer('teg_up_quarantine')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { $res = Tegatai_Uploads_Monitor::quarantine_hits(50); }
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

    private function render_toggle($key, $label, $desc = '') {
        $val = $this->get_opt($key);
        $checked = $val ? 'checked' : '';
        echo "<div class='teg-switch-row'><div><span class='teg-switch-label'>$label</span>".($desc ? "<span class='teg-switch-desc'>$desc</span>" : "")."</div><label class='switch'><input type='checkbox' class='teg-toggle-checkbox' onchange=\"tegToggle('$key', this)\" $checked><span class='slider'></span></label></div>";
    }

    public function add_dashboard_widgets() {
        wp_add_dashboard_widget('tegatai_dashboard_widget', __('🛡️ Tegatai Security Status', 'tegatai-secure'), [$this, 'render_dashboard_widget']);
    }

    public function render_dashboard_widget() {
        $stats = Tegatai_Logger::get_stats();
        $scan_status = get_option('teg_scan_status');
        $last_scan = isset($scan_status['last_scan']) ? $scan_status['last_scan'] : __('Never', 'tegatai-secure');
        $scan_res = (isset($scan_status['bad_files']) && empty($scan_status['bad_files'])) ? '<span style=\"color:#10b981;font-weight:bold;\">' . esc_html__('Clean ✅', 'tegatai-secure') . '</span>' : '<span style=\"color:#ef4444;font-weight:bold;\">' . esc_html__('Scan required...', 'tegatai-secure') . '</span>';
        
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

}
