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
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Tegatai uses its own tables (logs, settings) and live security data; queries are prepared and caching would serve stale data

class Tegatai_Admin {
    private $options_slug = 'tegatai_options';
    
    // Settings schema: every key stored in tegatai_options => type. Unknown keys are rejected on save/import.
    private $schema = [
        // Firewall / WAF
        'enable_waf' => 'bool', 'abuseipdb_enabled' => 'bool', 'block_fake_bots' => 'bool', 'block_ai_bots' => 'bool', 'block_seo_bots' => 'bool', 'block_bad_bots' => 'bool',
        'enable_upload_guard' => 'bool', 'enable_rate_limit' => 'bool', 'enable_404_block' => 'bool', 'enable_lockdown' => 'bool',
        'blacklist_ips' => 'textarea', 'whitelist_ips' => 'textarea', 'waf_whitelist_ips' => 'textarea', 'waf_whitelist_urls' => 'textarea',
        'custom_waf_blocklist' => 'regex_list',
        // Hardening
        'hide_wp_version' => 'bool', 'disable_xmlrpc' => 'bool', 'disable_file_editor' => 'bool', 'block_user_enum' => 'bool', 'hide_login_errors' => 'bool',
        'enable_admin_honeypot' => 'bool', 'enable_role_guard' => 'bool',
        // Headers
        'header_xfo' => 'bool', 'header_nosniff' => 'bool', 'header_xss' => 'bool', 'header_hsts' => 'bool', 'header_hsts_subdomains' => 'bool',
        'header_ref' => 'bool', 'header_csp' => 'bool', 'header_permissions' => 'bool',
        // Login & sessions
        'enable_2fa' => 'bool', 'twofa_mode' => ['email', 'app', 'both'],
        'custom_login_slug' => 'slug', 'block_default_login' => 'bool', 'block_dash_access' => 'bool', 'enable_idle_logout' => 'bool', 'block_wp_admin_hide' => 'bool',
        'enable_login_limit' => 'bool', 'enable_trusted_devices' => 'bool', 'trusted_devices' => 'bool', 'disable_app_passwords' => 'bool', 'enable_single_session' => 'bool',
        'enable_ip_guard' => 'bool', 'enable_browser_guard' => 'bool', 'session_max_lifetime' => 'int',
        'enable_turnstile' => 'bool', 'turnstile_site_key' => 'text',
        'enable_recaptcha' => 'bool', 'recaptcha_version' => ['v2', 'v3'], 'recaptcha_site_key' => 'text', 'recaptcha_threshold' => 'score',
        // Server rules
        'server_disable_indexing' => 'bool', 'server_protect_files' => 'bool', 'server_block_xmlrpc' => 'bool', 'server_hide_system_files' => 'bool',
        'server_block_dotfiles' => 'bool', 'block_dotfiles' => 'bool', 'block_system_files' => 'bool', 'server_disable_php_uploads' => 'bool',
        'server_filter_bad_bots' => 'bool', 'server_hotlink_protection' => 'bool', 'server_hotlink_whitelist' => 'textarea',
        'server_protected_dirs' => 'textarea', 'server_custom_files_list' => 'textarea',
        // WP Masking
        'server_mask_paths' => 'bool', 'server_mask_core' => 'bool', 'server_mask_strip' => 'bool', 'server_mask_block' => 'bool', 'server_mask_files' => 'bool',
        'server_mask_base' => 'slug', 'server_mask_includes' => 'slug', 'server_mask_rest' => 'slug', 'server_mask_ajax' => 'slug',
        'server_mask_aliases' => 'alias_map',
        // Anti-spam
        'enable_honeypot' => 'bool', 'enable_bot_timer' => 'bool', 'spam_max_links' => 'int', 'spam_block_trashmail' => 'bool', 'spam_check_referrer' => 'bool',
        // Backups
        'enable_auto_backup' => 'bool', 'backup_frequency' => ['daily', 'weekly'], 'backup_retention_limit' => 'int',
        // Extras
        'disable_rest_api' => 'bool', 'enable_copy_protection' => 'bool', 'enable_rightclick_disable' => 'bool',
        // GeoIP
        'geoip_mode' => ['disabled', 'blacklist', 'whitelist'], 'geoip_list' => 'textarea', 'geoip_login_only' => 'bool',
        // Notifications
        'enable_email_alerts' => 'bool', 'alert_email' => 'email',
        // Scanners
        'enable_auto_quarantine' => 'bool', 'enable_vuln_check' => 'bool', 'scanner_exclusions' => 'textarea', 'option_whitelist_names' => 'textarea',
        'cron_whitelist_hooks' => 'textarea', 'dbscan_extra_patterns' => 'regex_list',
    ];

    // Keys excluded from the JSON export (credentials / secret URLs).
    private $secret_keys = ['turnstile_secret_key', 'recaptcha_secret_key', 'alert_webhook_url'];

    // Captcha switches that exclude each other: switching one on switches the other off
    private $captcha_exclusive = ['enable_recaptcha' => 'enable_turnstile', 'enable_turnstile' => 'enable_recaptcha'];

    public function __construct() {
        add_action('wp_ajax_tegatai_delete_cron', [$this, 'ajax_delete_cron']);
        add_action('admin_post_tegatai_export_config', [$this, 'export_config']);
        add_action('wp_ajax_tegatai_import_config', [$this, 'ajax_import_config']);
        add_action('wp_ajax_tegatai_deep_clean', [$this, 'ajax_deep_clean']);

        add_action('admin_menu', [$this, 'add_menu']);
        add_action('wp_dashboard_setup', [$this, 'add_dashboard_widgets']);
        add_action('admin_init', [$this, 'register_settings']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
        add_action('wp_ajax_tegatai_toggle_option', [$this, 'ajax_toggle_option']);
        add_action('wp_ajax_tegatai_save_form', [$this, 'ajax_save_form']);
        add_action('admin_post_tegatai_write_rules', [$this, 'handle_write_rules']);
        add_action('admin_post_tegatai_unban', [$this, 'handle_unban']);
        add_action('admin_post_tegatai_scan_reset', [$this, 'handle_scan_reset']);
        add_action('admin_post_tegatai_mask_save', [$this, 'handle_mask_save']);
        add_action('admin_post_tegatai_mask_check', [$this, 'handle_mask_check']);
    }

    public function add_menu() {
        add_menu_page('Tegatai', 'Tegatai Secure', 'manage_options', 'tegatai-Secure', [$this, 'render_page'], 'dashicons-shield-alt', 100);
    }

    /**
     * Styles and scripts only on Tegatai's own screens (main page, subpages) and the 2FA part of
     * the user profile. Nothing is loaded on other admin pages.
     */
    public function enqueue_assets($hook) {
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- screen detection only
        if ($page === 'tegatai-secure') {
            wp_enqueue_style('tegatai-admin', TEGATAI_URL . 'css/admin.css', [], TEGATAI_VERSION);
            wp_enqueue_script('tegatai-admin', TEGATAI_URL . 'js/admin.js', ['jquery'], TEGATAI_VERSION, ['in_footer' => true]);
            wp_localize_script('tegatai-admin', 'TegataiAdmin', [
                'ajaxNonce'  => wp_create_nonce('tegatai_ajax_nonce'),
                'adminNonce' => wp_create_nonce('tegatai_admin_nonce'),
                'i18n'       => [
                    'saved'         => __('Saved successfully', 'tegatai-secure'),
                    'dataSaved'     => __('Data saved!', 'tegatai-secure'),
                    'error'         => __('Error', 'tegatai-secure'),
                    'cleanConfirm'  => __('Do you want to clean the database now? (This may take a few seconds on large sites)', 'tegatai-secure'),
                    'cleaning'      => __('Cleaning...', 'tegatai-secure'),
                    'cleanDone'     => __('Cleanup successful! Statistics:', 'tegatai-secure'),
                    'cleanError'    => __('Error during cleanup.', 'tegatai-secure'),
                    'importSelect'  => __('Please select a .json file first!', 'tegatai-secure'),
                    'importConfirm' => __('WARNING: This will overwrite all settings. Continue?', 'tegatai-secure'),
                    'importing'     => __('Importing...', 'tegatai-secure'),
                    'importDone'    => __('Successfully imported! Reloading.', 'tegatai-secure'),
                    'importError'   => __('Import error: ', 'tegatai-secure'),
                    'cronConfirm'   => __('Warning: Deleting a WP cron can affect plugin functionality. Proceed?', 'tegatai-secure'),
                    'deleting'      => __('Deleting...', 'tegatai-secure'),
                    'delete'        => __('Delete', 'tegatai-secure'),
                ],
            ]);
        } elseif (strpos($page, 'tegatai-') === 0) {
            // Subpages (Hive, API Guard, Terminal)
            wp_enqueue_style('tegatai-subpages', TEGATAI_URL . 'css/subpages.css', [], TEGATAI_VERSION);
            if ($page === 'tegatai-hive' || $page === 'tegatai-api-guard') {
                wp_enqueue_script('tegatai-subpages', TEGATAI_URL . 'js/subpages.js', [], TEGATAI_VERSION, ['in_footer' => true]);
                wp_localize_script('tegatai-subpages', 'TegataiSub', [
                    'ajaxUrl'       => admin_url('admin-ajax.php'),
                    'hiveTestNonce' => wp_create_nonce('tegatai_hive_test_nonce'),
                    'i18n'          => [
                        'pinPrompt'       => __('Tegatai Sudo Vault: Please enter your TEGATAI_SUDO_PIN', 'tegatai-secure'),
                        'pinMissing'      => __('Error: TEGATAI_SUDO_PIN is not defined (secrets file or wp-config.php).', 'tegatai-secure'),
                        'pinInvalid'      => __('Sudo Access Denied: Invalid PIN.', 'tegatai-secure'),
                        'requestFailed'   => __('Request failed:', 'tegatai-secure'),
                        'copied'          => __('Copied!', 'tegatai-secure'),
                        'pinging'         => __('Signing payload and pinging nodes...', 'tegatai-secure'),
                        'results'         => __('Cryptographic Handshake Results:', 'tegatai-secure'),
                        'unknownError'    => __('Unknown error', 'tegatai-secure'),
                        'connectionError' => __('Connection error or invalid server response:', 'tegatai-secure'),
                    ],
                ]);
            }
        }
        if ($page === 'tegatai-secure' || $hook === 'profile.php' || $hook === 'user-edit.php') {
            if (class_exists('Tegatai_TwoFactor')) Tegatai_TwoFactor::enqueue_assets();
        }
    }

    public function register_settings() {
        // Every field is sanitized with the same schema as the AJAX save (regex rules stay verbatim).
        register_setting('tegatai_group', $this->options_slug, ['type' => 'array', 'sanitize_callback' => [$this, 'sanitize_options']]);
    }

    public function handle_mask_save() {
        check_admin_referer('tegatai_mask_nonce');
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        $ops = tegatai_get_setting($this->options_slug, []);
        if (!is_array($ops)) $ops = [];
        foreach (['mask_base' => 'server_mask_base', 'mask_includes' => 'server_mask_includes', 'mask_rest' => 'server_mask_rest', 'mask_ajax' => 'server_mask_ajax'] as $field => $key) {
            $ops[$key] = sanitize_title(wp_unslash($_POST[$field] ?? ''));
        }
        $ops['server_mask_aliases'] = $this->sanitize_setting('server_mask_aliases', wp_unslash($_POST['mask_aliases'] ?? [])); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- sanitized per entry in sanitize_setting()
        tegatai_update_setting($this->options_slug, $ops);
        Tegatai_Mask::check(); // also writes the rules
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=masking&msg=mask_saved'));
        exit;
    }

    public function handle_mask_check() {
        check_admin_referer('tegatai_mask_nonce');
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        Tegatai_Mask::check();
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=masking&msg=mask_checked'));
        exit;
    }

    // AbuseIPDB reporting: switch, key state and send status (Firewall tab).
    private function render_abuseipdb_card() {
        if (!class_exists('Tegatai_AbuseIPDB')) return;
        $st = Tegatai_AbuseIPDB::status();
        $has_key = Tegatai_AbuseIPDB::key() !== '';
        echo '<div class="teg-grid" style="margin-top:16px;"><div class="teg-card" style="grid-column: 1 / -1;"><h3>' . esc_html__('AbuseIPDB Reporting', 'tegatai-secure') . '</h3>';
        $this->render_toggle('abuseipdb_enabled', esc_html__('Report bans to AbuseIPDB', 'tegatai-secure'), esc_html__('Sends IPs banned by the honeypot URL, the 404 instant ban, the 404 scan and the login traps (also bans received through The Hive) to AbuseIPDB in the background.', 'tegatai-secure'));
        echo '<p style="font-size:12px; line-height:1.7; margin-top:12px;">';
        echo '<strong>' . esc_html__('API key:', 'tegatai-secure') . '</strong> ';
        if ($has_key) echo esc_html__('found (TEGATAI_ABUSEIPDB_KEY)', 'tegatai-secure');
        else echo '<span style="color:var(--teg-danger);">' . esc_html__('missing - add TEGATAI_ABUSEIPDB_KEY to the secrets file (Management → Secrets). Nothing is sent without a key.', 'tegatai-secure') . '</span>';
        echo '<br><strong>' . esc_html__('Sent today:', 'tegatai-secure') . '</strong> ' . (int) $st['sent_today'];
        echo ' · <strong>' . esc_html__('Total:', 'tegatai-secure') . '</strong> ' . (int) $st['sent_total'];
        echo ' · <strong>' . esc_html__('Waiting:', 'tegatai-secure') . '</strong> ' . (int) Tegatai_AbuseIPDB::queue_size();
        if (!empty($st['last_ok'])) echo '<br><strong>' . esc_html__('Last report:', 'tegatai-secure') . '</strong> ' . esc_html(wp_date('Y-m-d H:i:s', (int) $st['last_ok']));
        if ((int) $st['backoff_until'] > time()) echo '<br><strong>' . esc_html__('Paused until:', 'tegatai-secure') . '</strong> ' . esc_html(wp_date('Y-m-d H:i', (int) $st['backoff_until']));
        if (!empty($st['last_error'])) echo '<br><strong>' . esc_html__('Last error:', 'tegatai-secure') . '</strong> ' . esc_html(wp_date('Y-m-d H:i', (int) $st['last_error_at']) . ' - ' . $st['last_error']);
        echo '</p>';
        echo '<p class="teg-switch-desc" style="display:block;">' . esc_html__('Reports contain only the IP, the category and the type of the ban - no URLs, usernames or other request data. Private and reserved IPs are never reported.', 'tegatai-secure') . '</p>';
        echo '</div></div>';
    }

    // WP Masking tab: switches, check of the new paths and the names (aliases)
    private function render_mask_tab() {
        $msg = isset($_GET['msg']) ? sanitize_key(wp_unslash($_GET['msg'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $notes = [
            'mask_saved'   => ['#dcfce7;color:#15803d;border:1px solid #bbf7d0', __('Names saved, rules written and new paths checked.', 'tegatai-secure')],
            'mask_checked' => ['#dcfce7;color:#15803d;border:1px solid #bbf7d0', __('New paths checked.', 'tegatai-secure')],
        ];
        $status  = Tegatai_Mask::status();
        $snap    = Tegatai_Mask::snapshot();
        $aliases = Tegatai_Mask::aliases();
        $failed  = isset($status['failed']) && is_array($status['failed']) ? $status['failed'] : [];
        $skipped = isset($status['skipped']) && is_array($status['skipped']) ? $status['skipped'] : [];
        $home    = Tegatai_Mask::home_path();
        $base    = Tegatai_Mask::base();
        $paths_on = Tegatai_Mask::on('paths');
        $core_on  = Tegatai_Mask::on('core');

        // Status of one entry: masked, waiting for a check, failed or nothing to hide
        $state = static function ($key, $new_active) use ($failed, $skipped) {
            if ($new_active) return '<span style="color:#15803d; font-weight:600;">' . esc_html__('Masked', 'tegatai-secure') . '</span>';
            if (in_array($key, $skipped, true)) return '<span style="color:#64748b;">' . esc_html__('No files to hide', 'tegatai-secure') . '</span>';
            if (isset($failed[$key])) return '<span style="color:#b91c1c; font-weight:600;">' . esc_html__('Not reachable', 'tegatai-secure') . '</span> <span style="color:#64748b;">(' . esc_html((string) $failed[$key]) . ')</span>';
            return '<span style="color:#b45309; font-weight:600;">' . esc_html__('Waiting for check', 'tegatai-secure') . '</span>';
        };

        echo '<div class="teg-grid"><div class="teg-card">';
        echo '<h3>' . esc_html__('WP Masking', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Hides the WordPress structure in the pages visitors receive. nginx maps the new paths back to the real files; the rules are part of tegatai-nginx.conf.', 'tegatai-secure') . '</p>';
        if (isset($notes[$msg])) {
            echo '<div style="padding:10px 12px; border-radius:6px; margin-bottom:12px; font-size:12px; background:' . esc_attr($notes[$msg][0]) . ';">' . esc_html($notes[$msg][1]) . '</div>';
        }
        $this->render_toggle('server_mask_paths', esc_html__('Hide plugin and theme paths', 'tegatai-secure'), esc_html__('Plugin and theme folders are shown under their own names, e.g. /assets/bar/ instead of the plugin folder.', 'tegatai-secure'));
        $this->render_toggle('server_mask_core', esc_html__('Hide wp-includes, wp-json and admin-ajax', 'tegatai-secure'), esc_html__('wp-includes, the REST API and admin-ajax.php get their own paths. /wp-json/ keeps working for The Hive and other sites.', 'tegatai-secure'));
        $this->render_toggle('server_mask_strip', esc_html__('Remove versions and identifiers', 'tegatai-secure'), esc_html__('Removes ?ver= parameters, script/style ids, generator tags, RSD/wlwmanifest/shortlink/REST links, the emoji script, the speculation rules (they list the WordPress paths) and the X-Pingback header.', 'tegatai-secure'));
        $this->render_toggle('server_mask_files', esc_html__('Hide file names', 'tegatai-secure'), esc_html__('File names of masked plugin, theme and wp-includes files are replaced by a neutral name per file, e.g. /assets/bar/css/t3f9a0c1d2e4. The folders stay, so relative URLs in CSS and JS keep working. A changed file gets a new name.', 'tegatai-secure'));
        if (Tegatai_Mask::on('files')) {
            $fs = Tegatai_Mask::files_summary();
            echo '<p class="teg-switch-desc" style="display:block; margin:-4px 0 10px;">';
            /* translators: 1: number of active file names, 2: number of waiting file names */
            echo esc_html(sprintf(__('File names: %1$d active, %2$d waiting.', 'tegatai-secure'), $fs['active'], $fs['waiting']));
            if ($fs['waiting']) echo ' ' . esc_html__('New files are found when pages are visited. Tegatai adds them to the rules and checks them every hour; they are used as soon as nginx was reloaded. "Check new paths" does both right away.', 'tegatai-secure');
            echo '</p>';
        }
        $this->render_toggle('server_mask_block', esc_html__('Block original paths', 'tegatai-secure'), esc_html__('Visitors get a 404 for the original paths of masked entries. Logged-in users keep access. /wp-json/tegatai/ (The Hive) stays reachable.', 'tegatai-secure'));

        echo '<div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:6px; padding:12px; margin-top:14px; font-size:12px; line-height:1.6;">';
        echo '<strong>' . esc_html__('How it is activated', 'tegatai-secure') . '</strong><br>';
        echo esc_html__('1. Switch on and save the names. 2. Reload nginx so the new rules are active. 3. Click "Check new paths". Only paths that answered correctly are used in the pages and blocked, so a missing reload never breaks the site.', 'tegatai-secure');
        echo '</div>';

        if (!empty($status['time'])) {
            /* translators: %s: date and time */
            echo '<p class="teg-switch-desc" style="display:block; margin-top:12px;">' . esc_html(sprintf(__('Last check: %s', 'tegatai-secure'), wp_date('Y-m-d H:i:s', (int) $status['time']))) . '</p>';
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:10px;"><input type="hidden" name="action" value="tegatai_mask_check">' . wp_kses(wp_nonce_field('tegatai_mask_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT) . '<input type="submit" class="button button-primary" value="' . esc_attr__('Check new paths', 'tegatai-secure') . '"></form>';
        $this->render_rules_status();
        echo '</div>';

        // Names
        echo '<div class="teg-card" style="grid-column: 1 / -1;"><h3>' . esc_html__('Names', 'tegatai-secure') . '</h3>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '"><input type="hidden" name="action" value="tegatai_mask_save">' . wp_kses(wp_nonce_field('tegatai_mask_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT);
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:10px;">' . esc_html__('Lowercase letters, digits and hyphens. Names starting with "wp-" are not allowed. Empty fields get an automatic short name.', 'tegatai-secure') . '</p>';

        $field = static function ($name, $label, $value, $hint) {
            echo '<label class="teg-switch-label" style="display:block; margin-top:8px;">' . esc_html($label) . '</label>';
            echo '<input type="text" name="' . esc_attr($name) . '" value="' . esc_attr($value) . '" class="teg-form-input" maxlength="40" pattern="[a-z0-9\-]*">';
            echo '<p class="teg-switch-desc" style="display:block; margin:2px 0 0;">' . wp_kses_post($hint) . '</p>';
        };
        /* translators: %s: example path */
        $field('mask_base', __('Folder for plugins and themes', 'tegatai-secure'), $base, sprintf(__('Plugins and themes are shown under %s', 'tegatai-secure'), '<code>' . esc_html($home . '/' . $base . '/&lt;name&gt;/') . '</code>'));

        echo '<table class="widefat striped" style="margin-top:12px; font-size:12px;"><thead><tr><th>' . esc_html__('Folder', 'tegatai-secure') . '</th><th>' . esc_html__('Name', 'tegatai-secure') . '</th><th>' . esc_html__('Status', 'tegatai-secure') . '</th></tr></thead><tbody>';
        foreach ($aliases as $key => $alias) {
            $active = $paths_on && isset($snap['paths'][$key]);
            echo '<tr><td><code>' . esc_html(Tegatai_Mask::real_path($key) . '/') . '</code><br><span style="color:#64748b;">' . esc_html(Tegatai_Mask::label($key)) . '</span></td>';
            echo '<td><input type="text" name="mask_aliases[' . esc_attr($key) . ']" value="' . esc_attr($alias) . '" class="teg-form-input" style="margin:0; width:180px; max-width:100%;" maxlength="40" pattern="[a-z0-9\-]*">';
            if ($active && $snap['paths'][$key] !== $base . '/' . $alias) {
                /* translators: %s: path that is in use until the new name was checked */
                echo '<br><span style="color:#64748b;">' . esc_html(sprintf(__('in use: %s', 'tegatai-secure'), $home . '/' . $snap['paths'][$key] . '/')) . '</span>';
            }
            echo '</td><td>' . ($paths_on ? wp_kses_post($state($key, $active)) : '<span style="color:#64748b;">' . esc_html__('Off', 'tegatai-secure') . '</span>') . '</td></tr>';
        }
        echo '</tbody></table>';

        echo '<h4 style="margin:16px 0 4px; font-size:12px;">' . esc_html__('WordPress core', 'tegatai-secure') . '</h4>';
        $field('mask_includes', 'wp-includes', Tegatai_Mask::inc_alias(), wp_kses_post($core_on ? $state('includes', $snap['includes'] !== '') : esc_html__('Off', 'tegatai-secure')));
        $field('mask_rest', 'wp-json (REST API)', Tegatai_Mask::rest_alias(), $core_on ? '<span style="color:#15803d; font-weight:600;">' . esc_html__('Masked', 'tegatai-secure') . '</span>' : esc_html__('Off', 'tegatai-secure'));
        $field('mask_ajax', 'admin-ajax.php', Tegatai_Mask::ajax_alias(), wp_kses_post($core_on ? $state('ajax', $snap['ajax'] !== '') : esc_html__('Off', 'tegatai-secure')));

        echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" style="margin-top:12px;"></form></div></div>';
    }

    // Saves the names, writes the rules and checks the new paths
    private function render_secrets_tab() {
        $file = tegatai_secrets_file();
        $exists = file_exists($file);
        $status = tegatai_secrets_status();
        $labels = [
            'file'      => __('Secrets file', 'tegatai-secure'),
            'wp-config' => 'wp-config.php',
            'database'  => __('Database (older version, read only)', 'tegatai-secure'),
            ''          => __('Not set', 'tegatai-secure'),
        ];

        echo '<div class="teg-grid"><div class="teg-card" style="grid-column: 1 / -1;">';
        echo '<h3>' . esc_html__('Secrets File', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Tegatai keeps keys, API secrets and webhook URLs only in a PHP file outside the web root (or as constants in wp-config.php), never in the database. Tegatai only reads this file; you create it with the command below.', 'tegatai-secure') . '</p>';

        echo '<p style="font-size:13px;"><strong>' . esc_html__('Path:', 'tegatai-secure') . '</strong> <code>' . esc_html($file) . '</code> — ';
        if ($exists) {
            $perms = substr(sprintf('%o', (int) @fileperms($file)), -4);
            /* translators: %s: file permissions, e.g. 0600 */
            echo esc_html(sprintf(__('found (permissions %s)', 'tegatai-secure'), $perms));
            if ($perms !== '0600' && $perms !== '0400') echo ' <span style="color:var(--teg-danger);">' . esc_html__('Recommended: 0600', 'tegatai-secure') . '</span>';
        } else {
            echo esc_html__('not found', 'tegatai-secure');
        }
        echo '</p>';

        echo '<table class="teg-table" style="margin:12px 0;"><thead><tr><th>' . esc_html__('Secret', 'tegatai-secure') . '</th><th>' . esc_html__('Loaded from', 'tegatai-secure') . '</th><th>' . esc_html__('Note', 'tegatai-secure') . '</th></tr></thead><tbody>';
        foreach ($status as $name => $st) {
            $note = '';
            if ($st['source'] === 'wp-config' && $st['in_file']) $note = __('Also in the secrets file: remove the define() line from wp-config.php.', 'tegatai-secure');
            elseif ($st['source'] === 'database') $note = __('Move it into the secrets file (command below); the database copy is then deleted automatically.', 'tegatai-secure');
            echo '<tr><td><code>' . esc_html($name) . '</code></td><td>' . esc_html($labels[$st['source']]) . '</td><td>' . esc_html($note) . '</td></tr>';
        }
        echo '</tbody></table>';

        // Command that writes the complete file: current values (file, wp-config.php, legacy
        // database copies) plus a new backup secret if there is none yet. Run as the PHP-FPM user.
        $values = [];
        $legacy = tegatai_legacy_db_secrets();
        $in_file = tegatai_read_secrets_file();
        foreach (tegatai_secret_names() as $name) {
            if (isset($in_file[$name])) $values[$name] = $in_file[$name];
            elseif (defined($name) && is_string(constant($name)) && constant($name) !== '') $values[$name] = constant($name);
            elseif (isset($legacy[$name])) $values[$name] = $legacy[$name];
            elseif ($name === 'TEGATAI_BACKUP_SECRET' && Tegatai_Backup::own_keys()['public'] === '') $values[$name] = bin2hex(random_bytes(32));
            else $values[$name] = null;
        }
        $cmd = tegatai_key_file_command($file, $values, ['Tegatai Secure secrets. Keep this file outside the web root (folder 0700, file 0600).']);
        echo '<h4 style="margin-top:20px;">' . esc_html__('Create or update the secrets file', 'tegatai-secure') . '</h4>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:8px;">' . esc_html__('Run this command on the server as the site\'s PHP-FPM user (not as root), e.g. via SSH. It writes the complete file with all values Tegatai knows right now, including values still stored in the database by an older version; those database copies are deleted automatically afterwards. Edit the commented lines in the file to add more secrets.', 'tegatai-secure') . '</p>';
        echo '<details style="margin-bottom:12px;"><summary style="cursor:pointer; font-weight:600;">' . esc_html__('Show command (contains secrets)', 'tegatai-secure') . '</summary>';
        echo '<pre style="background:#0f172a; color:#e2e8f0; padding:12px; border-radius:6px; font-size:12px; overflow-x:auto; margin-top:8px;">' . esc_html($cmd) . '</pre></details>';

        // How to create each secret (run the commands on the server or any machine with PHP)
        $howto = [
            'TEGATAI_HIVE_SECRET' => [
                __('Signs the messages between your Hive sites (HMAC). Must be the same on every Hive site, unless you use per-peer keys.', 'tegatai-secure'),
                'php -r "echo \'tg_hmac_\' . bin2hex(random_bytes(32)), PHP_EOL;"',
            ],
            'TEGATAI_API_SECRET' => [
                __('Signs the requests of your API clients for the API Guard. Clients must use the same value.', 'tegatai-secure'),
                'php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"',
            ],
            'TEGATAI_SUDO_PIN' => [
                __('Optional. A bcrypt hash of a PIN of your choice; the PIN unlocks the display of secrets. Only the hash goes into the file, never the PIN itself.', 'tegatai-secure'),
                'php -r "echo password_hash(\'YourPin\', PASSWORD_BCRYPT), PHP_EOL;"',
            ],
            'TEGATAI_BACKUP_SECRET' => [
                __('Key for encrypting backups when no backup key pair is used. Never change it once backups exist, otherwise they can no longer be decrypted.', 'tegatai-secure'),
                'php -r "echo bin2hex(random_bytes(32)), PHP_EOL;"',
            ],
            'TEGATAI_ABUSEIPDB_KEY' => [
                __('Optional. API key for reporting banned IPs to AbuseIPDB (Firewall tab). Create it in your AbuseIPDB account under API.', 'tegatai-secure'),
                'https://www.abuseipdb.com/account/api',
            ],
            'TEGATAI_RECAPTCHA_SECRET' => [
                __('Optional. Secret key of Google reCAPTCHA (the site key stays in the settings).', 'tegatai-secure'),
                'Google reCAPTCHA admin console > your site > Settings',
            ],
            'TEGATAI_TURNSTILE_SECRET' => [
                __('Optional. Secret key of Cloudflare Turnstile (the site key stays in the settings).', 'tegatai-secure'),
                'Cloudflare dashboard > Turnstile > your site > Settings',
            ],
            'TEGATAI_ALERT_WEBHOOK' => [
                __('Optional. Webhook URL for security alerts (e.g. Discord). It contains an access token, so it is treated as a secret.', 'tegatai-secure'),
                'https://discord.com/api/webhooks/...',
            ],
        ];
        echo '<h4 style="margin-top:20px;">' . esc_html__('How to create the keys', 'tegatai-secure') . '</h4>';
        foreach ($howto as $name => $h) {
            echo '<div style="margin-bottom:12px;"><code style="font-weight:600;">' . esc_html($name) . '</code><br>';
            echo '<span style="font-size:12px;">' . esc_html($h[0]) . '</span>';
            echo '<pre style="background:#0f172a; color:#e2e8f0; padding:8px 12px; border-radius:6px; font-size:12px; overflow-x:auto; margin:4px 0 0;">' . esc_html($h[1]) . '</pre></div>';
        }

        echo '<p class="teg-switch-desc" style="display:block;">' . esc_html__('Instead of the file, the same names can be defined as constants in wp-config.php. Another location for the file can be set in wp-config.php with the path only:', 'tegatai-secure') . ' <code>define(\'TEGATAI_SECRETS_FILE\', \'/path/tegatai-secrets.php\');</code></p>';
        echo '</div></div>';
    }

    /**
     * Status line for a secret that lives in the secrets file (never in the database).
     */
    private function secret_note($name) {
        $st = tegatai_secrets_status();
        $src = $st[$name]['source'] ?? '';
        if ($src === 'file' || $src === 'wp-config') {
            $txt = sprintf(/* translators: %s: constant name */ __('%s is set (secrets file / wp-config.php).', 'tegatai-secure'), $name);
            return '<p class="teg-switch-desc" style="display:block; color:#15803d;">🔒 ' . esc_html($txt) . '</p>';
        }
        if ($src === 'database') {
            $txt = sprintf(/* translators: %s: constant name */ __('Still stored in the database by an older version. Move it into the secrets file as %s (command in the Secrets tab); it is then deleted from the database.', 'tegatai-secure'), $name);
            return '<p class="teg-switch-desc" style="display:block; color:#b45309;">⚠️ ' . esc_html($txt) . '</p>';
        }
        $txt = sprintf(/* translators: %s: constant name */ __('Not set. Secrets are never stored in the database: add %s to the secrets file (Secrets tab).', 'tegatai-secure'), $name);
        return '<p class="teg-switch-desc" style="display:block;">' . esc_html($txt) . '</p>';
    }

    // Notifications card (email alerts, webhook), shown in the Login tab.
    private function render_notifications_card() {
        echo '<div class="teg-card"><h3>' . esc_html__('Notifications', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_email_alerts', esc_html__('Enable Email Alerts', 'tegatai-secure'), esc_html__('Receive notifications for critical security events.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">
        <label class="teg-switch-label">' . esc_html__('Recipient Email', 'tegatai-secure') . '</label>
        <input type="email" name="tegatai_options[alert_email]" value="'.esc_attr($this->get_opt('alert_email', get_option('admin_email'))).'" class="teg-form-input">
        <label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Webhook URL', 'tegatai-secure') . '</label>
        ' . wp_kses_post($this->secret_note('TEGATAI_ALERT_WEBHOOK')) . '
        <input type="submit" class="button button-primary" style="margin-top:8px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >
    </form></div>';
    }

    // 2FA card: on/off, method and the current user's authenticator + backup codes (Login tab).
    private function render_2fa_card() {
        echo '<div class="teg-card" id="tegatai-2fa-card"><h3>' . esc_html__('2FA', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_2fa', esc_html__('Enable 2FA', 'tegatai-secure'), esc_html__('Enforces Two-Factor Authentication for administrators.', 'tegatai-secure'));
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Preferred Method', 'tegatai-secure') . '</label>';
        echo '<select name="tegatai_options[twofa_mode]" class="teg-form-input">';
        echo '<option value="email" '.selected($this->get_opt('twofa_mode'), 'email', false).'>' . esc_html__('Email Code Only', 'tegatai-secure') . '</option>';
        echo '<option value="app" '.selected($this->get_opt('twofa_mode'), 'app', false).'>' . esc_html__('App Only', 'tegatai-secure') . '</option>';
        echo '<option value="both" '.selected($this->get_opt('twofa_mode', 'both'), 'both', false).'>' . esc_html__('Both', 'tegatai-secure') . '</option>';
        echo '</select>';
        echo '<input type="submit" class="button button-primary" style="margin-top:8px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" >';
        echo '</form>';
        if (class_exists('Tegatai_TwoFactor') && method_exists('Tegatai_TwoFactor', 'render_enrollment_box')) { Tegatai_TwoFactor::render_enrollment_box(get_current_user_id(), true); }
        echo '</div>'; 
    }

    // Shows where the nginx rules file is and whether the last write worked.
    private function render_rules_status() {
        $st = Tegatai_Server::rules_status();
        $ok = !empty($st['ok']);
        $path = (string) ($st['path'] ?? Tegatai_Server::get_rules_file_path());
        $exists = $path !== '' && file_exists($path);
        $bg = $ok && $exists ? '#dcfce7;color:#15803d;border:1px solid #bbf7d0' : '#fee2e2;color:#b91c1c;border:1px solid #fecaca';
        echo '<div style="margin-top:16px; padding:10px 12px; border-radius:6px; font-size:12px; line-height:1.6; background:' . esc_attr($bg) . ';">';
        if (empty($st)) {
            echo esc_html__('The rules file has not been written by this version yet. Click "Write rules to config".', 'tegatai-secure');
        } elseif ($ok && $exists) {
            /* translators: 1: file path, 2: date and time */
            echo esc_html(sprintf(__('Rules written to %1$s (%2$s).', 'tegatai-secure'), $path, wp_date('Y-m-d H:i:s', (int) $st['time'])));
            echo '<br>' . esc_html__('Include line for your nginx server block:', 'tegatai-secure') . ' <code>include ' . esc_html($path) . ';</code>';
        } elseif ($ok) {
            /* translators: %s: file path */
            echo esc_html(sprintf(__('The rules file %s was written but no longer exists. Click "Write rules to config".', 'tegatai-secure'), $path));
        } else {
            /* translators: %s: error details (paths and reasons) */
            echo esc_html(sprintf(__('The rules file could not be written: %s', 'tegatai-secure'), (string) $st['error']));
        }
        echo '</div>';
    }

    public function handle_write_rules() {
        check_admin_referer('tegatai_write_nonce');
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        $status = Tegatai_Server::force_update();
        $msg = !empty($status['ok']) ? 'rules_written' : 'rules_failed';
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=server&msg=' . $msg));
        exit;
    }

    // Aborts a stuck/interrupted file scan so a new one can be started.
    public function handle_scan_reset() {
        check_admin_referer('tegatai_scan_reset_nonce');
        if (!current_user_can('manage_options')) wp_die('Forbidden');
        delete_option('tegatai_scan_status');
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=scanner'));
        exit;
    }

    public function ajax_toggle_option() {
        check_ajax_referer('tegatai_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Forbidden');
        $key = sanitize_text_field(wp_unslash($_POST['key'] ?? '')); $val = sanitize_text_field(wp_unslash($_POST['val'] ?? ''));
        if (!$key || ($this->schema[$key] ?? null) !== 'bool') { wp_send_json_error('Invalid key'); }
        $ops = tegatai_get_setting($this->options_slug, []); $ops[$key] = ($val === '1') ? 1 : 0;
        if ($key === 'enable_trusted_devices' || $key === 'trusted_devices') {
            $ops['enable_trusted_devices'] = ($val === '1') ? 1 : 0;
            $ops['trusted_devices'] = ($val === '1') ? 1 : 0;
        }
        // Only one captcha at a time: Google reCAPTCHA on = Cloudflare Turnstile off (and the other way round)
        $switched_off = [];
        if ($val === '1' && isset($this->captcha_exclusive[$key]) && !empty($ops[$this->captcha_exclusive[$key]])) {
            $ops[$this->captcha_exclusive[$key]] = 0;
            $switched_off[] = $this->captcha_exclusive[$key];
        }
        tegatai_update_setting($this->options_slug, $ops);
        if (strpos($key, 'server_mask_') === 0 && class_exists('Tegatai_Mask')) Tegatai_Mask::check(); // checks the new paths and writes the rules
        elseif (strpos($key, 'server_') === 0) Tegatai_Server::force_update();
        wp_send_json_success(['message' => __('Saved successfully', 'tegatai-secure'), 'switched_off' => $switched_off]);
    }

    public function ajax_save_form() {
        check_ajax_referer('tegatai_ajax_nonce', 'nonce');
        if (!current_user_can('manage_options')) wp_send_json_error('Forbidden');
        parse_str(wp_unslash($_POST['form_data'] ?? ''), $form_vars); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- every field is sanitized per key below
        $current_ops = tegatai_get_setting($this->options_slug, []); if (!is_array($current_ops)) $current_ops = [];
        $new_data = isset($form_vars['tegatai_options']) ? $form_vars['tegatai_options'] : [];
        if (!empty($new_data) && is_array($new_data)) {
            $saved = 0;
            foreach ($new_data as $key => $value) {
                if (!isset($this->schema[$key])) continue; // Unknown keys are discarded
                $current_ops[$key] = $this->sanitize_setting($key, $value);
                $saved++;
            }
            if (!$saved) wp_send_json_error(['message' => __('No data provided.', 'tegatai-secure')]);
            tegatai_update_setting($this->options_slug, $current_ops);
            if (class_exists('Tegatai_Server')) Tegatai_Server::force_update();
            wp_send_json_success(['message' => __('Data saved!', 'tegatai-secure')]);
        } else wp_send_json_error(['message' => __('No data provided.', 'tegatai-secure')]);
    }

    // register_setting() callback: keeps only known fields, each sanitized by its schema type.
    public function sanitize_options($value) {
        $out = [];
        if (!is_array($value)) return $out;
        foreach ($value as $key => $v) {
            if (!is_string($key) || !isset($this->schema[$key])) continue;
            $out[$key] = $this->sanitize_setting($key, $v);
        }
        return $out;
    }

    // Sanitizes a single value according to its schema type.
    private function sanitize_setting($key, $value) {
        $type = $this->schema[$key];
        if ($type === 'alias_map') return $this->sanitize_alias_map($value);
        if (!is_scalar($value)) $value = '';
        $value = (string)$value;
        if (is_array($type)) return in_array($value, $type, true) ? $value : $type[0];
        switch ($type) {
            case 'bool': return ($value === '1' || $value === 'on' || $value === 'true') ? 1 : 0;
            case 'int': return max(0, intval($value));
            case 'score': return is_numeric($value) ? round(max(0.1, min(0.9, (float) $value)), 1) : 0.5;
            case 'email': return sanitize_email($value);
            case 'url': return esc_url_raw(trim($value), ['https', 'http']);
            case 'slug': return sanitize_title($value);
            case 'textarea': return sanitize_textarea_field($value);
            case 'regex_list': return $this->sanitize_regex_list($value);
            default: return sanitize_text_field($value);
        }
    }

    // WP Masking names: ['plugin:<folder>' | 'theme:<slug>' => name]
    private function sanitize_alias_map($value) {
        $out = [];
        if (!is_array($value)) return $out;
        foreach ($value as $k => $v) {
            if (!is_string($k) || !preg_match('/^(plugin|theme):[A-Za-z0-9._\-]{1,100}$/', $k) || !is_scalar($v)) continue;
            $name = substr(sanitize_title((string) $v), 0, 40);
            if ($name !== '') $out[$k] = $name;
        }
        return $out;
    }

    // Keeps regex rules verbatim (no tag/octet stripping) but drops lines that do not compile.
    private function sanitize_regex_list($value) {
        $valid = [];
        foreach (explode("\n", str_replace(["\r\n", "\r"], "\n", $value)) as $rule) {
            $rule = trim(wp_check_invalid_utf8($rule));
            if ($rule === '' || strlen($rule) > 255) continue;
            if (@preg_match($rule, '') === false) continue;
            $valid[] = $rule;
        }
        return implode("\n", $valid);
    }

    private function get_opt($key, $default = 0) {
        $ops = tegatai_get_setting($this->options_slug, []);
        return isset($ops[$key]) ? $ops[$key] : $default;
    }

    public function render_page() {
        $tab = isset($_GET['tab']) ? sanitize_key(wp_unslash($_GET['tab'])) : 'dashboard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- tab navigation only
        
        if (isset($_POST['tegatai_action']) && $_POST['tegatai_action'] == 'clear_logs') {
            check_admin_referer('tegatai_act_nonce'); Tegatai_Logger::clear();
        }
        if (isset($_POST['action']) && $_POST['action'] == 'tegatai_clear_history') {
             check_admin_referer('tegatai_hist_nonce'); Tegatai_UserHistory::clear_history();
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
                'desc' => __('Server Rules, HTTP Headers, WP Masking, System Hardening', 'tegatai-secure'),
                'tabs' => [
                    'server' => __('Server Rules', 'tegatai-secure'),
                    'headers' => __('HTTP Headers', 'tegatai-secure'),
                    'masking' => __('WP Masking', 'tegatai-secure'),
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
                    'extras' => __('Extras & API', 'tegatai-secure'),
                    'secrets' => __('Secrets', 'tegatai-secure')
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
        <div id="teg-toast"></div>
        <div class="teg-wrap">
            <div class="teg-header teg-header-brand">
                <div class="teg-title teg-brand"><img class="teg-banner" src="<?php echo esc_url( TEGATAI_URL . 'images/tegatai-banner.png' ); ?>" width="772" height="250" alt="Tegatai Secure"></div>
                <div class="teg-badge">v<?php echo esc_html( TEGATAI_VERSION ); ?></div>
            </div>

            <?php if ($tab == 'dashboard'): ?>
                <?php
                  $ops = tegatai_get_setting($this->options_slug, []);
                  if (!is_array($ops)) { $ops = []; }
                  $stats2 = (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_stats')) ? Tegatai_Logger::get_stats() : ['blocked'=>0,'total'=>0];
                  $rows2 = (class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger','get_logs')) ? Tegatai_Logger::get_logs(250) : [];
                  $cut24 = time() - 86400; $blocks_24h = 0; $fails_24h = 0; $ip_counts = []; $recent = [];
                  foreach ($rows2 as $rr) {
                    $tstr = isset($rr['time']) ? (string)$rr['time'] : ''; $tt = $tstr ? strtotime($tstr) : 0;
                    $typ = strtoupper((string)($rr['type'] ?? '')); $msg = (string)($rr['message'] ?? ''); $low = strtolower($msg); $ip = (string)($rr['ip'] ?? '');
                    if ($tt && $tt >= $cut24) {
                      if (strpos($typ,'BLOCK')!==false || strpos($typ,'WAF')!==false || strpos($low,'blocked')!==false) $blocks_24h++;
                      if (strpos($typ,'LOGIN_FAIL')!==false || (strpos($typ,'LOGIN')!==false && strpos($typ,'FAIL')!==false) || strpos($low,'failed login')!==false || strpos($low,'invalid password')!==false || strpos($low,'login attempt')!==false) $fails_24h++;
                      if ($ip && !in_array($typ,['LOGIN','INFO','BACKUP','AUTH'],true)) $ip_counts[$ip]=($ip_counts[$ip]??0)+1;
                    }
                    if ($tt) $recent[]=['time'=>$tt,'type'=>$typ ?: 'EVENT','message'=>$msg];
                  }
                  arsort($ip_counts); $top_ips=array_slice($ip_counts,0,5,true);
                  usort($recent,function($a,$b){return $b['time']<=>$a['time'];}); $recent=array_slice($recent,0,6);
                  $protection = [
                    'enable_waf'=>__('WAF Firewall','tegatai-secure'), 'enable_login_limit'=>__('Login Guard','tegatai-secure'),
                    'enable_2fa'=>__('Two-Factor Auth','tegatai-secure'), 'enable_upload_guard'=>__('Upload Guard','tegatai-secure'),
                    'enable_honeypot'=>__('Honeypot','tegatai-secure'), 'enable_rate_limit'=>__('Rate Limiting','tegatai-secure'),
                    'enable_auto_quarantine'=>__('Auto Quarantine','tegatai-secure'), 'enable_trusted_devices'=>__('Trusted Devices','tegatai-secure')
                  ];
                  $enabled=0; foreach($protection as $k=>$label){ if(!empty($ops[$k])) $enabled++; }
                  $score = count($protection) ? (int)round(($enabled/count($protection))*70) : 0;
                  $score += !empty($ops['server_protect_files']) ? 8 : 0;
                  $score += !empty($ops['server_hide_system_files']) ? 5 : 0;
                  $score += !empty($ops['server_block_dotfiles']) ? 5 : 0;
                  $score += !empty($ops['enable_auto_backup']) ? 5 : 0;
                  $score += ($fails_24h===0 ? 4 : 0) + ($blocks_24h<100 ? 3 : 0);
                  $score = max(0,min(100,$score));
                  $status = $score >= 85 ? __('PROTECTED','tegatai-secure') : ($score >= 65 ? __('ATTENTION','tegatai-secure') : __('CRITICAL','tegatai-secure'));
                  $status_desc = $score >= 85 ? __('Core protections are active and no critical dashboard condition was detected.','tegatai-secure') : ($score >= 65 ? __('Some protections are disabled or recent security activity needs review.','tegatai-secure') : __('Important protections are missing. Review the security modules below.','tegatai-secure'));
                  $score_class = $score < 65 ? 'teg-score-danger' : ($score < 85 ? 'teg-score-warn' : '');
                  $status_color = $score < 65 ? '#ef4444' : ($score < 85 ? '#f59e0b' : '#10b981');

                  // Actionable recommendations: only show settings that are genuinely worth reviewing.
                  // Optional features are deliberately presented as optional, not as security failures.
                  $recommendations = [];
                  if (empty($ops['enable_waf'])) {
                    $recommendations[] = ['level'=>'important','title'=>__('Enable WAF Firewall','tegatai-secure'),'desc'=>__('Recommended as the primary request-level protection against common malicious traffic.','tegatai-secure'),'tab'=>'firewall','action'=>__('Review WAF','tegatai-secure')];
                  }
                  if (empty($ops['enable_2fa'])) {
                    $recommendations[] = ['level'=>'important','title'=>__('Enable Two-Factor Authentication','tegatai-secure'),'desc'=>__('Strongly recommended for administrator accounts to reduce the impact of stolen passwords.','tegatai-secure'),'tab'=>'login','action'=>__('Review 2FA','tegatai-secure')];
                  }
                  if (empty($ops['enable_login_limit'])) {
                    $recommendations[] = ['level'=>'recommended','title'=>__('Enable Login Guard','tegatai-secure'),'desc'=>__('Helps slow down repeated login attempts and brute-force attacks.','tegatai-secure'),'tab'=>'login','action'=>__('Review Login Guard','tegatai-secure')];
                  }
                  if (empty($ops['enable_upload_guard'])) {
                    $recommendations[] = ['level'=>'recommended','title'=>__('Review Upload Guard','tegatai-secure'),'desc'=>__('Especially useful when the website accepts user-uploaded files.','tegatai-secure'),'tab'=>'firewall','action'=>__('Review Upload Guard','tegatai-secure')];
                  }
                  if (empty($ops['enable_rate_limit'])) {
                    $recommendations[] = ['level'=>'recommended','title'=>__('Review Rate Limiting','tegatai-secure'),'desc'=>__('Useful for limiting abusive request bursts without blocking normal visitors.','tegatai-secure'),'tab'=>'firewall','action'=>__('Review limits','tegatai-secure')];
                  }
                  if (empty($ops['server_protect_files'])) {
                    $recommendations[] = ['level'=>'recommended','title'=>__('Enable protected server files','tegatai-secure'),'desc'=>__('Adds an extra server-level barrier around sensitive files and paths.','tegatai-secure'),'tab'=>'server','action'=>__('Review Server Rules','tegatai-secure')];
                  }
                  if (empty($ops['enable_auto_backup'])) {
                    $recommendations[] = ['level'=>'recommended','title'=>__('Review automated backups','tegatai-secure'),'desc'=>__('A recent recoverable backup is an important part of a complete security strategy.','tegatai-secure'),'tab'=>'backups','action'=>__('Review Backups','tegatai-secure')];
                  }
                  if (empty($ops['enable_auto_quarantine'])) {
                    $recommendations[] = ['level'=>'optional','title'=>__('Automatic Quarantine is disabled','tegatai-secure'),'desc'=>__('Optional: enable it if you want high-confidence detections to be isolated automatically.','tegatai-secure'),'tab'=>'malware','action'=>__('Configure','tegatai-secure')];
                  }
                  $recommendations = array_slice($recommendations, 0, 3);
                  $score_breakdown = [
                    __('Core protection modules','tegatai-secure') => (int)round(($enabled/count($protection))*70),
                    __('Server hardening','tegatai-secure') => (int)(!empty($ops['server_protect_files']) ? 8 : 0) + (int)(!empty($ops['server_hide_system_files']) ? 5 : 0) + (int)(!empty($ops['server_block_dotfiles']) ? 5 : 0),
                    __('Backups','tegatai-secure') => !empty($ops['enable_auto_backup']) ? 5 : 0,
                    __('Recent activity','tegatai-secure') => ($fails_24h===0 ? 4 : 0) + ($blocks_24h<100 ? 3 : 0),
                  ];
                ?>

                <div class="teg-dashboard-hero">
                    <div class="teg-status-card">
                        <div class="teg-status-label"><?php echo esc_html__('Security Status','tegatai-secure'); ?></div>
                        <div class="teg-status-main">
                            <div class="teg-score <?php echo esc_attr($score_class); ?>" style="border-color:<?php echo esc_attr($status_color); ?>33;">
                                <strong><?php echo esc_html($score); ?></strong><small><?php echo esc_html__('score','tegatai-secure'); ?></small>
                            </div>
                            <div>
                                <div class="teg-status-name"><?php echo esc_html($status); ?></div>
                                <div class="teg-status-desc"><?php echo esc_html($status_desc); ?></div>
                            </div>
                        </div>
                        <div class="teg-status-meta">
                            <span class="teg-status-chip"><span class="teg-dot" style="background:<?php echo esc_attr($status_color); ?>"></span><?php echo esc_html__('Protection active','tegatai-secure'); ?></span>
                            <span class="teg-status-chip"><?php echo esc_html(sprintf(/* translators: 1: number of enabled modules, 2: number of all modules */ __('%1$d / %2$d modules','tegatai-secure'),$enabled,count($protection))); ?></span>
                        </div>
                        <div class="teg-recommendations">
                            <div class="teg-rec-head">
                                <span class="teg-rec-title"><?php echo esc_html__('Recommended actions','tegatai-secure'); ?></span>
                                <span class="teg-rec-count"><?php echo $recommendations ? esc_html(sprintf(/* translators: %d: number of recommended actions */ _n('%d item','%d items',count($recommendations),'tegatai-secure'),count($recommendations))) : esc_html__('No action required','tegatai-secure'); ?></span>
                            </div>
                            <?php if (empty($recommendations)): ?>
                                <div class="teg-muted" style="padding:8px 0 2px;"><?php echo esc_html__('Tegatai has not detected a configuration issue requiring attention.','tegatai-secure'); ?></div>
                            <?php else: ?>
                                <div class="teg-rec-list">
                                <?php foreach ($recommendations as $rec): ?>
                                    <div class="teg-rec <?php echo esc_attr($rec['level']); ?>">
                                        <span class="teg-rec-dot"></span>
                                        <div class="teg-rec-main">
                                            <div class="teg-rec-titleline"><?php echo esc_html($rec['title']); ?><span class="teg-rec-badge"><?php echo esc_html($rec['level'] === 'important' ? __('Important','tegatai-secure') : ($rec['level'] === 'optional' ? __('Optional','tegatai-secure') : __('Recommended','tegatai-secure'))); ?></span></div>
                                            <div class="teg-rec-desc"><?php echo esc_html($rec['desc']); ?></div>
                                        </div>
                                        <a class="teg-rec-link" href="?page=tegatai-Secure&tab=<?php echo esc_attr($rec['tab']); ?>"><?php echo esc_html($rec['action']); ?> →</a>
                                    </div>
                                <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                            <details class="teg-score-details">
                                <summary><?php echo esc_html__('Why this score?','tegatai-secure'); ?></summary>
                                <div class="teg-score-breakdown">
                                    <?php foreach ($score_breakdown as $label=>$value): ?>
                                        <span><?php echo esc_html($label); ?></span><strong><?php echo esc_html($value); ?></strong>
                                    <?php endforeach; ?>
                                </div>
                            </details>
                        </div>
                    </div>
                    <div class="teg-away-card">
                        <div class="teg-away-head"><div><h3><?php echo esc_html__('While you were away','tegatai-secure'); ?></h3><p><?php echo esc_html__('Recent security activity from the Tegatai event log.','tegatai-secure'); ?></p></div><a class="button button-secondary" href="?page=tegatai-Secure&tab=timeline"><?php echo esc_html__('View all','tegatai-secure'); ?></a></div>
                        <div class="teg-event-list">
                        <?php if(empty($recent)): ?><div class="teg-muted"><?php echo esc_html__('No recent security events.','tegatai-secure'); ?></div>
                        <?php else: foreach($recent as $ev): ?><div class="teg-event"><span class="teg-event-dot"></span><span class="teg-event-time"><?php echo esc_html(wp_date('H:i',$ev['time'])); ?></span><span class="teg-event-msg" title="<?php echo esc_attr($ev['message']); ?>"><?php echo esc_html($ev['message'] ?: __('Security event','tegatai-secure')); ?></span><span class="teg-event-type"><?php echo esc_html($ev['type']); ?></span></div><?php endforeach; endif; ?>
                        </div>
                    </div>
                </div>

                <div class="teg-metric-grid">
                    <div class="teg-metric"><div class="teg-metric-label"><?php echo esc_html__('Blocked total','tegatai-secure'); ?></div><div class="teg-metric-value"><?php echo esc_html(number_format_i18n((int)($stats2['blocked']??0))); ?></div><div class="teg-metric-note"><?php echo esc_html__('All recorded blocks','tegatai-secure'); ?></div></div>
                    <div class="teg-metric"><div class="teg-metric-label"><?php echo esc_html__('Blocks / 24h','tegatai-secure'); ?></div><div class="teg-metric-value"><?php echo esc_html(number_format_i18n($blocks_24h)); ?></div><div class="teg-metric-note"><?php echo esc_html__('Firewall and WAF activity','tegatai-secure'); ?></div></div>
                    <div class="teg-metric"><div class="teg-metric-label"><?php echo esc_html__('Failed logins / 24h','tegatai-secure'); ?></div><div class="teg-metric-value"><?php echo esc_html(number_format_i18n($fails_24h)); ?></div><div class="teg-metric-note"><?php echo esc_html__('Authentication failures','tegatai-secure'); ?></div></div>
                    <div class="teg-metric"><div class="teg-metric-label"><?php echo esc_html__('Modules active','tegatai-secure'); ?></div><div class="teg-metric-value"><?php echo esc_html($enabled . ' / ' . count($protection)); ?></div><div class="teg-metric-note"><?php echo esc_html__('Core protection modules','tegatai-secure'); ?></div></div>
                </div>

                <div class="teg-cockpit-grid">
                    <div class="teg-card teg-dash-card">
                        <h3 class="teg-dash-title"><span class="dashicons dashicons-shield-alt"></span><?php echo esc_html__('Protection cockpit','tegatai-secure'); ?></h3>
                        <p class="teg-dash-sub"><?php echo esc_html__('The protections that matter most on every request.','tegatai-secure'); ?></p>
                        <div class="teg-protection-list">
                        <?php foreach($protection as $k=>$label): $on=!empty($ops[$k]); ?><div class="teg-protection-item"><span class="teg-protection-name"><?php echo esc_html($label); ?></span><span class="teg-mini-status <?php echo $on?'on':'off'; ?>"><?php echo $on?'● '.esc_html__('Active','tegatai-secure'):'○ '.esc_html__('Off','tegatai-secure'); ?></span></div><?php endforeach; ?>
                        </div>
                    </div>
                    <div class="teg-card teg-dash-card">
                        <h3 class="teg-dash-title"><span class="dashicons dashicons-warning"></span><?php echo esc_html__('Top sources / 24h','tegatai-secure'); ?></h3>
                        <p class="teg-dash-sub"><?php echo esc_html__('IPs generating the most security events.','tegatai-secure'); ?></p>
                        <?php if(empty($top_ips)): ?><div class="teg-muted"><?php echo esc_html__('No data yet.','tegatai-secure'); ?></div><?php else: foreach($top_ips as $ip=>$cnt): ?><div class="teg-top-ip"><code><?php echo esc_html($ip); ?></code><strong><?php echo esc_html(number_format_i18n($cnt)); ?></strong></div><?php endforeach; endif; ?>
                    </div>
                </div>

                <div class="teg-section-grid">
                    <?php foreach ($nav_groups as $g_id => $group): $first_tab = array_key_first($group['tabs']); ?>
                        <a href="?page=tegatai-Secure&tab=<?php echo esc_attr($first_tab); ?>" class="teg-section-card">
                            <div class="teg-section-icon"><span class="dashicons <?php echo esc_attr($group['icon']); ?>"></span></div>
                            <div class="teg-section-info"><h3><?php echo esc_html($group['title']); ?></h3><p><?php echo esc_html($group['desc']); ?></p></div>
                        </a>
                    <?php endforeach; ?>
                </div>

            
            <?php else: ?>
                <?php if ($current_group && isset($nav_groups[$current_group])): ?>
                    <div class="teg-inner-nav">
                        <a href="?page=tegatai-Secure&tab=dashboard" class="teg-back-btn">
                            <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Dashboard', 'tegatai-secure'); ?>
                        </a>
                        <div class="teg-horizontal-tabs">
                            <?php foreach ($nav_groups[$current_group]['tabs'] as $t_id => $t_label): ?>
                                <a href="?page=tegatai-Secure&tab=<?php echo esc_attr($t_id); ?>" class="teg-h-tab <?php echo ($tab == $t_id) ? 'active' : ''; ?>">
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

    /** Releases one IP from the IP Prison (local ban list only; other Hive nodes keep their bans). */
    public function handle_unban() {
        if (!current_user_can('manage_options')) wp_die('Access Denied', 403);
        check_admin_referer('tegatai_unban_nonce');
        $ip = sanitize_text_field(wp_unslash($_POST['ip'] ?? ''));
        if (filter_var($ip, FILTER_VALIDATE_IP)) {
            Tegatai_Bans::remove($ip);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('UNBAN', "Released from IP Prison: $ip");
        }
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=bans&msg=released'));
        exit;
    }

    /** IP Prison: all active bans, newest first, with a release button per IP. */
    private function render_bans_tab() {
        $bans = Tegatai_Bans::active();
        $total = count($bans);
        // Newest ban first: the end time is the best available order (bans never get shorter)
        uasort($bans, function ($a, $b) { return (int) $b['until'] <=> (int) $a['until']; });
        $limit = 500;
        $bans = array_slice($bans, 0, $limit, true);
        $msg = isset($_GET['msg']) ? sanitize_key(wp_unslash($_GET['msg'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        $nonce = wp_create_nonce('tegatai_unban_nonce');

        echo '<div class="teg-card">';
        echo '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;"><h3 style="margin:0;">' . esc_html__('IP Prison', 'tegatai-secure') . '</h3><span class="teg-muted">' . esc_html(sprintf(/* translators: %d: number of active bans */ _n('%d active ban', '%d active bans', $total, 'tegatai-secure'), $total)) . '</span></div>';
        if ($msg === 'released') {
            echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:4px; margin-bottom:12px; border:1px solid #bbf7d0; font-size:12px;">' . esc_html__('IP released. Bans from The Hive stay active on the other sites.', 'tegatai-secure') . '</div>';
        }
        if ($total === 0) {
            echo '<div class="teg-muted" style="text-align:center; padding:20px;">' . esc_html__('No active bans.', 'tegatai-secure') . '</div></div>';
            return;
        }
        echo '<div style="max-height:600px; overflow:auto; border:1px solid var(--teg-border); border-radius:6px;"><table class="teg-table"><thead><tr>';
        echo '<th>IP</th><th>' . esc_html__('Reason', 'tegatai-secure') . '</th><th>' . esc_html__('Source', 'tegatai-secure') . '</th><th>' . esc_html__('Level', 'tegatai-secure') . '</th><th>' . esc_html__('Until', 'tegatai-secure') . '</th><th style="text-align:right;">' . esc_html__('Action', 'tegatai-secure') . '</th>';
        echo '</tr></thead><tbody>';
        foreach ($bans as $ip => $b) {
            $source = (string) ($b['source'] ?? 'local');
            $source = strpos($source, 'hive:') === 0 ? 'Hive: ' . substr($source, 5) : __('This site', 'tegatai-secure');
            $until = (int) $b['until'];
            $left = human_time_diff(time(), $until);
            echo '<tr>';
            echo '<td><code>' . esc_html((string) $ip) . '</code></td>';
            echo '<td>' . esc_html((string) ($b['reason'] ?? '')) . '</td>';
            echo '<td>' . esc_html($source) . '</td>';
            echo '<td>' . esc_html((string) ($b['level'] ?? '')) . '</td>';
            echo '<td style="white-space:nowrap;" title="' . esc_attr(gmdate('Y-m-d H:i', $until) . ' UTC') . '">' . esc_html($left) . '</td>';
            echo '<td style="text-align:right;"><form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline;">';
            echo '<input type="hidden" name="action" value="tegatai_unban"><input type="hidden" name="ip" value="' . esc_attr((string) $ip) . '"><input type="hidden" name="_wpnonce" value="' . esc_attr($nonce) . '">';
            echo '<input type="submit" class="button button-secondary" value="' . esc_attr__('Release', 'tegatai-secure') . '"></form></td>';
            echo '</tr>';
        }
        echo '</tbody></table></div>';
        if ($total > $limit) {
            echo '<p class="teg-muted" style="margin-top:10px;">' . esc_html(sprintf(/* translators: 1: shown, 2: total */ __('Showing the newest %1$d of %2$d bans.', 'tegatai-secure'), $limit, $total)) . '</p>';
        }
        echo '</div>';
    }

    /** Status of the local country database on the GeoIP tab. */
    private function render_geoip_db_card() {
        $info = Tegatai_GeoIP::info();
        $msg  = isset($_GET['msg']) ? sanitize_key(wp_unslash($_GET['msg'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- display only
        echo '<div class="teg-card">';
        echo '<h3><span class="dashicons dashicons-database" style="vertical-align:middle;"></span> ' . esc_html__('Country Database', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Countries are looked up locally in the free "IP to Country Lite" database by DB-IP (CC BY 4.0). Visitor IPs never leave the server. The database is only downloaded while the GeoIP block is on, and renewed monthly.', 'tegatai-secure') . '</p>';
        if ($msg === 'geoip_updated') {
            echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:4px; margin-bottom:12px; border:1px solid #bbf7d0; font-size:12px;">' . esc_html__('Database downloaded.', 'tegatai-secure') . '</div>';
        } elseif ($msg === 'geoip_failed') {
            echo '<div style="padding:10px; background:#fee2e2; color:#b91c1c; border-radius:4px; margin-bottom:12px; border:1px solid #fecaca; font-size:12px;">' . esc_html__('Download failed:', 'tegatai-secure') . ' ' . esc_html((string) ($info['last']['error'] ?? '')) . '</div>';
        }
        if ($info['exists']) {
            echo '<table class="teg-table"><tbody>';
            echo '<tr><td>' . esc_html__('Edition', 'tegatai-secure') . '</td><td>' . esc_html($info['built'] ? gmdate('Y-m-d', $info['built']) : '–') . '</td></tr>';
            echo '<tr><td>' . esc_html__('Downloaded', 'tegatai-secure') . '</td><td>' . esc_html(gmdate('Y-m-d H:i', $info['mtime'])) . ' UTC</td></tr>';
            echo '<tr><td>' . esc_html__('Size', 'tegatai-secure') . '</td><td>' . esc_html(size_format($info['size'])) . '</td></tr>';
            echo '</tbody></table>';
        } else {
            $style = Tegatai_GeoIP::enabled() ? 'background:#fef3c7; color:#92400e; border:1px solid #fde68a;' : 'background:#f3f4f6; color:#374151; border:1px solid #e5e7eb;';
            echo '<div style="padding:10px; border-radius:4px; font-size:12px; ' . esc_attr($style) . '">' . esc_html__('No database yet. Until it is downloaded, no country is blocked.', 'tegatai-secure') . '</div>';
        }
        if (!empty($info['last']['time']) && empty($info['last']['ok']) && $msg === '') {
            echo '<p class="teg-switch-desc" style="display:block; margin-top:10px; color:var(--teg-danger);">' . esc_html__('Last download failed:', 'tegatai-secure') . ' ' . esc_html((string) $info['last']['error']) . '</p>';
        }
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:12px;">';
        echo '<input type="hidden" name="action" value="tegatai_geoip_update">';
        echo wp_kses(wp_nonce_field('tegatai_geoip_update', '_wpnonce', true, false), TEGATAI_KSES_INPUT);
        echo '<input type="submit" class="button button-secondary" value="' . esc_attr($info['exists'] ? __('Update now', 'tegatai-secure') : __('Download database', 'tegatai-secure')) . '">';
        echo '</form>';
        echo '</div>';
    }

    // Google reCAPTCHA card (Spam tab). Switching it on switches Cloudflare Turnstile off.
    private function render_recaptcha_card() {
        $ver = $this->get_opt('recaptcha_version') === 'v3' ? 'v3' : 'v2';
        $thr = is_numeric($this->get_opt('recaptcha_threshold')) ? (float) $this->get_opt('recaptcha_threshold') : 0.5;
        echo '<div class="teg-card"><h3>' . esc_html__('Google reCAPTCHA', 'tegatai-secure') . '</h3>';
        $this->render_toggle('enable_recaptcha', esc_html__('Enable reCAPTCHA', 'tegatai-secure'), esc_html__('Google CAPTCHA for login and comments. Switching it on switches Cloudflare Turnstile off.', 'tegatai-secure'));
        echo '<p class="teg-switch-desc">' . esc_html__('Only one captcha can be active: reCAPTCHA or Turnstile.', 'tegatai-secure') . '</p>';
        echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;">';
        echo '<label class="teg-switch-label">' . esc_html__('Type', 'tegatai-secure') . '</label><select name="tegatai_options[recaptcha_version]" class="teg-form-input">';
        echo '<option value="v2"' . selected($ver, 'v2', false) . '>' . esc_html__('v2 – "I\'m not a robot" checkbox', 'tegatai-secure') . '</option>';
        echo '<option value="v3"' . selected($ver, 'v3', false) . '>' . esc_html__('v3 – invisible, score based', 'tegatai-secure') . '</option></select>';
        echo '<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Site Key', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[recaptcha_site_key]" value="' . esc_attr($this->get_opt('recaptcha_site_key')) . '" class="teg-form-input" placeholder="6Lc...">';
        echo '<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Secret Key', 'tegatai-secure') . '</label>' . wp_kses_post($this->secret_note('TEGATAI_RECAPTCHA_SECRET'));
        echo '<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Minimum score (v3 only)', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[recaptcha_threshold]" value="' . esc_attr(number_format($thr, 1, '.', '')) . '" min="0.1" max="0.9" step="0.1" class="teg-form-input">';
        echo '<p class="teg-switch-desc">' . esc_html__('0.1 lets almost everyone through, 0.9 is very strict. Google recommends 0.5. The key type (v2 or v3) must match the type selected above.', 'tegatai-secure') . '</p>';
        echo '<input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div>';
    }

    private function render_toggle($key, $label, $desc = '') {
        $val = $this->get_opt($key);
        // reCAPTCHA wins when both flags are set (old settings): show Turnstile as off
        if ($key === 'enable_turnstile' && $this->get_opt('enable_recaptcha')) $val = 0;
        $checked = $val ? 'checked' : '';
        echo "<div class='teg-switch-row'><div><span class='teg-switch-label'>" . wp_kses_post($label);
        if ($desc) echo " <span class='dashicons dashicons-info-outline teg-help-icon' title='" . esc_attr(wp_strip_all_tags($desc)) . "'></span>";
        echo "</span></div><label class='switch'><input type='checkbox' class='teg-toggle-checkbox' data-teg-key='" . esc_attr($key) . "' onchange=\"tegToggle('" . esc_attr(esc_js($key)) . "', this)\"" . ($checked ? ' checked' : '') . "><span class='slider'></span></label></div>";
    }

    private function render_full_tabs($tab) {
        if ($tab == 'firewall') { echo '
<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('WAF Settings', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_waf', esc_html__('Enable WAF', 'tegatai-secure'), esc_html__('Activates the Web Application Firewall to block malicious requests.', 'tegatai-secure')); $this->render_toggle('block_fake_bots', esc_html__('Block Bad Bots', 'tegatai-secure'), esc_html__('Blocks known malicious bots, scrapers, and automated attack tools.', 'tegatai-secure')); $this->render_toggle('enable_rate_limit', esc_html__('Rate Limit', 'tegatai-secure'), esc_html__('Prevents brute-force attacks by limiting requests per minute.', 'tegatai-secure')); $this->render_toggle('enable_404_block', esc_html__('404 Trap', 'tegatai-secure'), esc_html__('Bans IPs that generate too many 404 Not Found errors.', 'tegatai-secure')); $this->render_toggle('enable_upload_guard', esc_html__('Upload Guard', 'tegatai-secure'), esc_html__('Blocks uploads of executable or disguised script files.', 'tegatai-secure')); $this->render_toggle('block_ai_bots', esc_html__('Block AI Bots', 'tegatai-secure'), esc_html__('Stops OpenAI, ChatGPT, and other AI scrapers from crawling your content.', 'tegatai-secure')); $this->render_toggle('block_seo_bots', esc_html__('Block SEO Bots', 'tegatai-secure'), esc_html__('Blocks aggressive SEO crawlers like Ahrefs or Semrush.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('WAF Whitelist', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Allowed URLs', 'tegatai-secure') . '</label><textarea name="tegatai_options[waf_whitelist_urls]" class="teg-form-input">'.esc_textarea($this->get_opt('waf_whitelist_urls', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Custom Rules', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Custom Regex Filters', 'tegatai-secure') . '</label><p class="teg-switch-desc">' . wp_kses_post(__('One regex per line (e.g., <code>/bad-bot/i</code>).', 'tegatai-secure')) . '</p><textarea name="tegatai_options[custom_waf_blocklist]" class="teg-form-input">'.esc_textarea($this->get_opt('custom_waf_blocklist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('IP Lists', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Whitelist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[whitelist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('whitelist_ips', '')).'</textarea><label class="teg-switch-label">' . esc_html__('Blacklist IPs', 'tegatai-secure') . '</label><textarea name="tegatai_options[blacklist_ips]" class="teg-form-input">'.esc_textarea($this->get_opt('blacklist_ips', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; $this->render_abuseipdb_card(); }
        elseif ($tab == 'masking') { $this->render_mask_tab(); }
        elseif ($tab == 'server') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Server Rules', 'tegatai-secure') . '</h3>'; $this->render_toggle('server_disable_indexing', esc_html__('Disable Directory Browsing', 'tegatai-secure'), esc_html__('Prevents attackers from seeing lists of your files.', 'tegatai-secure')); $this->render_toggle('server_protect_files', esc_html__('Protect Sensitive Files', 'tegatai-secure'), esc_html__('Blocks access to .env, .sql, .bak, .log, and .git files.', 'tegatai-secure')); $this->render_toggle('server_hide_system_files', esc_html__('Block System Files', 'tegatai-secure'), esc_html__('Hides readme.html, license.txt, and wp-config.php from the web.', 'tegatai-secure')); $this->render_toggle('server_block_dotfiles', esc_html__('Block Dotfiles', 'tegatai-secure'), esc_html__('Denies access to hidden files (e.g., .htaccess).', 'tegatai-secure')); $this->render_toggle('server_block_xmlrpc', esc_html__('Block XML-RPC', 'tegatai-secure'), esc_html__('Disables xmlrpc.php to prevent DDoS and brute-force attacks.', 'tegatai-secure')); $this->render_toggle('server_disable_php_uploads', esc_html__('Disable PHP in Uploads', 'tegatai-secure'), esc_html__('Prevents execution of malicious backdoors in your media folder.', 'tegatai-secure')); $this->render_toggle('server_filter_bad_bots', esc_html__('Ultimate Bad Bot Filter', 'tegatai-secure'), esc_html__('Strict Nginx-level blocking for hacking tools.', 'tegatai-secure')); $this->render_toggle('server_hotlink_protection', esc_html__('Hotlink Protection', 'tegatai-secure'), esc_html__('Prevents other sites from embedding your images and stealing bandwidth.', 'tegatai-secure')); $this->render_rules_status(); echo '<div style="background:#f9fafb; padding:12px; border-radius:6px; margin-top:16px; border:1px solid #e5e7eb;"><form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="tegatai_write_rules">'.wp_kses(wp_nonce_field('tegatai_write_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT).'<input type="submit" class="button button-primary" value="' . esc_attr__('Write rules to config', 'tegatai-secure') . '" ></form></div></div><div class="teg-card"><h3>' . esc_html__('Custom Protection', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Protected Directories', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[server_protected_dirs]" value="'.esc_attr($this->get_opt('server_protected_dirs', '')).'" class="teg-form-input">
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Block Specific Files', 'tegatai-secure') . '</label>
<p class="teg-switch-desc">' . wp_kses_post(__('Paths from root (e.g., <code>/secret.zip</code>).', 'tegatai-secure')) . '</p>
<textarea name="tegatai_options[server_custom_files_list]" class="teg-form-input" placeholder="/geheim.zip&#10;/custom/info.php">'.esc_textarea($this->get_opt('server_custom_files_list', '')).'</textarea>
<label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Hotlink Whitelist', 'tegatai-secure') . '</label><textarea name="tegatai_options[server_hotlink_whitelist]" class="teg-form-input">'.esc_textarea($this->get_opt('server_hotlink_whitelist', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" style="margin-top:8px;" ></form></div></div>'; }
        elseif ($tab == 'login') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Login Protection', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_login_limit', esc_html__('Login Limit', 'tegatai-secure'), esc_html__('Locks out IPs after multiple failed login attempts.', 'tegatai-secure')); $this->render_toggle('disable_app_passwords', esc_html__('Disable App Passwords', 'tegatai-secure'), esc_html__('Turns off the WordPress application passwords feature.', 'tegatai-secure'));
        $this->render_toggle('enable_trusted_devices', esc_html__('Trusted Devices', 'tegatai-secure'), esc_html__('Warns via email upon logins from unknown devices.', 'tegatai-secure')); $this->render_toggle('block_default_login', esc_html__('Block wp-login.php', 'tegatai-secure'), esc_html__('Disables the default login route (requires Custom Slug).', 'tegatai-secure')); $this->render_toggle('block_wp_admin_hide', esc_html__('Hide /wp-admin/', 'tegatai-secure'), esc_html__('Redirects unauthenticated users away from the admin area.', 'tegatai-secure')); $this->render_toggle('block_dash_access', esc_html__('Restrict Dashboard', 'tegatai-secure'), esc_html__('Only administrators and editors may access the WordPress dashboard.', 'tegatai-secure')); $this->render_toggle('enable_idle_logout', esc_html__('Idle Logout (60m)', 'tegatai-secure'), esc_html__('Automatically logs out inactive administrators after 60 minutes.', 'tegatai-secure')); echo '</div><div class="teg-card"><h3>' . esc_html__('Custom Login Slug', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><input type="text" name="tegatai_options[custom_login_slug]" value="'.esc_attr($this->get_opt('custom_login_slug', '')).'" class="teg-form-input" placeholder="mein-login"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div>'; $this->render_notifications_card(); $this->render_2fa_card(); echo '</div>'; }
        elseif ($tab == 'spam') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Spam & Bots', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_honeypot', esc_html__('Enable Honeypot', 'tegatai-secure'), esc_html__('Adds an invisible field to catch automated spam bots.', 'tegatai-secure')); $this->render_toggle('enable_bot_timer', esc_html__('Minimum Fill Time', 'tegatai-secure'), esc_html__('Blocks forms submitted too quickly.', 'tegatai-secure')); $this->render_toggle('spam_check_referrer', esc_html__('Referrer Check', 'tegatai-secure'), esc_html__('Ensures form submissions come from your own site.', 'tegatai-secure')); $this->render_toggle('spam_block_trashmail', esc_html__('Block Trash Mails', 'tegatai-secure'), esc_html__('Rejects disposable email addresses during registration.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Max. Links', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[spam_max_links]" value="'.esc_attr($this->get_opt('spam_max_links')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card"><h3>' . esc_html__('Cloudflare Turnstile', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_turnstile', esc_html__('Enable Turnstile', 'tegatai-secure'), esc_html__('Privacy-friendly Cloudflare CAPTCHA for login and comments.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:10px;"><label class="teg-switch-label">' . esc_html__('Site Key', 'tegatai-secure') . '</label><input type="text" name="tegatai_options[turnstile_site_key]" value="'.esc_attr($this->get_opt('turnstile_site_key')).'" class="teg-form-input" placeholder="0x4A..."><label class="teg-switch-label" style="margin-top:10px;">' . esc_html__('Secret Key', 'tegatai-secure') . '</label>' . wp_kses_post($this->secret_note('TEGATAI_TURNSTILE_SECRET')) . '<input type="submit" class="button button-primary" style="margin-top:10px;" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div>'; $this->render_recaptcha_card(); echo '</div>'; }
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
            echo '<p class="teg-switch-desc">' . esc_html__('One code per line (e.g. DE, AT).', 'tegatai-secure') . '</p>';
            echo '<textarea name="tegatai_options[geoip_list]" class="teg-form-input" placeholder="DE&#10;AT" style="min-height: 120px;">'.esc_textarea($this->get_opt('geoip_list', '')).'</textarea>';
            echo '<input type="submit" class="button button-primary" value="' . esc_attr__('Save Codes', 'tegatai-secure') . '">';
            echo '</form>';
            echo '</div>';
            $this->render_geoip_db_card();
            echo '</div>';
        }
        elseif ($tab == 'hardening') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('System', 'tegatai-secure') . '</h3>'; $this->render_toggle('hide_wp_version', esc_html__('Hide WP Version', 'tegatai-secure'), esc_html__('Removes the WordPress version number from your source code.', 'tegatai-secure')); $this->render_toggle('disable_xmlrpc', esc_html__('Disable XML-RPC', 'tegatai-secure'), esc_html__('Turns off the XML-RPC API internally.', 'tegatai-secure')); $this->render_toggle('disable_file_editor', esc_html__('Disable File Editor', 'tegatai-secure'), esc_html__('Prevents editing plugins and themes via the WP dashboard.', 'tegatai-secure')); $this->render_toggle('block_user_enum', esc_html__('Block Enumeration', 'tegatai-secure'), esc_html__('Stops attackers from discovering your usernames.', 'tegatai-secure')); $this->render_toggle('hide_login_errors', esc_html__('Hide Login Errors', 'tegatai-secure'), esc_html__('Shows a generic message instead of revealing whether the username or password was wrong.', 'tegatai-secure'));
        echo '<hr style="margin:16px 0; border:0; border-top:1px solid #f1f5f9;">';
        $this->render_toggle('enable_admin_honeypot', esc_html__('Admin Honeypot', 'tegatai-secure'), esc_html__('Permanently bans anyone trying to log in as admin.', 'tegatai-secure'));
        $this->render_toggle('enable_role_guard', esc_html__('Privilege Guard', 'tegatai-secure'), esc_html__('Prevents unauthorized users from upgrading to Administrator.', 'tegatai-secure')); echo '</div>';
        
        // --- CARD 4: Deep Clean (fixed quotes) ---
        echo '<div class="teg-card" style="grid-column: 1 / -1;">';
        echo '<h3><span class="dashicons dashicons-database" style="vertical-align:middle;"></span> ' . esc_html__('System Deep Clean', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . wp_kses_post(__('Manual database cleanup. Deletes expired transients, spam comments, old post revisions, and optimizes table overhead.', 'tegatai-secure')) . '</p>';
        echo '<button id="teg-run-clean" class="button button-primary"><span class="dashicons dashicons-update-alt" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Run Deep Clean', 'tegatai-secure') . '</button>';
        echo '<div id="teg-clean-results" style="display:none; margin-top:12px; padding:12px; background:#f0fdf4; border:1px solid #bbf7d0; border-radius:6px; color:#166534; font-size:12px; line-height:1.6;"></div>';
        echo '</div>'; 
        echo '</div>'; 
        }
        elseif ($tab == 'headers') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('HTTP Security Headers', 'tegatai-secure') . '</h3>'; $this->render_toggle('header_xfo', esc_html__('X-Frame-Options', 'tegatai-secure'), esc_html__('Clickjacking protection.', 'tegatai-secure')); $this->render_toggle('header_nosniff', esc_html__('X-Content-Type-Options', 'tegatai-secure'), esc_html__('Stops browsers from MIME-sniffing.', 'tegatai-secure')); $this->render_toggle('header_xss', esc_html__('X-XSS-Protection', 'tegatai-secure'), esc_html__('Enables legacy browser XSS filtering.', 'tegatai-secure')); $this->render_toggle('header_hsts', esc_html__('HSTS (SSL)', 'tegatai-secure'), esc_html__('Enforces strict HTTPS connections.', 'tegatai-secure')); $this->render_toggle('header_hsts_subdomains', esc_html__('HSTS: include subdomains', 'tegatai-secure'), esc_html__('Only enable if ALL subdomains are reachable via HTTPS, otherwise they become unreachable for a year.', 'tegatai-secure')); $this->render_toggle('header_ref', esc_html__('Referrer Policy', 'tegatai-secure'), esc_html__('Controls referrer information.', 'tegatai-secure')); $this->render_toggle('header_permissions', esc_html__('Permissions-Policy', 'tegatai-secure'), esc_html__('Restricts access to browser features (camera, mic).', 'tegatai-secure')); $this->render_toggle('header_csp', esc_html__('Content Security Policy (basic)', 'tegatai-secure'), esc_html__('Permissive baseline policy: restricts resources to HTTPS/same origin and blocks plain-HTTP content. It allows inline scripts and eval, so it does NOT protect against XSS.', 'tegatai-secure')); echo '</div></div>'; }
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
        // Encryption status: v3 key pair (like the Hive node key) or AES-256-GCM with TEGATAI_BACKUP_SECRET
        $bkeys = Tegatai_Backup::own_keys();
        echo '<hr style="margin:16px 0; border:0; border-top:1px solid #eee;">';
        echo '<label class="teg-switch-label">' . esc_html__('Encryption', 'tegatai-secure') . '</label>';
        if ($bkeys['public'] !== '') {
            echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:4px; border:1px solid #bbf7d0; font-size:12px; margin-top:6px;">🔒 ' . esc_html__('Backup key loaded: X25519 + XChaCha20-Poly1305.', 'tegatai-secure') . ($bkeys['secret'] === '' ? ' ' . esc_html__('Only the public key is on this server: new backups are encrypted, but can only be downloaded decrypted with the private key.', 'tegatai-secure') : '') . '</div>';
        } else {
            echo '<div style="padding:10px; background:#f3f4f6; color:#374151; border-radius:4px; border:1px solid #e5e7eb; font-size:12px; margin-top:6px;">' . esc_html__('No backup key pair: backups use XChaCha20-Poly1305 with a key derived from TEGATAI_BACKUP_SECRET (secrets file). For a key pair (recommended), run this on the server as the site\'s PHP-FPM user (not as root). Tegatai never writes key files itself:', 'tegatai-secure') . '<br><code style="word-break:break-all;">' . esc_html(Tegatai_Backup::keygen_command()) . '</code>' . (tegatai_secret('TEGATAI_BACKUP_SECRET') === '' ? '<br><strong style="color:#b91c1c;">' . esc_html__('Neither a key pair nor TEGATAI_BACKUP_SECRET is set: backups cannot be created yet.', 'tegatai-secure') . '</strong>' : '') . '</div>';
        }
        echo '</div>';
        
        echo '<div class="teg-card" style="grid-column: span 2;">';
        echo '<h3>' . esc_html__('Local Backups', 'tegatai-secure') . '</h3>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        echo '<input type="hidden" name="action" value="tegatai_create_backup">';
        wp_nonce_field('tegatai_backup_nonce', '_wpnonce', true, true);
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
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline; margin-right: 4px;">';
                echo '<input type="hidden" name="action" value="tegatai_download_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce('tegatai_backup_nonce') ) . '">';
                echo '<input type="submit" class="button button-secondary" value="' . esc_attr__('DL', 'tegatai-secure') . '" >';
                echo '</form>';
                
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline;">';
                echo '<input type="hidden" name="action" value="tegatai_delete_backup">';
                echo '<input type="hidden" name="file" value="' . esc_attr($b['name']) . '">';
                echo '<input type="hidden" name="_wpnonce" value="' . esc_attr( wp_create_nonce('tegatai_backup_nonce') ) . '">';
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
        
        // The former "Remote FTP" card was removed: there was never an upload implementation or
        // save handler, and the form echoed decrypted credentials into the page source.
        
        echo '</div>'; 
    }
        elseif ($tab == 'scanner') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Malware & Integrity Scanner', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('enable_auto_quarantine', esc_html__('Auto-Quarantine (IPS)', 'tegatai-secure'), esc_html__('Automatically moves detected malware to a safe location.', 'tegatai-secure')); 
        // External service: off by default, only runs after the administrator opts in
        $this->render_toggle('enable_vuln_check', esc_html__('Daily vulnerability check (WPVulnerability)', 'tegatai-secure'), esc_html__('Off by default. When enabled, the slugs of your installed plugins are sent once a day to wpvulnerability.net to look up known vulnerabilities. No other data is sent.', 'tegatai-secure')); 
        $status = get_option('tegatai_scan_status'); $is_running = isset($status['running']) && $status['running']; if ($is_running) { echo '<div style="padding:16px; background:#e0f2fe; border:1px solid #bae6fd; color:#0369a1; border-radius:6px; margin-bottom:16px;">' . esc_html__('Scan running...', 'tegatai-secure') . '</div>'; $scan_token = isset($status['scan_token']) ? (string)$status['scan_token'] : ''; $is_stale = empty($status['start_time']) || (time() - intval($status['start_time'])) > HOUR_IN_SECONDS; if ($scan_token !== '' && !$is_stale) { echo '<div data-tegatai-continue="' . esc_url(add_query_arg(['action' => 'tegatai_scan_process', 'scan_token' => rawurlencode($scan_token)], admin_url('admin-post.php'))) . '"></div>'; } echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="tegatai_scan_reset">'.wp_kses(wp_nonce_field('tegatai_scan_reset_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT).'<input type="submit" class="button button-secondary" value="' . esc_attr__('Abort / reset scan', 'tegatai-secure') . '" data-tegatai-confirm="' . esc_attr__('Abort the running scan and reset its state?', 'tegatai-secure') . '"></form>'; } else { echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'"><input type="hidden" name="action" value="tegatai_scan_start">'.wp_kses(wp_nonce_field('tegatai_scan_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT).'<input type="submit" class="button button-primary" value="' . esc_attr__('Start New Scan', 'tegatai-secure') . '"  style="padding:8px 16px;"></form>';

echo '<form method="post" action="'.esc_url(admin_url('admin-post.php')).'" style="display:inline-block; margin-top:8px;">
<input type="hidden" name="action" value="tegatai_scan_snapshot">
' . wp_kses(wp_nonce_field('tegatai_scan_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT) . '
<input type="submit"
class="button button-secondary"
value="📸 ' . esc_attr__('Create File Snapshot', 'tegatai-secure') . '"
style="padding:8px 16px;"
data-tegatai-confirm="' . esc_attr__('Save current state as a safe baseline?', 'tegatai-secure') . '">
</form>';
    } if (isset($status['last_scan'])) { echo '<hr style="margin:16px 0; border:0; border-top:1px solid #eee;">'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:8px; font-size:12px;"><strong>' . esc_html__('Last Result:', 'tegatai-secure') . '</strong> <span>' . esc_html($status['last_scan']) . '</span></div>'; echo '<div style="display:flex; justify-content:space-between; margin-bottom:16px; font-size:12px;"><strong>' . esc_html__('Files Checked:', 'tegatai-secure') . '</strong> <span>' . intval($status['files_checked']) . '</span></div>'; if (!empty($status['bad_files'])) { echo '<table class="teg-table"><thead><tr><th>Datei</th><th>' . esc_html__('Issue', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach ($status['bad_files'] as $bad) echo '<tr><td style="color:var(--teg-danger);">' . esc_html($bad['file']) . '</td><td>' . esc_html($bad['issue']) . '</td></tr>'; echo '</tbody></table>'; } else { echo '<div style="padding:12px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px;">✅ Sauber.</div>'; } } echo '</div><div class="teg-card"><h3>' . esc_html__('Scanner Configuration', 'tegatai-secure') . '</h3><form onsubmit="tegSaveForm(this, event)"><label class="teg-switch-label">' . esc_html__('Exclude from Scan', 'tegatai-secure') . '</label><textarea name="tegatai_options[scanner_exclusions]" class="teg-form-input" placeholder="/wp-content/cache/">'.esc_textarea($this->get_opt('scanner_exclusions', '')).'</textarea><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div></div>'; }
        elseif ($tab == 'sessions') { echo '<div class="teg-grid"><div class="teg-card"><h3>' . esc_html__('Session Security', 'tegatai-secure') . '</h3>'; $this->render_toggle('enable_ip_guard', esc_html__('IP Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users IP address changes.', 'tegatai-secure')); $this->render_toggle('enable_browser_guard', esc_html__('Browser Guard', 'tegatai-secure'), esc_html__('Invalidates the session if the users browser changes.', 'tegatai-secure')); $this->render_toggle('enable_single_session', esc_html__('Single Session', 'tegatai-secure'), esc_html__('Allows only one active session per user; older sessions are logged out.', 'tegatai-secure')); echo '<form onsubmit="tegSaveForm(this, event)" style="margin-top:16px;"><label class="teg-switch-label">' . esc_html__('Max Session (Min)', 'tegatai-secure') . '</label><input type="number" name="tegatai_options[session_max_lifetime]" value="'.esc_attr($this->get_opt('session_max_lifetime')).'" class="teg-form-input"><input type="submit" class="button button-primary" value="' . esc_attr__('Save', 'tegatai-secure') . '" ></form></div><div class="teg-card" style="grid-column: 1 / -1;"><h3>' . esc_html__('Active Sessions', 'tegatai-secure') . '</h3><div style="overflow-x:auto;"><table class="teg-table"><thead><tr><th>' . esc_html__('User', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Browser', 'tegatai-secure') . '</th><th>' . esc_html__('Action', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_SessionManager::get_all_sessions() as $s): echo "<tr><td>".esc_html($s['username'])."</td><td><code>".esc_html($s['ip'])."</code></td><td><span style='font-size:11px; color:#666;'>".esc_html(substr($s['ua'],0,40))."...</span></td><td><form method='post' action='".esc_url(admin_url('admin-post.php'))."'><input type='hidden' name='action' value='tegatai_kill_session'><input type='hidden' name='user_id' value='".(int) $s['user_id']."'><input type='hidden' name='verifier' value='".esc_attr($s['verifier'])."'><input type='hidden' name='_wpnonce' value='".esc_attr(wp_create_nonce('tegatai_session_nonce'))."'><input type='submit' class='button button-secondary' style='color:var(--teg-danger);' value='" . esc_attr__('Kill', 'tegatai-secure') . "'></form></td></tr>"; endforeach; echo '</tbody></table></div></div></div>'; }
        elseif ($tab == 'bans') { $this->render_bans_tab(); }
        elseif ($tab == 'secrets') { $this->render_secrets_tab(); }
        elseif ($tab == 'extras') { 
        echo '<div class="teg-grid">';
        
        echo '<div class="teg-card">';
        echo '<h3>' . esc_html__('Extras & API', 'tegatai-secure') . '</h3>'; 
        $this->render_toggle('disable_rest_api', esc_html__('Restrict REST API', 'tegatai-secure'), esc_html__('Requires authentication for REST endpoints.', 'tegatai-secure')); 
        $this->render_toggle('enable_rightclick_disable', esc_html__('Disable Right-Click', 'tegatai-secure'), esc_html__('Prevents basic right-clicking.', 'tegatai-secure')); 
        $this->render_toggle('enable_copy_protection', esc_html__('Enable Copy Protection', 'tegatai-secure'), esc_html__('Stops users from copying text.', 'tegatai-secure')); 
        echo '</div>';
        
        echo '<div class="teg-card" style="grid-column: 1 / -1;">';
        echo '<h3 style="border-bottom:1px solid #e5e7eb; padding-bottom:10px;"><span class="dashicons dashicons-download"></span> ' . esc_html__('Configuration Export & Import', 'tegatai-secure') . '</h3>';
        
        echo '<div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap:16px;">';
        
        echo '<div style="background:#f9fafb; padding:16px; border-radius:6px; border:1px solid #e5e7eb;">';
        echo '<h4>' . esc_html__('Export Settings', 'tegatai-secure') . '</h4>';
        echo '<p style="font-size:11px; color:#6b7280; margin-bottom:12px;">' . esc_html__('Downloads a .json file with all settings.', 'tegatai-secure') . '</p>';
        echo '<a href="' . esc_url(admin_url('admin-post.php?action=tegatai_export_config&_wpnonce=' . wp_create_nonce('tegatai_export_nonce'))) . '" class="button button-secondary"><span class="dashicons dashicons-download" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Download (.json)', 'tegatai-secure') . '</a>';
        echo '</div>';
        
        echo '<div style="background:#f9fafb; padding:16px; border-radius:6px; border:1px solid #e5e7eb;">';
        echo '<h4>' . esc_html__('Import Settings', 'tegatai-secure') . '</h4>';
        echo '<p style="font-size:11px; color:#6b7280; margin-bottom:12px;">' . esc_html__('Select a .json file to apply instantly.', 'tegatai-secure') . '</p>';
        echo '<input type="file" id="teg-import-file" accept=".json" style="margin-bottom:8px; font-size:12px; max-width:100%;">';
        echo '<br><button id="teg-run-import" class="button button-primary"><span class="dashicons dashicons-upload" style="vertical-align:middle; margin-top:3px;"></span> ' . esc_html__('Import', 'tegatai-secure') . '</button>';
        echo '</div>';
        
        echo '</div>'; 
        
        
        echo '</div>'; 
        
        echo '</div>'; 
    }
        elseif ($tab == 'logs') { echo '<div class="teg-card"><div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;"><h3>' . esc_html__('Live Traffic Log', 'tegatai-secure') . '</h3><form method="post"><input type="hidden" name="tegatai_action" value="clear_logs">'.wp_kses(wp_nonce_field('tegatai_act_nonce', '_wpnonce', true, false), TEGATAI_KSES_INPUT).'<input type="submit" class="button button-secondary" value="' . esc_attr__('Clear Logs', 'tegatai-secure') . '"  data-tegatai-confirm="' . esc_attr(__('Are you sure?', 'tegatai-secure')) . '"></form></div><div style="max-height:600px; overflow-y:auto; border:1px solid var(--teg-border); border-radius:6px;"><table class="teg-table"><thead><tr><th>' . esc_html__('Time', 'tegatai-secure') . '</th><th>' . esc_html__('Type', 'tegatai-secure') . '</th><th>IP</th><th>' . esc_html__('Message', 'tegatai-secure') . '</th></tr></thead><tbody>'; foreach(Tegatai_Logger::get_logs(200) as $l): $c = in_array($l['type'], ['WAF','FLOOD','BAN-404','AUTH-BAN','SPAM','GEO-BLK'])?'var(--teg-danger)':'var(--teg-text)'; echo "<tr><td>".esc_html($l['time'])."</td><td style='font-weight:bold; color:".esc_attr($c).";'>".esc_html($l['type'])."</td><td><code>".esc_html($l['ip'])."</code></td><td>".esc_html($l['message'])."</td></tr>"; endforeach; echo '</tbody></table></div></div>'; }
    
        elseif ($tab == 'fim') {
            if (isset($_POST['tegatai_fim_build']) && function_exists('check_admin_referer') && check_admin_referer('tegatai_fim_build')) {
                if (class_exists('Tegatai_FIM')) {
                    Tegatai_FIM::build_snapshot();
                    echo '<div class="notice notice-success is-dismissible"><p>' . esc_html__('Baseline snapshot created.', 'tegatai-secure') . '</p></div>';
                }
            }

            $res = null;
            if (isset($_POST['tegatai_fim_check']) && function_exists('check_admin_referer') && check_admin_referer('tegatai_fim_check')) {
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
            wp_nonce_field('tegatai_fim_build', '_wpnonce', true, true);
            echo '<button class="button button-secondary" name="tegatai_fim_build" value="1">' . esc_html__('Create baseline', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post">';
            wp_nonce_field('tegatai_fim_check', '_wpnonce', true, true);
            echo '<button class="button button-primary" name="tegatai_fim_check" value="1">' . esc_html__('Check now', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '</div>';

            echo '<p class="teg-muted" style="margin-top:10px; font-size:11px;">' . esc_html(sprintf(/* translators: %s: date and time of the last run */ __('Last run: %s', 'tegatai-secure'), $lt)) . '</p>';

            if (is_array($res) && !empty($res['ok'])) {
                $c_changed = is_array($res['changed'] ?? null) ? count($res['changed']) : 0;
                $c_new     = is_array($res['new'] ?? null) ? count($res['new']) : 0;
                $c_del     = is_array($res['deleted'] ?? null) ? count($res['deleted']) : 0;

                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-danger);">'.(int) $c_changed.'</span><span class="teg-stat-label">Changed</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-primary);">'.(int) $c_new.'</span><span class="teg-stat-label">New</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="color:var(--teg-muted);">'.(int) $c_del.'</span><span class="teg-stat-label">Deleted</span></div>';
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
            if (isset($_POST['tegatai_dbscan_run']) && function_exists('check_admin_referer') && check_admin_referer('tegatai_dbscan_run')) {
                if (class_exists('Tegatai_DBScan')) {
                    $result = Tegatai_DBScan::scan_stored_xss(200);
                }
            }

            echo '<div class="teg-grid">';
            echo '<div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('Stored-XSS Database Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:12px;">' . esc_html__('Read-only scan of common WP tables for suspicious HTML/JS patterns.', 'tegatai-secure') . '</p>';

            echo '<form method="post">';
            wp_nonce_field('tegatai_dbscan_run', '_wpnonce', true, true);
            echo '<button class="button button-primary" name="tegatai_dbscan_run" value="1">' . esc_html__('Run scan', 'tegatai-secure') . '</button>';
            echo '</form>';

            if (is_array($result)) {
                $hits = $result['hits'] ?? [];
                
                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num" style="font-size:16px;">'.esc_html($result['prefix']).'</span><span class="teg-stat-label">Prefix</span></div>';
                echo '<div class="teg-stat-box"><span class="teg-stat-num">'.(int) $result['rows_checked'].'</span><span class="teg-stat-label">Rows Checked</span></div>';
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
            $limit = isset($_POST['tegatai_mw_limit']) ? intval($_POST['tegatai_mw_limit']) : 1200;
            if ($limit < 200) $limit = 200;
            if ($limit > 3000) $limit = 3000;

            $result = null;

            
            // A new incremental pass starts with empty hits; until it has results, show the last complete pass.
            $mw_current = function () {
                $prog = get_option('tegatai_mw_progress_v1', []);
                $last = get_option('tegatai_mw_last_result_v1', []);
                if (is_array($prog) && (!empty($prog['hits']) || !empty($prog['done']) || empty($last))) return $prog;
                return is_array($last) ? $last : [];
            };
            if (isset($_POST['tegatai_mw_quarantine']) && check_admin_referer('tegatai_mw_quarantine')) {
                $prog = $mw_current();
                $hits_q = isset($prog['hits']) && is_array($prog['hits']) ? $prog['hits'] : [];
                $count_ok = 0; $count_fail = 0;
                if (class_exists('Tegatai_Malware_Scanner')) {
                    foreach ($hits_q as $h) {
                        $r = Tegatai_Malware_Scanner::quarantine_hit(is_array($h) ? $h : []);
                        if (!empty($r['ok'])) { $count_ok++; } else { $count_fail++; }
                        if (($count_ok + $count_fail) >= 50) { break; }
                    }
                }
                echo '<div style="padding:10px; background:#fffbeb; color:#b45309; border:1px solid #fde68a; border-radius:6px; margin-bottom:15px; font-size:12px;">' . esc_html(sprintf(/* translators: 1: number of quarantined files, 2: number of failures */ __('Quarantine done: %1$d ok, %2$d failed (max 50 per click).', 'tegatai-secure'), $count_ok, $count_fail)) . '</div>';
            }
            if (isset($_POST['tegatai_mw_reset']) && check_admin_referer('tegatai_mw_reset')) {
                if (class_exists('Tegatai_Malware_Scanner')) { Tegatai_Malware_Scanner::reset(); }
                echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; margin-bottom:15px; border:1px solid #bbf7d0; font-size:12px;">' . esc_html__('State reset.', 'tegatai-secure') . '</div>';
            }

            if (isset($_POST['tegatai_mw_run']) && check_admin_referer('tegatai_mw_run')) {
                if (class_exists('Tegatai_Malware_Scanner')) {
                    $result = Tegatai_Malware_Scanner::run(['limit' => $limit, 'reset' => !empty($_POST['tegatai_mw_fresh'])]);
                }
            } else {
                $result = $mw_current() ?: null;
            }

            echo '<div class="teg-grid"><div class="teg-card" style="grid-column: span 2;">';
            echo '<h3>' . esc_html__('Malware / Backdoor Scanner', 'tegatai-secure') . '</h3>';
            echo '<p class="teg-switch-desc" style="display:block; margin-bottom:15px;">' . esc_html__('Signature-based scan for common malware/backdoor patterns.', 'tegatai-secure') . '</p>';

            echo '<div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center;">';
            echo '<form method="post" style="display:flex; gap:10px; align-items:center;">';
            wp_nonce_field('tegatai_mw_run', '_wpnonce', true, true);
            echo '<input type="number" name="tegatai_mw_limit" value="' . esc_attr((string)$limit) . '" class="teg-form-input" style="width:80px; margin:0;" />';
            echo '<label style="font-size:12px; font-weight:600;"><input type="checkbox" name="tegatai_mw_fresh" value="1" /> ' . esc_html__('Fresh scan', 'tegatai-secure') . '</label>';
            echo '<button class="button button-primary" name="tegatai_mw_run" value="1">' . esc_html__('Run', 'tegatai-secure') . '</button>';
            echo '</form>';

            echo '<form method="post">';
            wp_nonce_field('tegatai_mw_reset', '_wpnonce', true, true);
            echo '<button class="button button-secondary" name="tegatai_mw_reset" value="1">' . esc_html__('Reset', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '</div>';

            if (is_array($result)) {
                $hits = isset($result['hits']) && is_array($result['hits']) ? $result['hits'] : [];
                $checked = isset($result['checked']) ? intval($result['checked']) : 0;
                $total = isset($result['total_files']) ? intval($result['total_files']) : 0;
                $done = !empty($result['done']);

                echo '<div class="teg-stat-row" style="margin-top:20px;">';
                echo '<div class="teg-stat-box"><span class="teg-stat-num">'.(int) $checked.' / '.(int) $total.'</span><span class="teg-stat-label">Progress</span></div>';
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
            echo '</div>';
            if (class_exists('Tegatai_Quarantine')) Tegatai_Quarantine::render_list();
            echo '</div>';
        }


        elseif ($tab == 'timeline') {
            echo '<div class="teg-grid"><div class="teg-card" style="grid-column: span 2;">';
            echo '<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:15px;">';
            echo '<h3 style="margin:0; border:none; padding:0;">' . esc_html__('Security Timeline', 'tegatai-secure') . '</h3>';
            
            if (class_exists('Tegatai_Timeline')) {
                if (isset($_POST['tegatai_tl_clear']) && check_admin_referer('tegatai_tl_clear')) {
                    Tegatai_Timeline::clear();
                }
                echo '<form method="post" style="margin:0;">';
                wp_nonce_field('tegatai_tl_clear', '_wpnonce', true, true);
                echo '<button class="button button-secondary" name="tegatai_tl_clear" value="1" data-tegatai-confirm="' . esc_attr(__('Clear?', 'tegatai-secure')) . '">' . esc_html__('Clear', 'tegatai-secure') . '</button>';
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
            if (isset($_POST['tegatai_core_check']) && check_admin_referer('tegatai_core_check')) {
                if (class_exists('Tegatai_Core_Integrity')) { $res = Tegatai_Core_Integrity::check(); }
            }
            echo '<form method="post" style="margin:12px 0;">';
            wp_nonce_field('tegatai_core_check', '_wpnonce', true, true);
            echo '<button class="button button-primary" name="tegatai_core_check" value="1">' . esc_html__('Run check', 'tegatai-secure') . '</button>';
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
                        echo '</tr>';
                    }
                    echo '</tbody></table></div>';
                    
                    // Core files are restored by WordPress itself, never written by Tegatai.
                    echo '<p class="teg-switch-desc" style="display:block; margin-top:12px;">' . esc_html__('To restore the original core files, use WordPress\' own re-installation: Dashboard > Updates > "Re-install version". It replaces all core files with the official package.', 'tegatai-secure') . '</p>';
                    echo '<a class="button button-primary" href="' . esc_url(admin_url('update-core.php')) . '">' . esc_html__('Open Dashboard > Updates', 'tegatai-secure') . '</a>';
                } else {
                    echo '<div style="padding:10px; background:#dcfce7; color:#15803d; border-radius:6px; font-weight:bold; text-align:center; font-size:12px; margin-top:10px;">✅ ' . esc_html(sprintf(/* translators: %s: WordPress version */ __('WordPress core %s is clean.', 'tegatai-secure'), $res['version'] ?? '')) . '</div>';
                }
            }
            echo '</div></div>';
        }
        elseif ($tab == 'options') {
            echo '<div class="teg-grid"><div class="teg-card">';
            echo '<h3>' . esc_html__('Dangerous Options Scanner', 'tegatai-secure') . '</h3>';
            $res = null;
            if (isset($_POST['tegatai_opt_scan']) && check_admin_referer('tegatai_opt_scan')) {
                if (class_exists('Tegatai_Option_Scanner')) { $res = Tegatai_Option_Scanner::scan(2500); }
            }
            echo '<form method="post" style="margin:12px 0;">';
            wp_nonce_field('tegatai_opt_scan', '_wpnonce', true, true);
            echo '<button class="button button-primary" name="tegatai_opt_scan" value="1">' . esc_html__('Scan options', 'tegatai-secure') . '</button>';
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
            if (isset($_POST['tegatai_up_scan']) && check_admin_referer('tegatai_up_scan')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { Tegatai_Uploads_Monitor::scan(2000); }
            }
            if (isset($_POST['tegatai_up_quarantine']) && check_admin_referer('tegatai_up_quarantine')) {
                if (class_exists('Tegatai_Uploads_Monitor')) { Tegatai_Uploads_Monitor::quarantine_hits(50); }
            }
            echo '<form method="post" style="margin:12px 0;display:flex;gap:10px;flex-wrap:wrap;">';
            wp_nonce_field('tegatai_up_scan', '_wpnonce', true, true);
            echo '<button class="button button-primary" name="tegatai_up_scan" value="1">' . esc_html__('Scan uploads', 'tegatai-secure') . '</button>';
            echo '</form>';
            echo '<form method="post" style="margin:0 0 12px 0;">';
            wp_nonce_field('tegatai_up_quarantine', '_wpnonce', true, true);
            echo '<button class="button button-secondary" name="tegatai_up_quarantine" value="1">' . esc_html__('Quarantine flagged (max 50)', 'tegatai-secure') . '</button>';
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
        if (!current_user_can('manage_options')) return; // Security stats are for administrators only
        wp_add_dashboard_widget('tegatai_dashboard_widget', __('🛡️ Tegatai Security Status', 'tegatai-secure'), [$this, 'render_dashboard_widget']);
    }

    public function render_dashboard_widget() {
        $stats = Tegatai_Logger::get_stats();
        $scan_status = get_option('tegatai_scan_status');
        $last_scan = isset($scan_status['last_scan']) ? $scan_status['last_scan'] : __('Never', 'tegatai-secure');
        $scan_res = (isset($scan_status['bad_files']) && empty($scan_status['bad_files'])) ? '<span style="color:#10b981;font-weight:bold;">' . esc_html__('Clean ✅', 'tegatai-secure') . '</span>' : '<span style="color:#ef4444;font-weight:bold;">' . esc_html__('Scan required...', 'tegatai-secure') . '</span>';
        
        echo '<div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:center;margin-bottom:15px;">';
        echo '<div style="background:#f3f4f6;padding:10px;border-radius:5px;"><strong>' . esc_html__('Blocked', 'tegatai-secure') . '</strong><br><span style="font-size:20px;color:#ef4444;">' . intval($stats['blocked']) . '</span></div>';
        echo '<div style="background:#f3f4f6;padding:10px;border-radius:5px;"><strong>' . esc_html__('Traffic', 'tegatai-secure') . '</strong><br><span style="font-size:20px;color:#4f46e5;">' . intval($stats['total']) . '</span></div>';
        echo '</div>';
        
        echo '<div style="border-top:1px solid #eee;padding-top:10px;font-size:13px;">';
        echo '<strong>' . esc_html__('Last Scan:', 'tegatai-secure') . '</strong> ' . esc_html($last_scan) . '<br>';
        echo '<strong>' . esc_html__('Result:', 'tegatai-secure') . '</strong> ' . wp_kses_post($scan_res);
        echo '</div>';
        
        echo '<div style="margin-top:15px;text-align:right;">';
        echo '<a href="admin.php?page=tegatai-Secure" class="button button-primary">' . esc_html__('Go to Dashboard', 'tegatai-secure') . '</a>';
        echo '</div>';
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
                echo '<td><strong style="'.esc_attr($color).'">' . esc_html(wp_date($time_format, $e['time'])) . '</strong><br><small>(' . esc_html($in_text) . ')</small></td>';
                echo '<td><code>' . esc_html($e['hook']) . '</code></td>';
                echo '<td>' . esc_html(ucfirst($e['schedule'])) . '</td>';
                echo '<td><a href="#" class="teg-delete-cron" data-hook="' . esc_attr($e['hook']) . '" style="color:var(--teg-danger); text-decoration:none;"><span class="dashicons dashicons-trash" style="vertical-align:middle;"></span> Delete</a></td>';
                echo '</tr>';
            }
        }
        echo '</tbody></table></div>';

    }

    
    public function export_config() {
        if (!current_user_can('manage_options') || !isset($_GET['_wpnonce']) || !wp_verify_nonce(sanitize_key(wp_unslash($_GET['_wpnonce'])), 'tegatai_export_nonce')) wp_die('Forbidden');
        $ops = tegatai_get_setting($this->options_slug, []); if (!is_array($ops)) $ops = [];
        // Only export known settings and never include secrets in the plain JSON file.
        $ops = array_diff_key(array_intersect_key($ops, $this->schema), array_flip($this->secret_keys));
        header('Content-Type: application/json');
        header('Content-Disposition: attachment; filename="tegatai-config-'.gmdate('Y-m-d').'.json"');
        echo wp_json_encode($ops);
        exit;
    }

    public function ajax_import_config() {
        check_ajax_referer('tegatai_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        // Raw JSON on purpose: decoded below and only known setting keys are taken over
        // The JSON text is decoded and then every value is validated and sanitized with the settings
        // schema below (unknown keys and non-scalar values are dropped). sanitize_text_field() on the
        // raw JSON would break the firewall patterns, which are kept verbatim after validation.
        $json = isset($_POST['json']) && is_string($_POST['json']) ? wp_unslash($_POST['json']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- see above
        if (strlen($json) > 262144) wp_send_json_error(['msg' => __('Invalid JSON format.', 'tegatai-secure')]);
        $data = json_decode($json, true);
        if (!$data || !is_array($data)) wp_send_json_error(['msg' => __('Invalid JSON format.', 'tegatai-secure')]);
        // Replace all known settings with the imported ones; unknown keys in the file are discarded.
        $ops = tegatai_get_setting($this->options_slug, []); if (!is_array($ops)) $ops = [];
        // Secrets are not exported, so keep the current ones unless the file explicitly provides them.
        $ops = array_diff_key($ops, array_diff_key($this->schema, array_flip($this->secret_keys)));
        foreach ($data as $key => $value) {
            if (!is_string($key) || !isset($this->schema[$key]) || !is_scalar($value)) continue;
            if (is_bool($value) || is_int($value)) $value = (string)(int)$value;
            $ops[$key] = $this->sanitize_setting($key, $value);
        }
        // Only one captcha at a time (reCAPTCHA wins, same rule as at runtime)
        if (!empty($ops['enable_recaptcha'])) $ops['enable_turnstile'] = 0;
        tegatai_update_setting($this->options_slug, $ops);
        if (class_exists('Tegatai_Server')) Tegatai_Server::force_update();
        wp_send_json_success();
    }

    public function ajax_deep_clean() {
        check_ajax_referer('tegatai_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        global $wpdb;
        $stats = [];
        
        // 1. Expired Transients
        $time = time();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- maintenance task, no API for this
        $expired = $wpdb->get_col($wpdb->prepare("SELECT option_name FROM %i WHERE option_name LIKE %s AND option_value < %d", $wpdb->options, $wpdb->esc_like('_transient_timeout_') . '%', $time));
        $del_trans = 0;
        foreach ($expired as $t) {
            $key = str_replace('_transient_timeout_', '', $t);
            delete_transient($key);
            $del_trans++;
        }
        if ($del_trans > 0) $stats[] = sprintf(/* translators: %d: number of deleted transients */ __('🗑️ <strong>%d</strong> expired transients deleted.', 'tegatai-secure'), $del_trans);

        // 2. Spam & Trash Kommentare
        $spam_del = $wpdb->query("DELETE FROM {$wpdb->comments} WHERE comment_approved = 'spam' OR comment_approved = 'trash'");
        if ($spam_del > 0) $stats[] = sprintf(/* translators: %d: number of removed comments */ __('🗑️ <strong>%d</strong> spam/trash comments removed.', 'tegatai-secure'), $spam_del);

        // 3. Post Revisions
        $rev_del = $wpdb->query("DELETE a,b,c FROM {$wpdb->posts} a LEFT JOIN {$wpdb->term_relationships} b ON ( a.ID = b.object_id ) LEFT JOIN {$wpdb->postmeta} c ON ( a.ID = c.post_id ) WHERE a.post_type = 'revision'");
        if ($rev_del > 0) $stats[] = sprintf(/* translators: %d: number of removed revisions */ __('🗑️ <strong>%d</strong> old post revisions cleaned.', 'tegatai-secure'), $rev_del);

        // 4. Optimize Tables
        // Only this site's tables; a shared database may contain tables of other applications.
        $tables = $wpdb->get_col($wpdb->prepare("SHOW TABLES LIKE %s", $wpdb->esc_like($wpdb->prefix) . '%'));
        foreach ($tables as $table) {
            $wpdb->query($wpdb->prepare("OPTIMIZE TABLE %i", $table));
        }
        $stats[] = __('⚡ Database tables defragmented (overhead released).', 'tegatai-secure');

        if (empty($stats)) $stats[] = __('Everything was already spotless! No cleanup needed.', 'tegatai-secure');

        wp_send_json_success(['stats' => $stats]);
    }

    
    public function ajax_delete_cron() {
        check_ajax_referer('tegatai_admin_nonce');
        if (!current_user_can('manage_options')) wp_send_json_error();
        $hook = sanitize_text_field(wp_unslash($_POST['hook'] ?? ''));
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
