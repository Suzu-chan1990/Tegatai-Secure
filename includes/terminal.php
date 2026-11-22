<?php
if (!defined('ABSPATH')) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Tegatai uses its own tables (logs, settings) and live security data; queries are prepared and caching would serve stale data
// phpcs:disable WordPress.Security.ValidatedSanitizedInput -- Request headers (IP, user agent, URI) are read raw for fingerprints and comparisons; output is escaped and SQL is prepared

/* TEGATAI_TERMINAL_REFINEMENT_V1 applied */
/* TEGATAI_TERMINAL_FINAL_POLISH_V1 applied */
class Tegatai_Terminal {
    public function __construct() {
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('wp_ajax_tegatai_terminal_fetch', [$this, 'ajax_fetch']);
        add_action('admin_enqueue_scripts', [$this, 'enqueue_assets']);
    }

    // DRY: Unified IP Handling
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? ''));
    }

    // Unified Cache Engine for Rate Limiting
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

    // Script only on the terminal screen (styles: css/subpages.css, loaded by Tegatai_Admin).
    public function enqueue_assets($hook) {
        $page = isset($_GET['page']) ? sanitize_key(wp_unslash($_GET['page'])) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- screen detection only
        if ($page !== 'tegatai-terminal') return;
        wp_enqueue_script('tegatai-terminal', TEGATAI_URL . 'js/terminal.js', [], TEGATAI_VERSION, ['in_footer' => true]);
        wp_localize_script('tegatai-terminal', 'TegataiTerminal', [
            'ajaxUrl' => admin_url('admin-ajax.php'),
            'nonce'   => wp_create_nonce('tegatai_terminal_nonce'),
            'backUrl' => admin_url('admin.php?page=tegatai-Secure&tab=logs'),
        ]);
    }

    public function register_page() {
        // Versteckte Seite (kein Menü-Eintrag links)
        add_submenu_page('tegatai-Secure', 'Tegatai Terminal', 'Terminal', 'manage_options', 'tegatai-terminal', [$this, 'render_terminal']);
    }

    public function ajax_fetch() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        
        // 1. Security Check: Nonce Validation
        check_ajax_referer('tegatai_terminal_nonce', 'security');

        // 2. Security Check: Rate Limiting (DDoS Protection via Unified Cache)
        $ip = $this->get_client_ip();
        $rl_key = 'tegatai_term_rl_' . md5($ip);
        
        // Maximal 1 Request alle 2 Sekunden erlaubt
        if ($this->get_cache($rl_key)) {
            // No FLOOD log/webhook alert here: this endpoint is admin-only, a fast refresh is not an attack.
            // 429 tells the client to keep the current output.
            status_header(429);
            wp_die('', '', ['response' => 429]);
        }
        $this->set_cache($rl_key, 1, 2);

        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        
        $limit = isset($_POST['limit']) ? intval($_POST['limit']) : 50;
        if ($limit > 200) $limit = 200; // Hard Cap für DB-Schutz
        
        $logs = $wpdb->get_results($wpdb->prepare("SELECT * FROM %i ORDER BY id DESC LIMIT %d", $table, $limit), ARRAY_A);
        
        $output = "";
        if (empty($logs)) {
            $output = "<div class='log-row info'>[SYS] No current traffic logs found. Waiting for events...</div>";
        } else {
            foreach ($logs as $log) {
                $time = gmdate('H:i:s', strtotime($log['time']));
                $ip_str = esc_html(str_pad((string)$log['ip'], 15, ' '));
                $type = esc_html(str_pad((string)$log['type'], 12, ' '));
                $msg = esc_html($log['message']);
                
                // Color coding based on event type
                $css_class = 'info';
                if (strpos($type, 'BAN') !== false || strpos($type, 'BLOCK') !== false || strpos($type, 'FW') !== false) $css_class = 'danger';
                if (strpos($type, 'WARN') !== false || strpos($type, 'SPAM') !== false || strpos($type, 'FLOOD') !== false) $css_class = 'warn';
                if (strpos($type, 'AUTH') !== false || strpos($type, 'LOGIN') !== false) $css_class = 'success';

                $output .= "<div class='log-row $css_class'>";
                $output .= "<span class='time'>[$time]</span> ";
                $output .= "<span class='ip'>$ip_str</span> ";
                $output .= "<span class='type'>[$type]</span> ";
                $output .= "<span class='msg'>$msg</span>";
                $output .= "</div>";
            }
        }
        echo wp_kses_post($output); // every value above is escaped already; wp_kses_post keeps the markup
        wp_die();
    }

    public function render_terminal() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        ?>

        <div class="teg-wrap">
            <div class="teg-header">
                <div class="teg-title"><span class="dashicons dashicons-desktop" style="font-size:32px;"></span> Tegatai Live Terminal</div>
                <div class="teg-badge">v1.2</div>
            </div>

            <div class="teg-inner-nav">
                <a href="<?php echo esc_url(admin_url('admin.php?page=tegatai-Secure&tab=logs')); ?>" class="teg-back-btn">
                    <span class="dashicons dashicons-arrow-left-alt" style="margin-top:2px;"></span> <?php echo esc_html__('Back to Logs', 'tegatai-secure'); ?>
                </a>
                <div class="teg-horizontal-tabs">
                    <span class="teg-h-tab active"><?php echo esc_html__('Live Traffic Stream', 'tegatai-secure'); ?></span>
                </div>
            </div>

            <div class="teg-terminal-card">
                <div class="teg-term-header">
                    <div><span class="dashicons dashicons-arrow-right-alt2" style="font-size:16px; width:16px; height:16px; vertical-align:middle; color:var(--teg-primary);"></span> root@tegatai-secure:~# tail -f /var/log/tegatai_traffic.log</div>
                    <div style="display:flex; align-items:center; gap:15px;">
                        <button id="btn-pause" class="teg-btn-term">Pause (P)</button>
                        <div id="status" style="color: #34d399; font-weight: 600; width: 110px; text-align: right;">[ CONNECTED ]</div>
                    </div>
                </div>
                
                <div id="terminal-output" class="teg-term-output">
                    <div class="log-row info">[SYS] Initializing Tegatai Terminal Mode...</div>
                    <div class="log-row info">[SYS] Establishing secure stream...</div>
                </div>

                <div class="teg-term-footer">
                    Shortcuts: <span class="teg-key">R</span> Refresh stream &nbsp; <span class="teg-key">P</span> Pause/Resume &nbsp; <span class="teg-key">C</span> Clear console &nbsp; <span class="teg-key">ESC</span> Exit to Dashboard
                </div>
            </div>
            
        </div>
        <?php
    }
}
