<?php
if (!defined('ABSPATH')) { exit; }

/* TEGATAI_TERMINAL_REFINEMENT_V1 applied */
/* TEGATAI_TERMINAL_FINAL_POLISH_V1 applied */
class Tegatai_Terminal {
    public function __construct() {
        add_action('admin_menu', [$this, 'register_page'], 20);
        add_action('wp_ajax_tegatai_terminal_fetch', [$this, 'ajax_fetch']);
    }

    // DRY: Unified IP Handling
    private function get_client_ip() {
        return class_exists('Tegatai_Logger') && method_exists('Tegatai_Logger', 'get_ip') ? Tegatai_Logger::get_ip() : ($_SERVER['REMOTE_ADDR'] ?? '');
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

    public function register_page() {
        // Versteckte Seite (kein Menü-Eintrag links)
        add_submenu_page('tegatai-secure', 'Tegatai Terminal', 'Terminal', 'manage_options', 'tegatai-terminal', [$this, 'render_terminal']);
    }

    public function ajax_fetch() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        
        // 1. Security Check: Nonce Validation
        check_ajax_referer('teg_terminal_nonce', 'security');

        // 2. Security Check: Rate Limiting (DDoS Protection via Unified Cache)
        $ip = $this->get_client_ip();
        $rl_key = 'teg_term_rl_' . md5($ip);
        
        // Maximal 1 Request alle 2 Sekunden erlaubt
        if ($this->get_cache($rl_key)) {
            // Loggt den Flood-Versuch, falls es ein manueller Spam-Angriff ist
            if (class_exists('Tegatai_Logger')) {
                Tegatai_Logger::log('FLOOD', "Terminal API rate limit hit by $ip");
            }
            echo "<div class='log-row warn'>[SYS] Rate limit exceeded. Polling too fast...</div>";
            wp_die();
        }
        $this->set_cache($rl_key, 1, 2);

        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        
        $limit = isset($_POST['limit']) ? intval($_POST['limit']) : 50;
        if ($limit > 200) $limit = 200; // Hard Cap für DB-Schutz
        
        $logs = $wpdb->get_results("SELECT * FROM $table ORDER BY id DESC LIMIT $limit", ARRAY_A);
        
        $output = "";
        if (empty($logs)) {
            $output = "<div class='log-row info'>[SYS] No current traffic logs found. Waiting for events...</div>";
        } else {
            foreach ($logs as $log) {
                $time = date('H:i:s', strtotime($log['time']));
                $ip_str = str_pad($log['ip'], 15, ' ');
                $type = str_pad($log['type'], 12, ' ');
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
        echo $output;
        wp_die();
    }

    public function render_terminal() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
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

            /* Terminal Specific styling */
            .teg-terminal-card { background-color: #0f172a; border-radius: 8px; border: 1px solid #1e293b; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); display: flex; flex-direction: column; height: 65vh; min-height: 500px; overflow: hidden; margin-top: 10px; }
            .teg-term-header { background: #1e293b; padding: 12px 20px; color: #94a3b8; font-size: 13px; font-family: monospace; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #334155; }
            .teg-term-output { flex-grow: 1; padding: 20px; overflow-y: auto; font-family: 'Courier New', Courier, monospace; font-size: 13px; line-height: 1.6; color: #cbd5e1; background: #0f172a; }
            .teg-term-output::-webkit-scrollbar { width: 8px; }
            .teg-term-output::-webkit-scrollbar-thumb { background: #334155; border-radius: 4px; }
            .teg-term-footer { background: #1e293b; padding: 10px 20px; color: #64748b; font-size: 12px; font-family: 'Inter', system-ui, sans-serif; border-top: 1px solid #334155; }
            
            .log-row { white-space: pre-wrap; word-wrap: break-word; margin-bottom: 4px; }
            .log-row .time { color: #64748b; margin-right: 8px; }
            .log-row .ip { color: #818cf8; margin-right: 8px; }
            .log-row .type { font-weight: 700; margin-right: 8px; }
            
            .log-row.danger .type, .log-row.danger .msg { color: #f87171; }
            .log-row.warn .type, .log-row.warn .msg { color: #fbbf24; }
            .log-row.success .type, .log-row.success .msg { color: #34d399; }
            .log-row.info .type, .log-row.info .msg { color: #94a3b8; }
            
            .teg-key { display: inline-block; background: #334155; color: #cbd5e1; padding: 2px 6px; border-radius: 4px; border: 1px solid #475569; margin: 0 4px; font-family: monospace; font-size: 11px; }
            .teg-btn-term { background: transparent; border: 1px solid #475569; color: #cbd5e1; border-radius: 4px; cursor: pointer; padding: 4px 10px; font-size: 11px; font-family: monospace; transition: all 0.2s; }
            .teg-btn-term:hover { background: #334155; color: #fff; }
        </style>

        <div class="teg-wrap">
            <div class="teg-header">
                <div class="teg-title"><span class="dashicons dashicons-desktop" style="font-size:32px;"></span> Tegatai Live Terminal</div>
                <div class="teg-badge">v1.2</div>
            </div>

            <div class="teg-inner-nav">
                <a href="<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=logs')); ?>" class="teg-back-btn">
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
            
            <script>
                const ajaxurl = '<?php echo esc_url(admin_url('admin-ajax.php')); ?>';
                const output = document.getElementById('terminal-output');
                const status = document.getElementById('status');
                const btnPause = document.getElementById('btn-pause');
                
                let autoRefresh;
                let isPaused = false;

                function fetchLogs() {
                    if (isPaused) return;

                    status.innerText = '[ FETCHING... ]';
                    status.style.color = '#fbbf24';
                    
                    const fd = new FormData();
                    fd.append('action', 'tegatai_terminal_fetch');
                    fd.append('limit', '100');
                    fd.append('security', '<?php echo wp_create_nonce('teg_terminal_nonce'); ?>');

                    fetch(ajaxurl, { method: 'POST', body: fd })
                        .then(res => res.text())
                        .then(data => {
                            if (isPaused) return; // Verhindert Update, falls während des Fetches pausiert wurde
                            output.innerHTML = data;
                            status.innerText = '[ IDLE ]';
                            status.style.color = '#34d399';
                        }).catch(err => {
                            status.innerText = '[ ERROR ]';
                            status.style.color = '#ef4444';
                        });
                }

                function togglePause() {
                    isPaused = !isPaused;
                    if (isPaused) {
                        status.innerText = '[ PAUSED ]';
                        status.style.color = '#ef4444';
                        btnPause.innerText = 'Resume (P)';
                        btnPause.style.color = '#34d399';
                        btnPause.style.borderColor = '#34d399';
                    } else {
                        status.innerText = '[ RESUMED ]';
                        btnPause.innerText = 'Pause (P)';
                        btnPause.style.color = '#cbd5e1';
                        btnPause.style.borderColor = '#475569';
                        fetchLogs();
                    }
                }

                btnPause.addEventListener('click', function(e) {
                    e.preventDefault();
                    togglePause();
                });

                // Initial fetch & interval (5 Sekunden)
                setTimeout(fetchLogs, 500);
                autoRefresh = setInterval(fetchLogs, 5000);

                // Keyboard Controls
                document.addEventListener('keydown', (e) => {
                    // Verhindert Shortcuts, wenn man sich in einem Input-Feld befinden würde
                    if(e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;

                    if (e.key === 'r' || e.key === 'R') {
                        fetchLogs();
                    }
                    if (e.key === 'p' || e.key === 'P') {
                        togglePause();
                    }
                    if (e.key === 'c' || e.key === 'C') {
                        output.innerHTML = '<div class="log-row info">[SYS] Console cleared. Waiting for new events...</div>';
                    }
                    if (e.key === 'Escape') {
                        window.location.href = '<?php echo esc_url(admin_url('admin.php?page=tegatai-secure&tab=logs')); ?>';
                    }
                });
            </script>
        </div>
        <?php
    }
}
