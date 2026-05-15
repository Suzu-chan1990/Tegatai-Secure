<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Terminal {
    public function __construct() {
        add_action('admin_menu', [$this, 'register_page'], 20);
                add_action('wp_ajax_tegatai_terminal_fetch', [$this, 'ajax_fetch']);
    }

    public function register_page() {
        // Versteckte Seite (kein Menü-Eintrag links)
        add_submenu_page('tegatai-secure', 'Tegatai Terminal', 'Terminal', 'manage_options', 'tegatai-terminal', [$this, 'render_terminal']);
    }

    
    public function ajax_fetch() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        global $wpdb;
        $table = $wpdb->prefix . 'tegatai_logs';
        
        $limit = isset($_POST['limit']) ? intval($_POST['limit']) : 50;
        $logs = $wpdb->get_results("SELECT * FROM $table ORDER BY id DESC LIMIT $limit", ARRAY_A);
        
        $output = "";
        if (empty($logs)) {
            $output = "<div class='log-row info'>[SYS] No current traffic logs found. Waiting for events...</div>";
        } else {
            foreach ($logs as $log) {
                $time = date('H:i:s', strtotime($log['time']));
                $ip = str_pad($log['ip'], 15, ' ');
                $type = str_pad($log['type'], 12, ' ');
                $msg = esc_html($log['message']);
                
                // Color coding based on event type
                $css_class = 'info';
                if (strpos($type, 'BAN') !== false || strpos($type, 'BLOCK') !== false || strpos($type, 'FW') !== false) $css_class = 'danger';
                if (strpos($type, 'WARN') !== false || strpos($type, 'SPAM') !== false) $css_class = 'warn';
                if (strpos($type, 'AUTH') !== false || strpos($type, 'LOGIN') !== false) $css_class = 'success';

                $output .= "<div class='log-row $css_class'>";
                $output .= "<span class='time'>[$time]</span> ";
                $output .= "<span class='ip'>$ip</span> ";
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
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <title>Tegatai Terminal</title>
            <style>
                body { margin: 0; padding: 20px; background-color: #050505; color: #a9b7c6; font-family: 'Courier New', Courier, monospace; font-size: 14px; line-height: 1.5; height: 100vh; overflow: hidden; box-sizing: border-box; display: flex; flex-direction: column; }
                #header { display: flex; justify-content: space-between; border-bottom: 1px solid #333; padding-bottom: 10px; margin-bottom: 10px; color: #6a8759; }
                #terminal-output { flex-grow: 1; overflow-y: auto; padding-right: 10px; }
                #terminal-output::-webkit-scrollbar { width: 8px; }
                #terminal-output::-webkit-scrollbar-thumb { background: #333; }
                .log-row { white-space: pre-wrap; word-wrap: break-word; margin-bottom: 2px; }
                .time { color: #888; }
                .ip { color: #9876aa; }
                .type { font-weight: bold; }
                .danger .type, .danger .msg { color: #cc7832; } /* Muted Orange/Red */
                .warn .type, .warn .msg { color: #bbb529; } /* Muted Yellow */
                .success .type, .success .msg { color: #6a8759; } /* Hacker Green */
                .info .type, .info .msg { color: #a9b7c6; }
                #controls { margin-top: 10px; padding-top: 10px; border-top: 1px solid #333; font-size: 12px; color: #555; }
                .key { display: inline-block; background: #222; color: #888; padding: 2px 6px; border-radius: 3px; border: 1px solid #444; margin: 0 4px; }
            </style>
        </head>
        <body>
            <div id="header">
                <div>root@tegatai-secure:~# tail -f access.log</div>
                <div id="status">Status: CONNECTED</div>
            </div>
            
            <div id="terminal-output">
                <div class="log-row info">Initializing Tegatai Terminal Mode...</div>
                <div class="log-row info">Establishing secure stream...</div>
            </div>

            <div id="controls">
                Shortcuts: <span class="key">R</span> Refresh <span class="key">C</span> Clear Local Console <span class="key">ESC</span> Return to Dashboard
            </div>

            <script>
                const ajaxurl = '<?php echo admin_url('admin-ajax.php'); ?>';
                const output = document.getElementById('terminal-output');
                const status = document.getElementById('status');
                let autoRefresh;

                function fetchLogs() {
                    status.innerText = 'Status: FETCHING...';
                    status.style.color = '#bbb529';
                    
                    const fd = new FormData();
                    fd.append('action', 'tegatai_terminal_fetch');
                    fd.append('limit', '100');

                    fetch(ajaxurl, { method: 'POST', body: fd })
                        .then(res => res.text())
                        .then(data => {
                            output.innerHTML = data;
                            status.innerText = 'Status: IDLE';
                            status.style.color = '#6a8759';
                        });
                }

                // Initial fetch & interval
                setTimeout(fetchLogs, 500);
                autoRefresh = setInterval(fetchLogs, 5000);

                // Keyboard Controls
                document.addEventListener('keydown', (e) => {
                    if (e.key === 'r' || e.key === 'R') {
                        fetchLogs();
                    }
                    if (e.key === 'c' || e.key === 'C') {
                        output.innerHTML = '<div class="log-row info">Console cleared. Waiting for new events...</div>';
                    }
                    if (e.key === 'Escape') {
                        window.location.href = '<?php echo admin_url('admin.php?page=tegatai-secure'); ?>';
                    }
                });
            </script>
        </body>
        </html>
        <?php
        exit; // Stoppt das Laden des WP-Admin-Rests für pure Performance
    }
}
