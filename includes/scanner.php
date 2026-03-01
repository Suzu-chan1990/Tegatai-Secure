<?php

/* TEGATAI_REMAINING_FIXES_V1 applied 2026-02-26 17:47:52 */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Scanner {
    public function __construct() {
        add_action('admin_post_tegatai_scan_start', [$this, 'start_scan']);
        add_action('admin_post_tegatai_scan_process', [$this, 'process_scan']);
        add_action('tegatai_daily_maintenance', [$this, 'auto_night_scan']);
        add_action('tegatai_daily_maintenance', [$this, 'check_cve_vulnerabilities']);
        add_action('admin_post_tegatai_scan_snapshot', [$this, 'create_snapshot']);
    }

    public function create_snapshot() {
        check_admin_referer('teg_scan_nonce');
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        
        $files = $this->get_content_files();
        $snapshot = [];
        foreach ($files as $file) {
            $snapshot[str_replace(ABSPATH, '', $file)] = md5_file($file);
        }
        
        $dir = wp_upload_dir()['basedir'] . '/tegatai-logs/';
        if (!is_dir($dir)) wp_mkdir_p($dir);
        file_put_contents($dir . 'snapshot.json', wp_json_encode($snapshot));
        
        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=scanner&msg=snapshot_created'));
        exit;
    }

    public function auto_night_scan() {
        $state = ['phase' => 'silent', 'bad_files' => []];
        $this->scan_core_files($state);
        $files = $this->get_content_files();
        foreach ($files as $file) {
            $this->analyze_file($file, $state);
        }
        
        if (!empty($state['bad_files'])) {
            $ops = get_option('tegatai_options');
            $to = !empty($ops['alert_email']) ? $ops['alert_email'] : get_option('admin_email');
            $msg = "🚨 Tegatai Auto-Scan Alarm!\n\nFolgende Dateien wurden modifiziert oder sind verdächtig:\n\n";
            foreach ($state['bad_files'] as $b) {
                $msg .= "- " . $b['file'] . " (" . $b['issue'] . ")\n";
            }
            $msg .= "\nBitte prüfe dein Dashboard umgehend!";
            wp_mail($to, "[Tegatai] Malware Alarm - Dateiänderung erkannt!", $msg);
            Tegatai_Logger::log('SEC-WARN', 'Auto-Scan fand modifizierte Dateien!');
        }
    }

    public function start_scan() {
        check_admin_referer('teg_scan_nonce');
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        $scan_token = wp_generate_password(32, false, false);

        
        update_option('teg_scan_status', [
            'running' => true,
            'phase' => 'core',
            'offset' => 0,
            'files_checked' => 0,
            'bad_files' => [],
            'start_time' => time(),
            'scan_token' => $scan_token
        ]);
        
        wp_redirect(admin_url('admin-post.php?action=tegatai_scan_process&scan_token=' . rawurlencode($scan_token)));
        exit;
    }

    public function process_scan() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        
        $state = get_option('teg_scan_status');
        
        $expected = is_array($state) && isset($state['scan_token']) ? (string)$state['scan_token'] : '';
        $provided = isset($_REQUEST['scan_token']) ? (string)$_REQUEST['scan_token'] : '';
        if ($expected === '' || $provided === '' || !hash_equals($expected, $provided)) {
            wp_die('Invalid scan token.');
        }
if (empty($state) || !$state['running']) {
            wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=scanner'));
            exit;
        }

        $time_start = microtime(true);

        // Phase 1: Core Checksums
        if ($state['phase'] === 'core') {
            $this->scan_core_files($state);
            $state['phase'] = 'content';
            $state['offset'] = 0;
            update_option('teg_scan_status', $state);
            wp_redirect(admin_url('admin-post.php?action=tegatai_scan_process&scan_token=' . rawurlencode($state['scan_token'])));
            exit;
        }

        // Phase 2: Content Scan
        if ($state['phase'] === 'content') {
            $files = $this->get_content_files(); // Updated with Exclusions
            $total = count($files);
            
            for ($i = $state['offset']; $i < $total; $i++) {
                if ((microtime(true) - $time_start) > 5) { // 5 sek limit
                    $state['offset'] = $i;
                    update_option('teg_scan_status', $state);
                    wp_redirect(admin_url('admin-post.php?action=tegatai_scan_process&scan_token=' . rawurlencode($state['scan_token'])));
                    exit;
                }
                
                $this->analyze_file($files[$i], $state);
                $state['files_checked']++;
            }

            // Fertig
            $state['running'] = false;
            $state['last_scan'] = current_time('mysql');
            update_option('teg_scan_status', $state);
            wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=scanner&msg=done'));
            exit;
        }
    }

    private function scan_core_files(&$state) {
        $version = get_bloginfo('version');
        $locale = get_locale();
        $url = "https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=$locale";
        
        $response = wp_remote_get($url);
        if (is_wp_error($response)) {
            $state['bad_files'][] = ['file' => 'API Error', 'issue' => 'Connection failed'];
            return;
        }

        $data = json_decode(wp_remote_retrieve_body($response), true);
        if (!isset($data['checksums']) || !is_array($data['checksums'])) return;

        foreach ($data['checksums'] as $file => $checksum) {
            $local_path = ABSPATH . $file;
            if (!file_exists($local_path)) {
                // Ignore wp-config-sample if missing
                continue; 
            }
            if (md5_file($local_path) !== $checksum && $file !== 'wp-config-sample.php') {
                $state['bad_files'][] = ['file' => $file, 'issue' => 'Core Modified'];
            }
        }
    }

    private function get_content_files() {
        $files = [];
        if (!is_dir(WP_CONTENT_DIR) || !is_readable(WP_CONTENT_DIR)) return $files;
        $dir_iterator = new RecursiveDirectoryIterator(WP_CONTENT_DIR);
        $iterator = new RecursiveIteratorIterator($dir_iterator);
        
        // Exclusions holen
        $ops = get_option('tegatai_options');
        $excludes = [];
        if (!empty($ops['scanner_exclusions'])) {
            $lines = explode("\n", $ops['scanner_exclusions']);
            foreach($lines as $l) if(trim($l)) $excludes[] = trim($l);
        }

        foreach ($iterator as $file) {
            if (!$file->isDir() && pathinfo($file, PATHINFO_EXTENSION) === 'php') {
                $path = $file->getPathname();
                
                // Check Exclusions
                $skip = false;
                foreach($excludes as $ex) {
                    if (strpos($path, $ex) !== false) { $skip = true; break; }
                }
                if ($skip) continue;

                $files[] = $path;
            }
        }
        return $files;
    }

    private function analyze_file($path, &$state) {
        $rel_path = str_replace(ABSPATH, '', $path);
        
        // --- SNAPSHOT CHECK ---
        static $snapshot = null;
        if ($snapshot === null) {
            $snap_file = wp_upload_dir()['basedir'] . '/tegatai-logs/snapshot.json';
            $snapshot = file_exists($snap_file) ? json_decode(file_get_contents($snap_file), true) : [];
        }
        
        if (!empty($snapshot)) {
            if (!isset($snapshot[$rel_path])) {
                $this->add_bad($state, $path, "NEUE DATEI (Nicht im Snapshot)");
            } elseif ($snapshot[$rel_path] !== md5_file($path)) {
                $this->add_bad($state, $path, "MODIFIZIERT (Snapshot Mismatch)");
            }
        }

        $content = @file_get_contents($path);
        if (!$content) return;

        $patterns = [
            'eval\s*\(' => 'eval() Found',
            // 'base64_decode\s*\(' => 'base64_decode() Found', // TEGATAI_FIX: Deaktiviert, reduziert Fehlalarme
            'shell_exec\s*\(' => 'shell_exec() Found',
            'passthru\s*\(' => 'passthru() Found',
            'system\s*\(' => 'system() Found',
            'gzinflate\s*\(' => 'gzinflate() Found',
            '\\x[0-9a-f]{2}' => 'Hex Obfuscation'
        ];

        foreach ($patterns as $pattern => $desc) {
            if ($pattern === '\\x[0-9a-f]{2}') {
                // Hex check: nur alarmieren wenn > 50 Vorkommen
                if (preg_match_all('/\\\\x[0-9a-f]{2}/', $content) > 50) {
                    $this->add_bad($state, $path, "Heavy Hex Obfuscation");
                    break;
                }
                continue;
            }

            if (preg_match('/' . $pattern . '/i', $content)) {
                // Ignore self
                if (strpos($path, 'tegatai-secure') !== false) continue;
                
                $this->add_bad($state, $path, $desc);
                
                // --- TEGATAI PRO: Auto-Quarantäne (IPS) ---
                $ops = get_option('tegatai_options');
                
                // Wir verschieben nur Dateien aus dem Upload-Ordner in Quarantäne (Schutz vor Zerstörung des WP-Cores)
                if (!empty($ops['enable_auto_quarantine']) && strpos($path, wp_upload_dir()['basedir']) !== false) {
                    $quarantine_dir = wp_upload_dir()['basedir'] . '/tegatai-quarantine/';
                    
                    if (!is_dir($quarantine_dir)) {
                        wp_mkdir_p($quarantine_dir);
                        file_put_contents($quarantine_dir . '.htaccess', "Order Deny,Allow\nDeny from all");
                        file_put_contents($quarantine_dir . 'index.php', '<?php // Silence');
                    }
                    
                    $safe_filename = time() . '_' . basename($path) . '.quarantine';
                    $target_path = $quarantine_dir . $safe_filename;
                    
                    if (@rename($path, $target_path)) {
                        Tegatai_Logger::log('SEC-WARN', "Malware in Quarantäne verschoben: " . basename($path));
                        
                        // Status im Scan-Array updaten
                        $last_idx = count($state['bad_files']) - 1;
                        $state['bad_files'][$last_idx]['issue'] .= " (Verschoben in Quarantäne)";
                    }
                }
                
                break;
            }
        }
    }

    private function add_bad(&$state, $path, $issue) {
        $rel = str_replace(ABSPATH, '', $path);
        foreach ($state['bad_files'] as $b) if ($b['file'] === $rel) return;
        $state['bad_files'][] = ['file' => $rel, 'issue' => $issue];
    }

    public function check_cve_vulnerabilities() {
        if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = get_plugins();
        foreach ($plugins as $file => $data) {
            $slug = dirname($file);
            if ($slug === '.' || strpos($slug, 'tegatai') !== false) continue;
            
            // Sichere Abfrage der WP Vulnerability API
            $response = wp_remote_get("https://www.wpvulnerability.net/plugin/{$slug}/", ['timeout' => 5, 'sslverify' => true]);
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (!empty($body['data']['vulnerability'])) {
                    foreach ($body['data']['vulnerability'] as $vuln) {
                        $vuln_title = sanitize_text_field($vuln['title'] ?? 'Unbekannte Lücke');
                        Tegatai_Logger::log('SEC-WARN', "CVE in Plugin '{$slug}': " . $vuln_title);
                        break; 
                    }
                }
            }
        }
    }

}
