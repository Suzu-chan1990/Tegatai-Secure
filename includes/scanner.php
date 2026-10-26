<?php

/* TEGATAI_REMAINING_FIXES_V1 applied 2026-02-26 17:47:52 */
/* TEGATAI_SCANNER_REFINEMENT_V1 applied */
/* TEGATAI_SCANNER_FINAL_TURBO_V1 applied */
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Scanner {
    public function __construct() {
        add_action('admin_post_tegatai_scan_start', [$this, 'start_scan']);
        add_action('admin_post_tegatai_scan_process', [$this, 'process_scan']);
        add_action('tegatai_daily_maintenance', [$this, 'auto_night_scan']);
        add_action('tegatai_daily_maintenance', [$this, 'check_cve_vulnerabilities']);
        add_action('admin_post_tegatai_scan_snapshot', [$this, 'create_snapshot']);

        // Asynchroner Background-Scanner (Self-Contained)
        add_action('tegatai_bg_scan_chunk', [$this, 'process_bg_chunk']);
        add_action('wp_ajax_tegatai_start_bg_scan', [$this, 'start_bg_scan_ajax']);
    }

    // Unified Cache Engine (Memory First)
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

    // Protected log directory (tegatai-logs has .htaccess/index.php)
    private function logs_dir() {
        $dir = wp_upload_dir()['basedir'] . '/tegatai-logs/';
        if (function_exists('tegatai_protect_directory')) {
            tegatai_protect_directory($dir);
        } elseif (!is_dir($dir)) {
            wp_mkdir_p($dir);
        }
        return $dir;
    }

    public function create_snapshot() {
        check_admin_referer('teg_scan_nonce');
        if (!current_user_can('manage_options')) wp_die('Access Denied');

        $files = $this->get_content_files();
        $snapshot = [];
        foreach ($files as $file) {
            $snapshot[str_replace(ABSPATH, '', $file)] = md5_file($file);
        }

        $dir = $this->logs_dir();

        file_put_contents($dir . 'snapshot.json', wp_json_encode($snapshot));
        // Cache direkt aktualisieren
        $this->set_cache('tegatai_scan_snapshot', $snapshot, 3600);

        wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=scanner&msg=snapshot_created'));
        exit;
    }

    /**
     * Daily scan. Runs through the chunked background worker instead of scanning everything in one
     * cron request (which timed out on larger sites); the alarm mail is sent when the last chunk is done.
     */
    public function auto_night_scan() {
        $state = get_option('teg_scan_status');
        // Do not interfere with a scan that is still running (stale states older than 6h are replaced).
        if (is_array($state) && !empty($state['running']) && (time() - (int)($state['start_time'] ?? 0)) < 6 * HOUR_IN_SECONDS) {
            return;
        }

        // No scan_token: the admin page must not drive this scan via admin-post in parallel to cron.
        update_option('teg_scan_status', [
            'running' => true,
            'phase' => 'core',
            'offset' => 0,
            'files_checked' => 0,
            'bad_files' => [],
            'start_time' => time(),
            'notify' => true
        ], false);

        wp_schedule_single_event(time(), 'tegatai_bg_scan_chunk');
    }

    private function send_alarm(array $bad_files) {
        $ops = tegatai_get_setting('tegatai_options');
        $to = !empty($ops['alert_email']) ? $ops['alert_email'] : get_option('admin_email');
        $msg = "🚨 Tegatai Auto-Scan Alarm!\n\nFolgende Dateien wurden modifiziert oder sind verdächtig:\n\n";
        foreach ($bad_files as $b) {
            $msg .= "- " . $b['file'] . " (" . $b['issue'] . ")\n";
        }
        $msg .= "\nBitte prüfe dein Dashboard umgehend!";
        wp_mail($to, "[Tegatai] Malware Alarm - Dateiänderung erkannt!", $msg);
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', 'Auto-Scan fand modifizierte Dateien!');
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
        ], false);

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
            wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=scanner'));
            exit;
        }

        $done = $this->run_chunk($state);
        update_option('teg_scan_status', $state, false);

        if ($done) {
            wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=scanner&msg=done'));
        } else {
            wp_redirect(admin_url('admin-post.php?action=tegatai_scan_process&scan_token=' . rawurlencode($state['scan_token'])));
        }
        exit;
    }

    /**
     * Processes one time-boxed chunk (shared by the admin-post and the cron worker).
     * The file list is enumerated once per scan and cached in the protected log directory,
     * so a chunk no longer re-walks wp-content (which alone could exceed the time budget).
     *
     * @return bool true when the scan is complete
     */
    private function run_chunk(array &$state) {
        $time_start = microtime(true);

        // Phase 1: Core Checksums
        if ($state['phase'] === 'core') {
            $this->scan_core_files($state);
            $this->get_scan_files(true);
            $state['phase'] = 'content';
            $state['offset'] = 0;
            return false;
        }

        // Phase 2: Content Scan
        $files = $this->get_scan_files(false);
        $total = count($files);
        $start = (int)$state['offset'];

        for ($i = $start; $i < $total; $i++) {
            // 5 sek limit; at least one file per chunk so the scan always progresses
            if ($i > $start && (microtime(true) - $time_start) > 5) {
                $state['offset'] = $i;
                return false;
            }

            if (is_file($files[$i])) {
                $this->analyze_file($files[$i], $state);
            }
            $state['files_checked']++;
        }

        // Fertig
        $state['running'] = false;
        $state['offset'] = $total;
        $state['last_scan'] = current_time('mysql');
        @unlink($this->scan_files_path());
        return true;
    }

    private function scan_core_files(&$state) {
        $version = get_bloginfo('version');
        $locale = get_locale();
        $url = "https://api.wordpress.org/core/checksums/1.0/?version=$version&locale=$locale";

        $response = wp_remote_get($url, ['timeout' => 10]);
        if (is_wp_error($response)) {
            $state['bad_files'][] = ['file' => 'API Error', 'issue' => 'Connection failed to WP API'];
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
                $state['bad_files'][] = ['file' => $file, 'issue' => 'Core Modified (Checksum Mismatch)'];
            }
        }
    }

    private function scan_files_path() {
        return wp_upload_dir()['basedir'] . '/tegatai-logs/scan_files.json';
    }

    // Cached, sorted file list for the running scan (stable offsets between chunks).
    private function get_scan_files($fresh) {
        $path = $this->scan_files_path();
        if (!$fresh && file_exists($path)) {
            $files = json_decode((string)@file_get_contents($path), true);
            if (is_array($files)) return $files;
        }
        $files = $this->get_content_files();
        sort($files, SORT_STRING);
        $this->logs_dir();
        @file_put_contents($path, wp_json_encode($files), LOCK_EX);
        return $files;
    }

    private function get_content_files() {
        $files = [];
        if (!is_dir(WP_CONTENT_DIR) || !is_readable(WP_CONTENT_DIR)) return $files;

        // Own storage (backups, logs, quarantine) is never scanned.
        $upload_base = wp_upload_dir()['basedir'];
        $excludes = [
            $upload_base . '/tegatai-backups',
            $upload_base . '/tegatai-logs',
            $upload_base . '/tegatai-quarantine',
            WP_CONTENT_DIR . '/tegatai-quarantine',
        ];

        // Exclusions holen
        $ops = tegatai_get_setting('tegatai_options');
        if (!empty($ops['scanner_exclusions'])) {
            $lines = explode("\n", $ops['scanner_exclusions']);
            foreach($lines as $l) if(trim($l)) $excludes[] = trim($l);
        }

        try {
            // CATCH_GET_CHILD: unreadable directories are skipped instead of throwing an UnexpectedValueException
            $dir_iterator = new RecursiveDirectoryIterator(WP_CONTENT_DIR, FilesystemIterator::SKIP_DOTS);
            $iterator = new RecursiveIteratorIterator($dir_iterator, RecursiveIteratorIterator::LEAVES_ONLY, RecursiveIteratorIterator::CATCH_GET_CHILD);

            foreach ($iterator as $file) {
                if (!$file->isDir() && strtolower(pathinfo($file, PATHINFO_EXTENSION)) === 'php') {
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
        } catch (UnexpectedValueException $e) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SCAN-ERROR', 'Directory walk failed: ' . $e->getMessage());
        }
        return $files;
    }

    // DRY: Quarantäne Verzeichnis absichern
    private function ensure_quarantine_dir() {
        $quarantine_dir = wp_upload_dir()['basedir'] . '/tegatai-quarantine/';
        if (function_exists('tegatai_protect_directory')) {
            tegatai_protect_directory($quarantine_dir);
        } elseif (!is_dir($quarantine_dir)) {
            wp_mkdir_p($quarantine_dir);
            file_put_contents($quarantine_dir . '.htaccess', "Require all denied\n");
            file_put_contents($quarantine_dir . 'index.php', '<?php // Silence');
        }
        return $quarantine_dir;
    }

    private function is_own_file($path) {
        if (defined('TEGATAI_PATH') && strpos(wp_normalize_path($path), wp_normalize_path(TEGATAI_PATH)) === 0) return true;
        return stripos($path, 'tegatai-secure') !== false;
    }

    private function analyze_file($path, &$state) {
        $rel_path = str_replace(ABSPATH, '', $path);

        // --- SNAPSHOT CHECK MIT UNIFIED CACHE ---
        static $snapshot = null;
        if ($snapshot === null) {
            $snapshot = $this->get_cache('tegatai_scan_snapshot');
            if (!$snapshot) {
                $snap_file = wp_upload_dir()['basedir'] . '/tegatai-logs/snapshot.json';
                $snapshot = file_exists($snap_file) ? json_decode(file_get_contents($snap_file), true) : [];
                $this->set_cache('tegatai_scan_snapshot', $snapshot, 3600);
            }
        }

        if (!empty($snapshot)) {
            if (!isset($snapshot[$rel_path])) {
                $this->add_bad($state, $path, "NEUE DATEI (Nicht im Snapshot)");
            } elseif ($snapshot[$rel_path] !== md5_file($path)) {
                $this->add_bad($state, $path, "MODIFIZIERT (Snapshot Mismatch)");
            }
        }

        // Ignore self (the signatures below are part of this plugin's own source)
        if ($this->is_own_file($path)) return;

        $content = @file_get_contents($path);
        if (!$content) return;

        // Hex check: nur alarmieren wenn > 50 Vorkommen von literal "\xNN"
        if (preg_match_all('/\\\\x[0-9a-f]{2}/i', $content) > 50) {
            $this->add_bad($state, $path, "Heavy Hex Obfuscation");
            return;
        }

        // The lookbehind excludes method/static calls and identifiers that merely end in the
        // function name (WP_Filesystem(), retrieval(), $obj->system()).
        $patterns = [
            '(?<![\w$>:])eval\s*\(' => 'eval() Found',
            '(?<![\w$>:])shell_exec\s*\(' => 'shell_exec() Found',
            '(?<![\w$>:])passthru\s*\(' => 'passthru() Found',
            '(?<![\w$>:])system\s*\(' => 'system() Found',
            '(?<![\w$>:])gzinflate\s*\(' => 'gzinflate() Found',
        ];

        foreach ($patterns as $pattern => $desc) {
            // ReDoS Shield for File Content
            $matched = @preg_match('/' . $pattern . '/i', $content);
            if ($matched === false) {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SCAN-ERROR', "Regex failed (PCRE Err: " . preg_last_error() . ") for pattern: $pattern");
            } elseif ($matched) {
                $this->add_bad($state, $path, $desc);

                // --- TEGATAI PRO: Auto-Quarantäne (IPS) ---
                $ops = tegatai_get_setting('tegatai_options');

                // Wir verschieben nur Dateien aus dem Upload-Ordner in Quarantäne (Schutz vor Zerstörung des WP-Cores)
                if (!empty($ops['enable_auto_quarantine']) && strpos($path, wp_upload_dir()['basedir']) !== false) {
                    $quarantine_dir = $this->ensure_quarantine_dir();
                    $safe_filename = time() . '_' . basename($path) . '.quarantine';
                    $target_path = $quarantine_dir . $safe_filename;

                    if (@rename($path, $target_path)) {
                        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', "Malware in Quarantäne verschoben: " . basename($path));

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

    // Operators accepted by version_compare(); anything else would throw a ValueError on PHP 8.
    private static $version_ops = ['<', 'lt', '<=', 'le', '>', 'gt', '>=', 'ge', '==', '=', 'eq', '!=', '<>', 'ne'];

    /**
     * Defensive parsing of a wpvulnerability.net entry. Only reports true when the affected range
     * can be determined; unknown formats are treated as "not vulnerable" instead of flagging every
     * plugin that ever had an advisory.
     */
    private function version_is_affected($installed, $vuln) {
        if (!is_array($vuln)) return false;
        $op = $vuln['operator'] ?? null;

        // Range object: {min_version, min_operator, max_version, max_operator, unfixed}
        if (is_array($op)) {
            $has_bound = false;
            foreach (['min', 'max'] as $side) {
                $ver = $op[$side . '_version'] ?? null;
                $cmp = $op[$side . '_operator'] ?? null;
                if ($ver === null || $ver === '') continue;
                if (!is_string($cmp) || !in_array($cmp, self::$version_ops, true)) return false;
                if (!version_compare($installed, (string)$ver, $cmp)) return false;
                $has_bound = true;
            }
            if ($has_bound) return true;
            // No version bounds at all: only an explicit "unfixed" marker counts
            return !empty($op['unfixed']) && (string)$op['unfixed'] === '1';
        }

        // Flat format: operator + version
        if (is_string($op) && isset($vuln['version']) && is_scalar($vuln['version'])) {
            if (!in_array($op, self::$version_ops, true)) return false;
            return version_compare($installed, (string)$vuln['version'], $op);
        }

        if (!empty($vuln['fixed_in']) && is_scalar($vuln['fixed_in'])) {
            return version_compare($installed, (string)$vuln['fixed_in'], '<');
        }

        return false;
    }

    public function check_cve_vulnerabilities() {
        if (!function_exists('get_plugins')) require_once ABSPATH . 'wp-admin/includes/plugin.php';
        $plugins = get_plugins();
        $time_start = microtime(true);
        foreach ($plugins as $file => $data) {
            // Overall budget so the daily cron run cannot be stalled by a slow API
            if ((microtime(true) - $time_start) > 60) break;

            $slug = dirname($file);
            if ($slug === '.' || strpos($slug, 'tegatai') !== false) continue;

            $installed_version = $data['Version'] ?? '0.0.0';
            if ($installed_version === '') continue;

            // Sichere Abfrage der WP Vulnerability API
            $response = wp_remote_get('https://www.wpvulnerability.net/plugin/' . rawurlencode($slug) . '/', ['timeout' => 5, 'sslverify' => true]);
            if (!is_wp_error($response) && wp_remote_retrieve_response_code($response) === 200) {
                $body = json_decode(wp_remote_retrieve_body($response), true);
                if (!empty($body['data']['vulnerability']) && is_array($body['data']['vulnerability'])) {
                    foreach ($body['data']['vulnerability'] as $vuln) {
                        if ($this->version_is_affected($installed_version, $vuln)) {
                            $vuln_title = sanitize_text_field($vuln['name'] ?? ($vuln['title'] ?? 'Unbekannte Lücke'));
                            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', "CVE in Plugin '{$slug}' (Installiert: v{$installed_version}): " . $vuln_title);
                            break; // Nur einen Alarm pro anfälligem Plugin triggern
                        }
                    }
                }
            }
        }
    }

    /**
     * Startet den asynchronen Scan via AJAX
     */
    public function start_bg_scan_ajax() {
        check_ajax_referer('teg_scan_nonce', 'security');
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
        ], false);

        wp_schedule_single_event(time(), 'tegatai_bg_scan_chunk');
        wp_send_json_success(['msg' => 'Background scan started successfully.']);
    }

    /**
     * Der unsichtbare Background-Worker (WP-Cron) - Self-Contained Engine
     */
    public function process_bg_chunk() {
        $state = get_option('teg_scan_status');
        if (empty($state) || empty($state['running'])) return;

        $done = $this->run_chunk($state);
        update_option('teg_scan_status', $state, false);

        if (!$done) {
            wp_schedule_single_event(time() + 1, 'tegatai_bg_scan_chunk');
            return;
        }

        // Scan ist komplett durchgelaufen
        if (class_exists('Tegatai_Logger')) {
            $hits = count($state['bad_files']);
            Tegatai_Logger::log('SCAN', "Background Scan beendet. Dateien: {$state['files_checked']}, Treffer: {$hits}");
        }
        if (!empty($state['notify']) && !empty($state['bad_files'])) {
            $this->send_alarm($state['bad_files']);
        }
    }

}
