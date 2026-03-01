<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

class Tegatai_Backup {
    private $backup_dir;

    public function __construct() {
        $upload = wp_upload_dir();
        $this->backup_dir = trailingslashit($upload['basedir']) . 'tegatai-backups/';
        
        add_action('admin_post_tegatai_create_backup', [$this, 'create_backup_action']);
        add_action('admin_post_tegatai_delete_backup', [$this, 'delete_backup']);
        add_action('admin_post_tegatai_download_backup', [$this, 'download_backup']);
        add_action('tegatai_daily_backup_event', [$this, 'cron_job']);
    }

    public function cron_job() {
        $ops = get_option('tegatai_options');
        if (empty($ops['enable_auto_backup'])) return;
        $freq = isset($ops['backup_frequency']) ? $ops['backup_frequency'] : 'daily';
        if ($freq === 'weekly' && date('N') != 1) return;
        $this->create_db_backup('cron');
    }

    public function create_backup_action() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        if ($this->create_db_backup('manual')) { 
            wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=backups&msg=created')); 
        } else { 
            wp_die(esc_html__('Backup Error.', 'tegatai-secure')); 
        } 
        exit;
    }

    private function create_db_backup($type = 'manual') {
        global $wpdb;
        
        // Ordner + Schutz erstellen
        if (!file_exists($this->backup_dir)) {
            mkdir($this->backup_dir, 0755, true);
            if (!file_exists($this->backup_dir . '.htaccess')) file_put_contents($this->backup_dir . '.htaccess', "Order Deny,Allow\nDeny from all");
            if (!file_exists($this->backup_dir . 'index.php')) file_put_contents($this->backup_dir . 'index.php', '<?php // Silence');
        }
        
        // Tabellen exportieren
        $tables = $wpdb->get_results('SHOW TABLES', ARRAY_N);
        $sql = "<?php exit; ?>\n-- Tegatai Backup ($type) - " . date('Y-m-d H:i:s') . "\n\n";
        
        foreach ($tables as $table) {
            $tbl = $table[0]; 
            $row2 = $wpdb->get_row('SHOW CREATE TABLE ' . $tbl, ARRAY_N);
            $sql .= "\n\n" . $row2[1] . ";\n\n"; 
            
            $rows = $wpdb->get_results('SELECT * FROM ' . $tbl, ARRAY_N);
            foreach ($rows as $row) {
                $sql .= "INSERT INTO $tbl VALUES("; 
                $vals = [];
                foreach ($row as $v) { 
                    // PHP 8 FIX: Null-Werte abfangen
                    if ($v === null) {
                        $vals[] = 'NULL'; 
                    } else { 
                        $v = addslashes($v); 
                        $v = str_replace("\n", "\\n", $v); 
                        $vals[] = '"' . $v . '"'; 
                    }
                }
                $sql .= implode(',', $vals) . ");\n";
            }
        }
        
        // SECURITY: Zufalls-Hash im Dateinamen
        $hash = substr(md5(uniqid(rand(), true)), 0, 8);
        $filename = 'db_backup_' . date('Y-m-d_H-i-s') . '_' . $type . '_' . $hash . '.sql.php';
        $path = $this->backup_dir . $filename;
        
        // Komprimierung wenn möglich
        if (function_exists('gzopen')) { 
            $filename .= '.gz'; 
            $path .= '.gz'; 
            $fp = gzopen($path, 'w9'); 
            gzwrite($fp, $sql); 
            gzclose($fp); 
        } else { 
            file_put_contents($path, $sql); 
        }
        
        Tegatai_Logger::log('BACKUP', "Backup erstellt: $filename"); 
        return true;
    }

    public function delete_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name($_POST['file']); 
        $path = $this->backup_dir . $file;
        
        // SECURITY FIX: Robuster Check
        // 1. Datei muss existieren
        if (!file_exists($path)) {
            // Könnte schon gelöscht sein -> Redirect ohne Fehler
            wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=backups&msg=deleted'));
            exit;
        }

        // 2. Pfad muss im Backup-Verzeichnis sein. 
        // sanitize_file_name() entfernt bereits .. und /, daher reicht ein dirname Check zur Sicherheit.
        if (dirname($path) !== rtrim($this->backup_dir, '/')) {
             Tegatai_Logger::log('SEC-WARN', "Invalid delete path: $path");
             wp_die("Security Check Failed.");
        }

        unlink($path); 
        Tegatai_Logger::log('BACKUP', "Gelöscht: $file"); 
        
        wp_redirect(admin_url('admin.php?page=tegatai-secure&tab=backups&msg=deleted')); 
        exit;
    }

    public function download_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name($_POST['file']); 
        $path = $this->backup_dir . $file;
        
        if (file_exists($path) && dirname($path) === rtrim($this->backup_dir, '/')) {
            header('Content-Type: application/octet-stream'); 
            header('Content-Disposition: attachment; filename="'.basename($path).'"'); 
            header('Content-Length: ' . filesize($path)); 
            readfile($path); 
            exit;
        } 
        wp_die('File not found or access denied.');
    }

    public static function get_backups() {
        $upload = wp_upload_dir(); 
        $dir = trailingslashit($upload['basedir']) . 'tegatai-backups/'; 
        $files = [];
        
        if (file_exists($dir)) {
            foreach (scandir($dir) as $file) {
                if ($file !== '.' && $file !== '..' && $file !== '.htaccess' && $file !== 'index.php') {
                    $files[] = [
                        'name' => $file, 
                        'size' => round(filesize($dir . $file) / 1024, 2) . ' KB', 
                        'date' => date("Y-m-d H:i", filemtime($dir . $file))
                    ];
                }
            }
        } 
        return array_reverse($files);
    }
}
