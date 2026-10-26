<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/* TEGATAI_BACKUP_ENCRYPTION_V1 applied */
class Tegatai_Backup {
    private $backup_dir;

    public function __construct() {
        $upload = wp_upload_dir();
        $this->backup_dir = trailingslashit($upload['basedir']) . 'tegatai-backups/';
        if (!is_dir($this->backup_dir)) { tegatai_protect_directory($this->backup_dir); }
        
        add_action('admin_post_tegatai_create_backup', [$this, 'create_backup_action']);
        add_action('admin_post_tegatai_delete_backup', [$this, 'delete_backup']);
        add_action('admin_post_tegatai_download_backup', [$this, 'download_backup']);
        add_action('tegatai_daily_backup_event', [$this, 'cron_job']);
    }

    public function cron_job() {
        $ops = tegatai_get_setting('tegatai_options');
        if (empty($ops['enable_auto_backup'])) return;
        $freq = isset($ops['backup_frequency']) ? $ops['backup_frequency'] : 'daily';
        if ($freq === 'weekly' && date('N') != 1) return;
        $this->create_db_backup('cron');
    }

    public function create_backup_action() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        if ($this->create_db_backup('manual')) { 
            wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=created')); 
        } else { 
            wp_die(esc_html__('Backup Error.', 'tegatai-secure')); 
        } 
        exit;
    }

    // --- ENCRYPTION KEY MANAGER ---
    private function get_encryption_key() {
        if (defined('TEGATAI_BACKUP_SECRET')) return TEGATAI_BACKUP_SECRET;
        $secret = get_option('tegatai_backup_secret');
        if (empty($secret)) {
            $secret = bin2hex(random_bytes(32));
            update_option('tegatai_backup_secret', $secret, false);
        }
        return $secret;
    }

    const ENC_MAGIC = 'TGB2';

    // Raw 32-byte key. The stored secret is 64 hex chars; passing it directly made OpenSSL
    // silently truncate it to 32 characters (128 bit).
    private function derive_key($purpose) {
        return hash_hmac('sha256', 'tegatai-backup-' . $purpose, $this->get_encryption_key(), true);
    }

    // Format v2: "TGB2" | 12-byte nonce | 16-byte GCM tag | ciphertext
    private function encrypt($plain) {
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $this->derive_key('enc'), OPENSSL_RAW_DATA, $nonce, $tag, self::ENC_MAGIC, 16);
        return $cipher === false ? false : self::ENC_MAGIC . $nonce . $tag . $cipher;
    }

    private function decrypt($data) {
        if (strncmp($data, self::ENC_MAGIC, 4) === 0) {
            $nonce = substr($data, 4, 12);
            $tag = substr($data, 16, 16);
            return openssl_decrypt(substr($data, 32), 'aes-256-gcm', $this->derive_key('enc'), OPENSSL_RAW_DATA, $nonce, $tag, self::ENC_MAGIC);
        }
        // Legacy v1 files: AES-256-CBC, IV prepended, hex secret used as key (unauthenticated)
        $iv_len = openssl_cipher_iv_length('aes-256-cbc');
        return openssl_decrypt(substr($data, $iv_len), 'aes-256-cbc', $this->get_encryption_key(), OPENSSL_RAW_DATA, substr($data, 0, $iv_len));
    }

    private function create_db_backup($type = 'manual') {
        global $wpdb;
        
        // Ordner + Schutz sicherstellen
        tegatai_protect_directory($this->backup_dir);
        
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
        
        // 1. ZLIB Komprimierung (Verschlüsselte Daten lassen sich nicht gut packen, also erst komprimieren)
        if (function_exists('gzencode')) { 
            $sql = gzencode($sql, 9);
            $filename .= '.gz'; 
        }

        // 2. AES-256-GCM data-at-rest encryption (authenticated, tampering is detected on decrypt)
        if (function_exists('openssl_encrypt') && in_array('aes-256-gcm', openssl_get_cipher_methods(), true)) {
            $encrypted = $this->encrypt($sql);
            
            if ($encrypted !== false) {
                $sql = $encrypted;
                $filename .= '.enc';
            } else {
                if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP-ERR', "AES Encryption failed. Saving unencrypted.");
            }
        }
        
        $path = $this->backup_dir . $filename;
        file_put_contents($path, $sql); 
        
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP', "Backup erstellt: $filename"); 
        
        // 3. Garbage Collection (Retention Policy)
        $ops = tegatai_get_setting('tegatai_options');
        $limit = !empty($ops['backup_retention_limit']) ? intval($ops['backup_retention_limit']) : 7;
        $this->enforce_retention($limit);

        return true;
    }

    // --- GARBAGE COLLECTION ---
    private function enforce_retention($limit = 7) {
        $files = glob($this->backup_dir . 'db_backup_*');
        if (!$files || count($files) <= $limit) return;

        // Nach modification time absteigend sortieren (neueste zuerst)
        usort($files, function($a, $b) {
            return filemtime($b) - filemtime($a); 
        });

        // Alle Dateien ab dem Index $limit löschen
        $to_delete = array_slice($files, $limit);
        foreach ($to_delete as $file) {
            @unlink($file);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP-GC', "Auto-deleted old backup: " . basename($file));
        }
    }

    public function delete_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name($_POST['file']); 
        $path = $this->backup_dir . $file;
        
        // SECURITY FIX: Robuster Check
        if (!file_exists($path)) {
            wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=deleted'));
            exit;
        }

        if (dirname($path) !== rtrim($this->backup_dir, '/')) {
             if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', "Invalid delete path: $path");
             wp_die("Security Check Failed.");
        }

        unlink($path); 
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP', "Gelöscht: $file"); 
        
        wp_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=deleted')); 
        exit;
    }

    public function download_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name($_POST['file']); 
        $path = $this->backup_dir . $file;
        
        if (file_exists($path) && dirname($path) === rtrim($this->backup_dir, '/')) {
            $data = file_get_contents($path);
            $dl_name = basename($path);
            
            // --- ON-THE-FLY DECRYPTION ---
            if (substr($path, -4) === '.enc' && function_exists('openssl_decrypt')) {
                $decrypted = $this->decrypt($data);
                if ($decrypted !== false) {
                    $data = $decrypted;
                    $dl_name = str_replace('.enc', '', $dl_name); // Originalendung wiederherstellen (.gz oder .sql)
                } else {
                    wp_die(esc_html__('Decryption failed: wrong TEGATAI_BACKUP_SECRET or the file was modified.', 'tegatai-secure'));
                }
            }

            header('Content-Type: application/octet-stream'); 
            header('Content-Disposition: attachment; filename="'.$dl_name.'"'); 
            header('Content-Length: ' . strlen($data)); 
            echo $data; 
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
                if (!in_array($file, ['.', '..', '.htaccess', 'index.php', 'web.config'], true)) {
                    $files[] = [
                        'name' => $file, 
                        'size' => round(filesize($dir . $file) / 1024, 2) . ' KB', 
                        'date' => date("Y-m-d H:i", filemtime($dir . $file))
                    ];
                }
            }
        } 
        
        // Nach neuestem Datum sortieren
        usort($files, function($a, $b) {
            return strtotime($b['date']) - strtotime($a['date']);
        });
        
        return $files;
    }
}
