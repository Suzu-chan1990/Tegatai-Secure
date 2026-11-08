<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- Tegatai uses its own tables (logs, settings) and live security data; queries are prepared and caching would serve stale data

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
        if ($freq === 'weekly' && gmdate('N') != 1) return;
        $this->create_db_backup('cron');
    }

    public function create_backup_action() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        if ($this->create_db_backup('manual')) { 
            wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=created')); 
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

    const ENC_MAGIC    = 'TGB2';
    const ENC_MAGIC_V3 = 'TGB3';
    const CHUNK        = 1048576;

    // Raw 32-byte key. The stored secret is 64 hex chars; passing it directly made OpenSSL
    // silently truncate it to 32 characters (128 bit).
    private function derive_key($purpose) {
        return hash_hmac('sha256', 'tegatai-backup-' . $purpose, $this->get_encryption_key(), true);
    }

    // --- Backup key pair (format v3, same approach as the Hive node keys) ---

    public static function sodium_available() {
        return function_exists('sodium_crypto_box_seal') && function_exists('sodium_crypto_secretstream_xchacha20poly1305_init_push');
    }

    /**
     * Key file next to tegatai-secrets.php (outside the web root).
     * Another location: define('TEGATAI_BACKUP_KEY_FILE', '/path/tegatai-backup-key.php') in wp-config.php.
     */
    public static function key_file() {
        if (defined('TEGATAI_BACKUP_KEY_FILE')) return (string) TEGATAI_BACKUP_KEY_FILE;
        return dirname(tegatai_secrets_file()) . '/tegatai-backup-key.php';
    }

    /**
     * X25519 keys from the key file written by "wp tegatai backup-keygen":
     * ['public' => 32 bytes or '', 'secret' => 32 bytes or ''].
     * A file with only the public key can encrypt but not decrypt (private key kept offline).
     * Tegatai never creates this key on its own.
     */
    public static function own_keys() {
        static $keys = null;
        if ($keys !== null) return $keys;
        $keys = ['public' => '', 'secret' => ''];
        if (!self::sodium_available()) return $keys;
        $file = self::key_file();
        if ($file === '' || !@is_file($file) || !@is_readable($file)) return $keys;
        $data = include $file;
        if (!is_array($data)) return $keys;
        $sk = isset($data['private_key']) && is_string($data['private_key']) ? base64_decode(trim($data['private_key']), true) : false;
        $pk = isset($data['public_key']) && is_string($data['public_key']) ? base64_decode(trim($data['public_key']), true) : false;
        if (is_string($sk) && strlen($sk) === SODIUM_CRYPTO_BOX_SECRETKEYBYTES) {
            $keys['secret'] = $sk;
            $keys['public'] = sodium_crypto_box_publickey_from_secretkey($sk);
        } elseif (is_string($pk) && strlen($pk) === SODIUM_CRYPTO_BOX_PUBLICKEYBYTES) {
            $keys['public'] = $pk;
        }
        return $keys;
    }

    /**
     * Creates a new key pair and writes it to the key file (0600, folder 0700). Only called by
     * the WP-CLI command the admin runs explicitly. Refuses to overwrite an existing key unless
     * $replace is true. Returns the key file path or a WP_Error.
     */
    public static function write_new_key($replace = false) {
        if (!self::sodium_available()) return new WP_Error('sodium', 'The PHP sodium extension is missing.');
        $file = self::key_file();
        if (@is_file($file) && !$replace) return new WP_Error('exists', 'A backup key already exists: ' . $file . ' (use --replace to create a new one; backups made with the old key can then only be decrypted with a copy of the old key file).');
        $dir = dirname($file);
        if (!is_dir($dir) && !@mkdir($dir, 0700, true)) return new WP_Error('dir', 'Folder could not be created: ' . $dir);
        if (!is_writable($dir)) return new WP_Error('dir', 'Folder is not writable: ' . $dir);

        $pair = sodium_crypto_box_keypair();
        $sk   = sodium_crypto_box_secretkey($pair);
        $pk   = sodium_crypto_box_publickey($pair);
        $php  = "<?php\n// Tegatai backup key (X25519) of " . home_url() . ". Without the private key the backups cannot be decrypted: keep a copy in a safe place.\n"
              . "if ( ! defined( 'ABSPATH' ) ) exit;\n"
              . "return [ 'private_key' => '" . base64_encode($sk) . "', 'public_key' => '" . base64_encode($pk) . "', 'created' => '" . gmdate('c') . "' ];\n";
        sodium_memzero($sk);
        sodium_memzero($pair);

        $tmp = $file . '.tmp-' . bin2hex(random_bytes(4));
        $old = umask(0077);
        $ok  = file_put_contents($tmp, $php, LOCK_EX);
        umask($old);
        if ($ok === false) { @unlink($tmp); return new WP_Error('write', 'The key file could not be written.'); }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $file)) { @unlink($tmp); return new WP_Error('write', 'The key file could not be written.'); }
        if (function_exists('opcache_invalidate')) @opcache_invalidate($file, true);
        return $file;
    }

    /**
     * Format v3: "TGB3" | crypto_box_seal(file key) (80 bytes) | secretstream header (24 bytes) |
     * chunks of [4-byte length | XChaCha20-Poly1305 ciphertext], the last one tagged FINAL.
     * Every backup gets its own random file key, sealed to the public key, so the server only
     * needs the public key to write backups. Magic and sealed key are authenticated with every chunk.
     */
    private function encrypt_v3($plain, $pk) {
        $file_key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
        $sealed   = sodium_crypto_box_seal($file_key, $pk);
        [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($file_key);
        sodium_memzero($file_key);
        $ad  = self::ENC_MAGIC_V3 . $sealed;
        $out = $ad . $header;
        $len = strlen($plain);
        $pos = 0;
        do {
            $chunk = (string) substr($plain, $pos, self::CHUNK);
            $pos  += self::CHUNK;
            $tag   = $pos >= $len ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
            $c     = sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, $ad, $tag);
            $out  .= pack('N', strlen($c)) . $c;
        } while ($pos < $len);
        return $out;
    }

    private function decrypt_v3($data) {
        $keys = self::own_keys();
        if ($keys['secret'] === '') return new WP_Error('nokey', __('This backup needs the private backup key, which is not on this server.', 'tegatai-secure'));
        $seal_len = SODIUM_CRYPTO_BOX_SEALBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;
        $hdr_len  = SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES;
        if (strlen($data) < 4 + $seal_len + $hdr_len) return false;
        $sealed = substr($data, 4, $seal_len);
        $header = substr($data, 4 + $seal_len, $hdr_len);
        $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($keys['secret'], $keys['public']);
        $file_key = sodium_crypto_box_seal_open($sealed, $kp);
        sodium_memzero($kp);
        if ($file_key === false) return false;
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $file_key);
        sodium_memzero($file_key);
        $ad  = self::ENC_MAGIC_V3 . $sealed;
        $pos = 4 + $seal_len + $hdr_len;
        $end = strlen($data);
        $out = '';
        $final = false;
        while ($pos < $end) {
            if ($final || $pos + 4 > $end) return false;
            $n = unpack('N', substr($data, $pos, 4))[1];
            $pos += 4;
            if ($n < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $pos + $n > $end) return false;
            $r = sodium_crypto_secretstream_xchacha20poly1305_pull($state, substr($data, $pos, $n), $ad);
            if ($r === false) return false;
            [$chunk, $tag] = $r;
            $out .= $chunk;
            $pos += $n;
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) $final = true;
        }
        // A file cut off before the FINAL chunk is rejected (truncation is detected)
        return $final ? $out : false;
    }

    // Format v2: "TGB2" | 12-byte nonce | 16-byte GCM tag | ciphertext
    private function encrypt($plain) {
        $nonce = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($plain, 'aes-256-gcm', $this->derive_key('enc'), OPENSSL_RAW_DATA, $nonce, $tag, self::ENC_MAGIC, 16);
        return $cipher === false ? false : self::ENC_MAGIC . $nonce . $tag . $cipher;
    }

    private function decrypt($data) {
        if (strncmp($data, self::ENC_MAGIC_V3, 4) === 0) {
            if (!self::sodium_available()) return false;
            return $this->decrypt_v3($data);
        }
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
        $sql = "<?php exit; ?>\n-- Tegatai Backup ($type) - " . gmdate('Y-m-d H:i:s') . "\n\n";
        
        foreach ($tables as $table) {
            $tbl = $table[0]; 
            $row2 = $wpdb->get_row($wpdb->prepare('SHOW CREATE TABLE %i', $tbl), ARRAY_N); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- database backup
            $sql .= "\n\n" . $row2[1] . ";\n\n"; 
            
            $rows = $wpdb->get_results($wpdb->prepare('SELECT * FROM %i', $tbl), ARRAY_N); // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- database backup
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
        $hash = substr(md5(uniqid(wp_rand(), true)), 0, 8);
        $filename = 'db_backup_' . gmdate('Y-m-d_H-i-s') . '_' . $type . '_' . $hash . '.sql.php';
        
        // 1. ZLIB Komprimierung (Verschlüsselte Daten lassen sich nicht gut packen, also erst komprimieren)
        if (function_exists('gzencode')) { 
            $sql = gzencode($sql, 9);
            $filename .= '.gz'; 
        }

        // 2. Encryption: v3 (X25519 + XChaCha20-Poly1305) with a backup key pair, otherwise
        //    AES-256-GCM with TEGATAI_BACKUP_SECRET. Both are authenticated.
        $keys = self::own_keys();
        if ($keys['public'] !== '') {
            $sql = $this->encrypt_v3($sql, $keys['public']);
            $filename .= '.enc';
        } elseif (function_exists('openssl_encrypt') && in_array('aes-256-gcm', openssl_get_cipher_methods(), true)) {
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
            wp_delete_file($file);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP-GC', "Auto-deleted old backup: " . basename($file));
        }
    }

    public function delete_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name(wp_unslash($_POST['file'] ?? '')); 
        $path = $this->backup_dir . $file;
        
        // SECURITY FIX: Robuster Check
        if (!file_exists($path)) {
            wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=deleted'));
            exit;
        }

        if (dirname($path) !== rtrim($this->backup_dir, '/')) {
             if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('SEC-WARN', "Invalid delete path: $path");
             wp_die("Security Check Failed.");
        }

        wp_delete_file($path); 
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP', "Gelöscht: $file"); 
        
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=deleted')); 
        exit;
    }

    public function download_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('teg_backup_nonce');
        
        $file = sanitize_file_name(wp_unslash($_POST['file'] ?? '')); 
        $path = $this->backup_dir . $file;
        
        if (file_exists($path) && dirname($path) === rtrim($this->backup_dir, '/')) {
            $data = file_get_contents($path);
            $dl_name = basename($path);
            
            // --- ON-THE-FLY DECRYPTION ---
            if (substr($path, -4) === '.enc') {
                $decrypted = $this->decrypt($data);
                if (is_wp_error($decrypted)) {
                    wp_die(esc_html($decrypted->get_error_message()));
                }
                if ($decrypted !== false) {
                    $data = $decrypted;
                    $dl_name = str_replace('.enc', '', $dl_name); // Originalendung wiederherstellen (.gz oder .sql)
                } else {
                    wp_die(esc_html__('Decryption failed: wrong key (backup key file or TEGATAI_BACKUP_SECRET) or the file was modified.', 'tegatai-secure'));
                }
            }

            header('Content-Type: application/octet-stream'); 
            header('Content-Disposition: attachment; filename="'.$dl_name.'"'); 
            header('Content-Length: ' . strlen($data)); 
            echo $data; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- binary file download (SQL dump), not HTML
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
                        'date' => gmdate("Y-m-d H:i", filemtime($dir . $file))
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

/**
 * WP-CLI command for the backup key. Run it as the site's FPM user, never as root,
 * so the key file belongs to the user PHP runs as:
 *   sudo -u <fpm-user> wp tegatai backup-keygen --path=/path/to/site
 */
if (defined('WP_CLI') && WP_CLI) {
    /**
     * Creates the X25519 key pair for encrypted database backups (format v3).
     *
     * The key pair is written to secrets/tegatai-backup-key.php next to tegatai-secrets.php
     * (file 0600, folder 0700) and is never printed. Keep a copy of the file in a safe place:
     * without it the backups cannot be decrypted.
     *
     * [--replace]
     * : Replace an existing key. Older backups then need a copy of the old key file.
     */
    WP_CLI::add_command('tegatai backup-keygen', function ($args, $assoc) {
        $r = Tegatai_Backup::write_new_key(!empty($assoc['replace']));
        if (is_wp_error($r)) WP_CLI::error($r->get_error_message());
        WP_CLI::success('Backup key written to ' . $r);
        WP_CLI::log('New backups are encrypted with this key. Keep a copy of the file outside the server.');
    });
}
