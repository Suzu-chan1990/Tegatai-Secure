<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- a database backup reads every table directly; caching would serve stale data
// phpcs:disable WordPress.WP.AlternativeFunctions.file_system_operations_fopen, WordPress.WP.AlternativeFunctions.file_system_operations_fclose, WordPress.WP.AlternativeFunctions.file_system_operations_fread, WordPress.WP.AlternativeFunctions.file_system_operations_fwrite, WordPress.WP.AlternativeFunctions.file_system_operations_readfile -- backups are encrypted and decrypted as a stream in 1 MB chunks inside the protected uploads folder; WP_Filesystem can only read or write whole files in memory
// phpcs:disable WordPress.DB.RestrictedFunctions -- rows are read unbuffered (MYSQLI_USE_RESULT) on the connection of $wpdb so one row is in memory at a time; $wpdb only offers buffered results
// phpcs:disable WordPress.Security.EscapeOutput.ExceptionNotEscaped -- exception messages are caught in this file, returned as WP_Error and escaped where they are displayed

/**
 * Encrypted database backups.
 *
 * The dump is streamed: rows are read unbuffered, gzip-compressed and encrypted in 1 MB chunks
 * and written to a temporary file, which is only renamed to its final name when everything
 * succeeded. Backups are never written unencrypted (fail closed).
 *
 * Formats written:
 *   TGB3  backup key pair (wp tegatai backup-keygen): random file key sealed to the X25519
 *         public key, data in XChaCha20-Poly1305 secretstream chunks
 *   TGB4  no key pair: same secretstream, key derived from TEGATAI_BACKUP_SECRET
 * Formats still read: TGB2 (AES-256-GCM, Tegatai 1.5 to 2.1.0) and v1 (AES-256-CBC, before 1.5).
 */
class Tegatai_Backup {
    private $backup_dir;

    const ENC_MAGIC    = 'TGB2';
    const ENC_MAGIC_V3 = 'TGB3';
    const ENC_MAGIC_V4 = 'TGB4';
    const CHUNK        = 1048576;
    const INSERT_BATCH = 524288;
    const TMP_PREFIX   = 'tmp_';

    public function __construct() {
        $this->backup_dir = trailingslashit(tegatai_data_dir('backups'));
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
        check_admin_referer('tegatai_backup_nonce');

        $r = $this->create_db_backup('manual');
        if ($r === true) {
            wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=created'));
            exit;
        }
        wp_die(esc_html(__('Backup Error.', 'tegatai-secure') . ' ' . (is_wp_error($r) ? $r->get_error_message() : '')));
    }

    // --- Symmetric key (TGB4 and the old formats) ---

    // Backup secret from the secrets file / wp-config.php (a database copy of an older version is
    // only read until it is moved). Tegatai never creates or stores a secret in the database.
    private function get_encryption_key() {
        return tegatai_secret('TEGATAI_BACKUP_SECRET');
    }

    // Raw 32-byte key. The stored secret is 64 hex chars; passing it directly made OpenSSL
    // silently truncate it to 32 characters (128 bit).
    private function derive_key($purpose) {
        return hash_hmac('sha256', 'tegatai-backup-' . $purpose, $this->get_encryption_key(), true);
    }

    // --- Backup key pair (TGB3, same approach as the Hive node keys) ---

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
     * Creates a new X25519 key pair and returns the content of the key file. Tegatai never
     * writes key files itself: the WP-CLI command prints the content and the administrator
     * redirects it into the key file (see the command in the Backups tab).
     *
     * @return string|WP_Error
     */
    public static function new_key_file_content() {
        if (!self::sodium_available()) return new WP_Error('sodium', 'The PHP sodium extension is missing.');
        $pair = sodium_crypto_box_keypair();
        $sk   = sodium_crypto_box_secretkey($pair);
        $pk   = sodium_crypto_box_publickey($pair);
        $php  = "<?php\n// Tegatai backup key (X25519) of " . home_url() . ". Without the private key the backups cannot be decrypted: keep a copy in a safe place.\n"
              . "if ( ! defined( 'ABSPATH' ) ) exit;\n"
              . "return [ 'private_key' => '" . base64_encode($sk) . "', 'public_key' => '" . base64_encode($pk) . "', 'created' => '" . gmdate('c') . "' ];\n";
        sodium_memzero($sk);
        sodium_memzero($pair);
        return $php;
    }

    // Shell command (run as the site's PHP-FPM user) that creates the key file without overwriting one.
    public static function keygen_command() {
        $file = self::key_file();
        $sh = static function ($v) { return "'" . str_replace("'", "'\\''", (string) $v) . "'"; };
        return 'mkdir -p ' . $sh(dirname($file)) . ' && chmod 700 ' . $sh(dirname($file))
            . ' && (umask 077; wp tegatai backup-keygen --path=' . $sh(untrailingslashit(ABSPATH)) . ' > ' . $sh($file . '.new') . ')'
            . ' && mv -n ' . $sh($file . '.new') . ' ' . $sh($file);
    }

    // --- Creating a backup ---

    /**
     * Streams the database into an encrypted file.
     *
     * @return true|WP_Error
     */
    private function create_db_backup($type = 'manual') {
        $r = $this->write_backup($type);
        if (is_wp_error($r)) {
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP-ERR', 'Backup failed: ' . $r->get_error_message());
            return $r;
        }
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP', 'Backup created: ' . $r);

        // Retention only after a backup was written completely
        $ops = tegatai_get_setting('tegatai_options');
        $limit = !empty($ops['backup_retention_limit']) ? intval($ops['backup_retention_limit']) : 7;
        $this->enforce_retention($limit);
        return true;
    }

    /** @return string|WP_Error final file name */
    private function write_backup($type) {
        if (!self::sodium_available()) {
            return new WP_Error('sodium', 'The PHP sodium extension is missing; no backup is written without encryption.');
        }
        if (!tegatai_protect_directory($this->backup_dir) || !wp_is_writable($this->backup_dir)) {
            return new WP_Error('dir', 'Backup folder not writable: ' . $this->backup_dir);
        }
        if (function_exists('set_time_limit')) @set_time_limit(0); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged -- a large database takes longer than the default time limit

        $keys = self::own_keys();
        if ($keys['public'] === '' && $this->get_encryption_key() === '') {
            return new WP_Error('nokey', __('No backup key: create the backup key file or set TEGATAI_BACKUP_SECRET in the secrets file (see the Backups and Secrets tabs).', 'tegatai-secure'));
        }
        $hash = bin2hex(random_bytes(4));
        $type = sanitize_key($type);
        $filename = 'db_backup_' . gmdate('Y-m-d_H-i-s') . '_' . $type . '_' . $hash . '.sql.php' . (function_exists('deflate_init') ? '.gz' : '') . '.enc';
        $tmp = $this->backup_dir . self::TMP_PREFIX . bin2hex(random_bytes(8)) . '.part';

        $old = umask(0077);
        $fh  = @fopen($tmp, 'xb');
        umask($old);
        if (!$fh) return new WP_Error('open', 'Temporary file could not be created in ' . $this->backup_dir);

        try {
            $stream = $keys['public'] !== ''
                ? Tegatai_Backup_Stream::sealed($fh, $keys['public'])
                : Tegatai_Backup_Stream::symmetric($fh, $this->derive_key('stream'));
            $this->dump_database($stream, $type);
            $stream->finish();
            if (!fflush($fh)) throw new RuntimeException('Writing the backup file failed.');
        } catch (\Throwable $e) {
            fclose($fh);
            wp_delete_file($tmp);
            return new WP_Error('write', $e->getMessage());
        }
        if (!fclose($fh)) {
            wp_delete_file($tmp);
            return new WP_Error('write', 'Closing the backup file failed.');
        }
        if (!@rename($tmp, $this->backup_dir . $filename)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.rename_rename -- atomic: the backup only gets its final name when it is complete
            wp_delete_file($tmp);
            return new WP_Error('rename', 'The backup file could not be renamed.');
        }
        return $filename;
    }

    /** Writes the SQL dump of all base tables into the stream. */
    /**
     * Writes the SQL dump of all base tables into the stream.
     *
     * Export side: the session runs with a fixed sql_mode during the dump (no ANSI_QUOTES, so
     * SHOW CREATE TABLE uses backticks; no NO_BACKSLASH_ESCAPES, so values are escaped with
     * backslashes) and gets its old mode back afterwards.
     * Import side: the dump saves the session settings of the importing connection, sets
     * NAMES, FOREIGN_KEY_CHECKS=0 and SQL_MODE='NO_AUTO_VALUE_ON_ZERO' (a stored 0 in an
     * AUTO_INCREMENT column stays 0; backslash escapes are valid even if the importer's mode
     * had NO_BACKSLASH_ESCAPES) and restores them at the end, like mysqldump.
     */
    private function dump_database(Tegatai_Backup_Stream $out, $type) {
        global $wpdb;

        $old_mode = $wpdb->get_var('SELECT @@SESSION.sql_mode');
        if ($old_mode === null) throw new RuntimeException('sql_mode could not be read: ' . $wpdb->last_error);
        if ($wpdb->query("SET SESSION sql_mode = 'NO_AUTO_VALUE_ON_ZERO'") === false) {
            throw new RuntimeException('sql_mode could not be set: ' . $wpdb->last_error);
        }
        // One consistent snapshot for all InnoDB tables (like mysqldump --single-transaction):
        // every table shows the same point in time, also while the site keeps writing.
        // Read only; non-transactional tables (MyISAM, Aria, MEMORY) are not covered.
        $wpdb->query('SET TRANSACTION ISOLATION LEVEL REPEATABLE READ');
        if ($wpdb->query('START TRANSACTION WITH CONSISTENT SNAPSHOT, READ ONLY') === false) {
            $wpdb->query($wpdb->prepare('SET SESSION sql_mode = %s', $old_mode));
            throw new RuntimeException('Snapshot transaction could not be started: ' . $wpdb->last_error);
        }
        try {
            $notes = $this->dump_objects($out, $type);
        } finally {
            $wpdb->query('COMMIT');
            $wpdb->query($wpdb->prepare('SET SESSION sql_mode = %s', $old_mode));
        }
        if ($notes && class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('BACKUP', implode(' ', $notes));
        }
    }

    private function dump_objects(Tegatai_Backup_Stream $out, $type) {
        global $wpdb;
        $charset = preg_match('/^[A-Za-z0-9_]+$/', (string) $wpdb->charset) ? $wpdb->charset : 'utf8mb4';

        // Objects this backup does not contain are named in the dump and in the log
        $skipped = [];
        foreach ([
            'views'    => "SELECT COUNT(*) FROM information_schema.VIEWS WHERE TABLE_SCHEMA = DATABASE()",
            'triggers' => "SELECT COUNT(*) FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA = DATABASE()",
            'routines' => "SELECT COUNT(*) FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA = DATABASE()",
            'events'   => "SELECT COUNT(*) FROM information_schema.EVENTS WHERE EVENT_SCHEMA = DATABASE()",
        ] as $what => $sql) {
            $n = (int) $wpdb->get_var($sql); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- fixed statements from the list above, no input
            if ($n > 0) $skipped[] = "$what: $n";
        }

        // Tables without transactions are read without the snapshot
        $non_tx = $wpdb->get_col("SELECT TABLE_NAME FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_TYPE = 'BASE TABLE' AND ENGINE NOT IN ('InnoDB')");

        $out->write("-- <?php exit; ?>\n"
            . "-- Tegatai Backup ($type) - " . gmdate('Y-m-d H:i:s') . " UTC\n"
            . "-- Contains: all base tables (structure and data) of the database, InnoDB tables from one consistent snapshot.\n"
            . ($non_tx ? '-- Not in the snapshot (no transactions): ' . implode(', ', $non_tx) . "\n" : '')
            . ($skipped ? '-- Not contained: ' . implode(', ', $skipped) . "\n" : '')
            . "\n"
            . "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
            . "/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n"
            . "/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;\n"
            . "/*!40101 SET NAMES $charset */;\n"
            . "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n"
            . "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n\n");

        $tables = $wpdb->get_col("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'");
        if ($wpdb->last_error !== '') throw new RuntimeException('Table list: ' . $wpdb->last_error);

        foreach ($tables as $tbl) {
            $row = $wpdb->get_row($wpdb->prepare('SHOW CREATE TABLE %i', $tbl), ARRAY_N);
            if (!is_array($row) || !isset($row[1])) throw new RuntimeException("SHOW CREATE TABLE $tbl failed: " . $wpdb->last_error);
            $q = $this->quote_name($tbl);
            $out->write("\nDROP TABLE IF EXISTS $q;\n" . $row[1] . ";\n\n");

            $this->dump_rows($tbl, $out);
        }

        $out->write("\n/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n"
            . "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n"
            . "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
            . "/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n"
            . "/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n"
            . "-- Dump completed\n");

        $notes = [];
        if ($skipped) $notes[] = 'Not contained in the backup: ' . implode(', ', $skipped) . ' (only base tables are saved).';
        if ($non_tx) $notes[] = 'Not in the consistent snapshot (tables without transactions): ' . implode(', ', $non_tx) . '.';
        return $notes;
    }

    private function quote_name($name) {
        return '`' . str_replace('`', '``', (string) $name) . '`';
    }

    /**
     * Column list and value kind per column, from information_schema.
     * kind: 'num' (written unquoted), 'bin' (read as HEX(), written as 0x literal), 'str'.
     * BIT columns are read as CAST(col AS UNSIGNED), so they are plain numbers.
     */
    private function column_info($tbl) {
        global $wpdb;
        $cols = $wpdb->get_results($wpdb->prepare(
            'SELECT COLUMN_NAME, DATA_TYPE, COLUMN_KEY FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s ORDER BY ORDINAL_POSITION',
            $tbl
        ), ARRAY_A);
        $num = ['tinyint', 'smallint', 'mediumint', 'int', 'integer', 'bigint', 'decimal', 'numeric', 'float', 'double', 'real', 'year', 'bit'];
        $bin = ['binary', 'varbinary', 'tinyblob', 'blob', 'mediumblob', 'longblob', 'geometry', 'point', 'linestring', 'polygon', 'multipoint', 'multilinestring', 'multipolygon', 'geometrycollection'];
        $out = [];
        foreach ((array) $cols as $c) {
            $type = strtolower((string) $c['DATA_TYPE']);
            $n = $this->quote_name($c['COLUMN_NAME']);
            if ($type === 'bit') $sel = "CAST($n AS UNSIGNED) AS $n";
            elseif (in_array($type, $bin, true)) $sel = "HEX($n) AS $n";
            else $sel = $n;
            $out[] = [
                'name' => (string) $c['COLUMN_NAME'],
                'type' => $type,
                'pri'  => $c['COLUMN_KEY'] === 'PRI',
                'kind' => in_array($type, $num, true) ? 'num' : (in_array($type, $bin, true) ? 'bin' : 'str'),
                'sel'  => $sel,
            ];
        }
        return $out;
    }

    /**
     * Writes the rows of one table as INSERT statements, read through $wpdb in pages.
     * Tables with a single integer primary key are paged by key (WHERE pk > last), all others
     * by LIMIT/OFFSET; the backup runs inside one consistent snapshot, so both are stable.
     * Text is escaped with $wpdb's connection escaping (charset-aware).
     */
    private function dump_rows($tbl, Tegatai_Backup_Stream $out) {
        global $wpdb;
        $q    = $this->quote_name($tbl);
        $cols = $this->column_info($tbl);
        if (!$cols) throw new RuntimeException("Reading $tbl failed: no columns found");
        $select = implode(', ', array_column($cols, 'sel'));

        $pri = array_values(array_filter($cols, static function ($c) { return $c['pri']; }));
        $int_types = ['tinyint', 'smallint', 'mediumint', 'int', 'integer', 'bigint'];
        $key = (count($pri) === 1 && in_array($pri[0]['type'], $int_types, true)) ? $pri[0]['name'] : '';
        $key_idx = $key !== '' ? array_search($key, array_column($cols, 'name'), true) : false;

        $page = 1000;
        $last = null;
        $offset = 0;
        $batch = '';
        while (true) {
            // Column list and table name come from information_schema and are quoted (quote_name()).
            if ($key !== '') {
                $sql = $last === null
                    ? $wpdb->prepare("SELECT $select FROM %i ORDER BY %i LIMIT %d", $tbl, $key, $page) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- quoted column list
                    : $wpdb->prepare("SELECT $select FROM %i WHERE %i > %d ORDER BY %i LIMIT %d", $tbl, $key, $last, $key, $page); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- quoted column list
            } else {
                $sql = $wpdb->prepare("SELECT $select FROM %i LIMIT %d OFFSET %d", $tbl, $page, $offset); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- quoted column list
            }
            $rows = $wpdb->get_results($sql, ARRAY_N); // phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter -- prepared above with %i/%d placeholders
            if ($wpdb->last_error !== '') throw new RuntimeException("Reading $tbl failed: " . $wpdb->last_error);
            if (empty($rows)) break;

            foreach ($rows as $row) {
                $vals = [];
                foreach ($row as $i => $v) {
                    $kind = $cols[$i]['kind'] ?? 'str';
                    if ($v === null) {
                        $vals[] = 'NULL';
                    } elseif ($kind === 'num' && is_numeric($v)) {
                        $vals[] = $v;
                    } elseif ($kind === 'bin') {
                        $vals[] = $v === '' ? "''" : '0x' . preg_replace('/[^0-9A-Fa-f]/', '', (string) $v);
                    } else {
                        // esc_sql() adds placeholder escapes for "%"; they are removed again for the dump
                        $vals[] = "'" . $wpdb->remove_placeholder_escape(esc_sql((string) $v)) . "'";
                    }
                }
                $batch .= ($batch === '' ? "INSERT INTO $q VALUES\n(" : ",\n(") . implode(',', $vals) . ')';
                if (strlen($batch) >= self::INSERT_BATCH) {
                    $out->write($batch . ";\n");
                    $batch = '';
                }
            }

            if (count($rows) < $page) break;
            if ($key !== '') {
                $last = (int) $rows[count($rows) - 1][$key_idx];
            } else {
                $offset += $page;
            }
        }
        if ($batch !== '') $out->write($batch . ";\n");
    }

    // --- Retention ---

    private function enforce_retention($limit = 7) {
        // Leftovers of interrupted runs
        foreach ((array) glob($this->backup_dir . self::TMP_PREFIX . '*') as $tmp) {
            if (is_file($tmp) && filemtime($tmp) < time() - DAY_IN_SECONDS) wp_delete_file($tmp);
        }

        $files = glob($this->backup_dir . 'db_backup_*');
        if (!$files || count($files) <= $limit) return;

        usort($files, function ($a, $b) {
            return filemtime($b) - filemtime($a);
        });
        foreach (array_slice($files, max(1, (int) $limit)) as $file) {
            wp_delete_file($file);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP-GC', 'Auto-deleted old backup: ' . basename($file));
        }
    }

    // --- Delete / download ---

    private function backup_path_from_request() {
        // sanitize_file_name() would rename multi-extension names (".sql.php.gz.enc" gets "_"
        // inserted), so the name is checked against the pattern of backup files instead
        $file = basename(sanitize_text_field(wp_unslash($_POST['file'] ?? ''))); // phpcs:ignore WordPress.Security.NonceVerification.Missing -- nonce and capability are checked by the callers (delete_backup, download_backup)
        if (!preg_match('/^db_backup_[A-Za-z0-9_-]+(\.[A-Za-z0-9]+)+$/', $file)) return '';
        $path = $this->backup_dir . $file;
        return dirname($path) === rtrim($this->backup_dir, '/') ? $path : '';
    }

    public function delete_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('tegatai_backup_nonce');

        $path = $this->backup_path_from_request();
        if ($path !== '' && is_file($path)) {
            wp_delete_file($path);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('BACKUP', 'Deleted: ' . basename($path));
        }
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=backups&msg=deleted'));
        exit;
    }

    /**
     * Decrypts into a temporary file in the protected backup folder first, so a damaged or
     * cut-off backup is rejected before anything is sent, then streams it to the browser.
     */
    public function download_backup() {
        if (!current_user_can('manage_options')) wp_die('Access Denied');
        check_admin_referer('tegatai_backup_nonce');

        $path = $this->backup_path_from_request();
        if ($path === '' || !is_file($path)) wp_die('File not found or access denied.');

        $dl_name = basename($path);
        $send = $path;
        $tmp = '';
        if (substr($path, -4) === '.enc') {
            $tmp = $this->backup_dir . self::TMP_PREFIX . bin2hex(random_bytes(8)) . '.dl';
            $r = $this->decrypt_file($path, $tmp);
            if ($r !== true) {
                wp_delete_file($tmp);
                wp_die(esc_html(is_wp_error($r) ? $r->get_error_message() : __('Decryption failed: wrong key (backup key file or TEGATAI_BACKUP_SECRET) or the file was modified.', 'tegatai-secure')));
            }
            $send = $tmp;
            $dl_name = substr($dl_name, 0, -4);
        }

        // The size of the temporary file is cached from its creation (0 bytes)
        clearstatcache(true, $send);
        while (ob_get_level() > 0) ob_end_clean();
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $dl_name . '"');
        header('Content-Length: ' . filesize($send));
        readfile($send);
        if ($tmp !== '') wp_delete_file($tmp);
        exit;
    }

    /**
     * Creates a new file that only the PHP user can read (umask 0077, then checked for 0600):
     * the decrypted dump contains the whole database.
     *
     * @return resource|WP_Error
     */
    private function open_private_file($path) {
        $old = umask(0077);
        $fh  = @fopen($path, 'xb');
        umask($old);
        if (!$fh) return new WP_Error('open', 'Temporary file could not be created.');
        @chmod($path, 0600); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_chmod -- decrypted dump must only be readable by the PHP user
        clearstatcache(true, $path);
        if (((int) @fileperms($path) & 0077) !== 0) {
            fclose($fh);
            wp_delete_file($path);
            return new WP_Error('chmod', 'Temporary file could not be protected with 0600.');
        }
        return $fh;
    }

    /**
     * Decrypts a backup into $dst (created with 0600). Any damage, wrong key or library error
     * ends as false or WP_Error, never as an uncaught exception.
     *
     * @return true|false|WP_Error
     */
    private function decrypt_file($src, $dst) {
        $in = @fopen($src, 'rb');
        if (!$in) return new WP_Error('open', 'Backup file could not be opened.');
        $out = null;
        try {
            $r = $this->decrypt_stream($in, $src, $dst, $out);
        } catch (\Throwable $e) {
            $r = false;
        }
        fclose($in);
        if (is_resource($out) && !fclose($out)) $r = false;
        return $r;
    }

    private function decrypt_stream($in, $src, $dst, &$out) {
        $magic = (string) fread($in, 4);

        if ($magic === self::ENC_MAGIC_V3 || $magic === self::ENC_MAGIC_V4) {
            if (!self::sodium_available()) return new WP_Error('sodium', 'The PHP sodium extension is missing.');
            if ($magic === self::ENC_MAGIC_V3) {
                $keys = self::own_keys();
                if ($keys['secret'] === '') return new WP_Error('nokey', __('This backup needs the private backup key, which is not on this server.', 'tegatai-secure'));
                $seal_len = SODIUM_CRYPTO_BOX_SEALBYTES + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_KEYBYTES;
                $sealed = (string) fread($in, $seal_len);
                if (strlen($sealed) !== $seal_len) return false;
                $kp = sodium_crypto_box_keypair_from_secretkey_and_publickey($keys['secret'], $keys['public']);
                $file_key = sodium_crypto_box_seal_open($sealed, $kp);
                sodium_memzero($kp);
                if ($file_key === false) return false;
                $ad = $magic . $sealed;
            } else {
                $file_key = $this->derive_key('stream');
                $ad = $magic;
            }
            $out = $this->open_private_file($dst);
            if (is_wp_error($out)) { $e = $out; $out = null; return $e; }
            $ok = Tegatai_Backup_Stream::decrypt($in, $out, $file_key, $ad);
            sodium_memzero($file_key);
            return $ok;
        }

        // Backups of older versions (TGB2, v1) need the OpenSSL extension.
        if (!function_exists('openssl_decrypt')) return new WP_Error('openssl', 'The PHP openssl extension is missing (needed for backups made before Tegatai 2.1).');

        if ($magic === self::ENC_MAGIC) {
            // TGB2 (Tegatai 1.5 to 2.1.0): "TGB2" | 12-byte nonce | 16-byte tag | AES-256-GCM.
            // The key has always been the HMAC derivation derive_key('enc') of the backup secret.
            // PHP has no streaming GCM, so the ciphertext and the plaintext are held in memory
            // once each; checked against the memory limit first.
            $nonce = (string) fread($in, 12);
            $tag   = (string) fread($in, 16);
            if (strlen($nonce) !== 12 || strlen($tag) !== 16) return false;
            $mem = $this->check_memory((int) filesize($src) * 2);
            if (is_wp_error($mem)) return $mem;
            $cipher = stream_get_contents($in);
            if ($cipher === false) return false;
            $plain = openssl_decrypt($cipher, 'aes-256-gcm', $this->derive_key('enc'), OPENSSL_RAW_DATA, $nonce, $tag, self::ENC_MAGIC);
            unset($cipher);
            if ($plain === false) return false;
            $out = $this->open_private_file($dst);
            if (is_wp_error($out)) { $e = $out; $out = null; return $e; }
            return fwrite($out, $plain) === strlen($plain);
        }

        // v1 (before 1.5): IV | AES-256-CBC with the hex secret passed directly as key (OpenSSL
        // uses its first 32 bytes). Decrypted in 1 MB blocks; unauthenticated, so the padding
        // check at the end is the only integrity check.
        $iv_len = openssl_cipher_iv_length('aes-256-cbc');
        fseek($in, 0);
        $iv = (string) fread($in, $iv_len);
        if (strlen($iv) !== $iv_len) return false;
        $key = $this->get_encryption_key();
        $out = $this->open_private_file($dst);
        if (is_wp_error($out)) { $e = $out; $out = null; return $e; }
        $carry = '';
        while (!feof($in)) {
            $block = fread($in, 1048576);
            if ($block === false) return false;
            $carry .= $block;
            // Always keep the last full block back: the final one holds the padding
            $take = strlen($carry) - (strlen($carry) % 16) - 16;
            if ($take <= 0) continue;
            $chunk = substr($carry, 0, $take);
            $carry = substr($carry, $take);
            $plain = openssl_decrypt($chunk, 'aes-256-cbc', $key, OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING, $iv);
            if ($plain === false) return false;
            $iv = substr($chunk, -16);
            if (fwrite($out, $plain) !== strlen($plain)) return false;
        }
        if ($carry === '' || strlen($carry) % 16 !== 0) return false;
        $plain = openssl_decrypt($carry, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) return false;
        return fwrite($out, $plain) === strlen($plain);
    }

    /** Raises the memory limit like other admin tasks and checks that $bytes still fit. */
    private function check_memory($bytes) {
        wp_raise_memory_limit('admin');
        $limit = wp_convert_hr_to_bytes((string) ini_get('memory_limit'));
        if ($limit > 0 && memory_get_usage(true) + $bytes > $limit) {
            return new WP_Error('memory', sprintf(
                'This old backup (AES-256-GCM, before 2.1.1) needs about %s of memory to decrypt, PHP allows %s. Raise memory_limit for the download (backups from 2.1.1 on are decrypted in chunks).',
                size_format($bytes + memory_get_usage(true)), size_format($limit)
            ));
        }
        return true;
    }

    public static function get_backups() {
        $dir = trailingslashit(tegatai_data_dir('backups'));
        $files = [];

        foreach ((array) glob($dir . 'db_backup_*') as $path) {
            if (!is_file($path)) continue;
            $files[] = [
                'name'  => basename($path),
                'size'  => round(filesize($path) / 1024, 2) . ' KB',
                'date'  => gmdate('Y-m-d H:i', filemtime($path)),
                'mtime' => filemtime($path),
            ];
        }
        usort($files, function ($a, $b) {
            return $b['mtime'] - $a['mtime'];
        });
        return $files;
    }
}

/**
 * gzip + XChaCha20-Poly1305 secretstream writer. Layout after the magic (and sealed key):
 * 24-byte stream header, then chunks of [4-byte length | ciphertext]; the last chunk is tagged
 * FINAL, so a cut-off file is detected. Magic (and sealed key) are authenticated with every chunk.
 */
class Tegatai_Backup_Stream {
    private $fh;
    private $state;
    private $ad;
    private $z = null;
    private $buf = '';

    /** TGB3: random file key sealed to the backup public key. */
    public static function sealed($fh, $public_key) {
        $file_key = sodium_crypto_secretstream_xchacha20poly1305_keygen();
        $sealed   = sodium_crypto_box_seal($file_key, $public_key);
        $s = new self($fh, Tegatai_Backup::ENC_MAGIC_V3 . $sealed, $file_key);
        sodium_memzero($file_key);
        return $s;
    }

    /** TGB4: key derived from TEGATAI_BACKUP_SECRET. */
    public static function symmetric($fh, $key) {
        return new self($fh, Tegatai_Backup::ENC_MAGIC_V4, $key);
    }

    private function __construct($fh, $prefix, $key) {
        $this->fh = $fh;
        $this->ad = $prefix;
        [$this->state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push($key);
        $this->put($prefix . $header);
        if (function_exists('deflate_init')) {
            $this->z = deflate_init(ZLIB_ENCODING_GZIP, ['level' => 6]);
            if ($this->z === false) throw new RuntimeException('gzip could not be started.');
        }
    }

    private function put($bytes) {
        $len = strlen($bytes);
        $done = 0;
        while ($done < $len) {
            $n = @fwrite($this->fh, $done === 0 ? $bytes : substr($bytes, $done));
            if ($n === false || $n === 0) throw new RuntimeException('Writing the backup file failed (disk full?).');
            $done += $n;
        }
    }

    private function push($chunk, $final) {
        $tag = $final ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
        $c = sodium_crypto_secretstream_xchacha20poly1305_push($this->state, $chunk, $this->ad, $tag);
        $this->put(pack('N', strlen($c)) . $c);
    }

    public function write($data) {
        if ($data === '') return;
        if ($this->z) {
            $data = deflate_add($this->z, $data, ZLIB_NO_FLUSH);
            if ($data === false) throw new RuntimeException('gzip compression failed.');
        }
        $this->buf .= $data;
        while (strlen($this->buf) > Tegatai_Backup::CHUNK) {
            $this->push(substr($this->buf, 0, Tegatai_Backup::CHUNK), false);
            $this->buf = substr($this->buf, Tegatai_Backup::CHUNK);
        }
    }

    public function finish() {
        if ($this->z) {
            $tail = deflate_add($this->z, '', ZLIB_FINISH);
            if ($tail === false) throw new RuntimeException('gzip compression failed.');
            $this->buf .= $tail;
        }
        while (strlen($this->buf) > Tegatai_Backup::CHUNK) {
            $this->push(substr($this->buf, 0, Tegatai_Backup::CHUNK), false);
            $this->buf = substr($this->buf, Tegatai_Backup::CHUNK);
        }
        $this->push($this->buf, true);
        $this->buf = '';
    }

    /**
     * Reads the stream header and all chunks from $in (positioned after magic and sealed key)
     * and writes the plaintext (the .gz data) to $out. False on any damage, a missing FINAL
     * chunk or data after it.
     */
    public static function decrypt($in, $out, $key, $ad) {
        try {
            return self::decrypt_chunks($in, $out, $key, $ad);
        } catch (\Throwable $e) {
            // SodiumException or any other error: a damaged backup is a failed decryption
            return false;
        }
    }

    private static function decrypt_chunks($in, $out, $key, $ad) {
        $header = (string) fread($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
        if (strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) return false;
        $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, $key);
        $final = false;
        while (true) {
            $len = (string) fread($in, 4);
            if ($len === '') break;
            if ($final || strlen($len) !== 4) return false;
            $n = unpack('N', $len)[1];
            if ($n < SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES || $n > Tegatai_Backup::CHUNK + 1024) return false;
            $c = '';
            while (strlen($c) < $n && !feof($in)) {
                $part = fread($in, $n - strlen($c));
                if ($part === false || $part === '') break;
                $c .= $part;
            }
            if (strlen($c) !== $n) return false;
            $r = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $c, $ad);
            if ($r === false) return false;
            [$plain, $tag] = $r;
            if ($plain !== '' && fwrite($out, $plain) !== strlen($plain)) return false;
            if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) $final = true;
        }
        return $final;
    }
}

/**
 * WP-CLI command for the backup key. Run it as the site's PHP-FPM user (never as root).
 */
if (defined('WP_CLI') && WP_CLI) {
    /**
     * Creates a new X25519 key pair for encrypted database backups and prints the key file to STDOUT.
     *
     * Redirect the output into the key file; Tegatai does not write it itself. Keep a copy of
     * the file in a safe place: without it the backups cannot be decrypted. Example:
     *   (umask 077; wp tegatai backup-keygen > /path/secrets/tegatai-backup-key.php.new) && mv -n /path/secrets/tegatai-backup-key.php.new /path/secrets/tegatai-backup-key.php
     */
    WP_CLI::add_command('tegatai backup-keygen', function () {
        $r = Tegatai_Backup::new_key_file_content();
        if (is_wp_error($r)) WP_CLI::error($r);
        WP_CLI::line(rtrim($r, "\n"));
        // Hint goes to STDERR, so it does not end up in the redirected key file
        WP_CLI::warning('Backup key created. Keep a copy of the key file outside the server.');
    });
}
