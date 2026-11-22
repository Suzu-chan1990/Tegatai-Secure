<?php
if (!defined('ABSPATH')) { exit; }
// phpcs:disable WordPress.DB.DirectDatabaseQuery -- own quarantine table / one-time cleanup of old meta keys; live data, not cached

/**
 * Quarantine for files flagged as malware.
 *
 * The content of a quarantined file is stored in the database table {prefix}tegatai_quarantine
 * (base64, never as a file) and the original file is deleted. Tegatai never writes code files:
 * a quarantined file is not restored to disk by the plugin. The administrator can download the
 * original content to inspect it and upload it again by hand if it was a false positive.
 */
class Tegatai_Quarantine {

    const DB_VERSION = '1';
    // Larger files are not quarantined (the content has to fit into one database row).
    const MAX_BYTES = 8388608;

    public static function table(): string {
        global $wpdb;
        return $wpdb->prefix . 'tegatai_quarantine';
    }

    public static function init(): void {
        add_action('admin_post_tegatai_quarantine_download', [__CLASS__, 'handle_download']);
        add_action('admin_post_tegatai_quarantine_delete', [__CLASS__, 'handle_delete']);
        if (is_admin() || wp_doing_cron()) add_action('init', [__CLASS__, 'maybe_install'], 30);
    }

    public static function maybe_install(): void {
        if (get_option('tegatai_quarantine_db_version') === self::DB_VERSION && self::table_exists()) return;
        global $wpdb;
        $table = self::table();
        $charset_collate = $wpdb->get_charset_collate();
        $sql = "CREATE TABLE $table (
            id char(32) NOT NULL,
            time bigint(20) unsigned NOT NULL DEFAULT 0,
            original text NOT NULL,
            sha256 char(64) NOT NULL DEFAULT '',
            size bigint(20) unsigned NOT NULL DEFAULT 0,
            content longtext NOT NULL,
            PRIMARY KEY  (id),
            KEY time (time)
        ) $charset_collate;";
        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta($sql);
        if (!self::table_exists()) return; // retried on the next admin request
        update_option('tegatai_quarantine_db_version', self::DB_VERSION, false);
        self::migrate_files();
    }

    private static function table_exists(): bool {
        global $wpdb;
        $t = self::table();
        return $wpdb->get_var($wpdb->prepare('SHOW TABLES LIKE %s', $wpdb->esc_like($t))) === $t;
    }

    /**
     * Moves quarantine entries of older versions (files in uploads/tegatai-quarantine or
     * <content dir>/tegatai-quarantine) into the database and deletes the files.
     */
    private static function migrate_files(): void {
        $dirs = [trailingslashit(wp_upload_dir(null, false)['basedir']) . 'tegatai-quarantine'];
        if (defined('WP_CONTENT_DIR')) $dirs[] = WP_CONTENT_DIR . '/tegatai-quarantine';
        $custom = get_option('tegatai_quarantine_dir_v1', '');
        if (is_string($custom) && $custom !== '') $dirs[] = $custom;

        foreach (array_unique($dirs) as $dir) {
            if (!is_dir($dir)) continue;
            // Format of 2.0 - 2.2.1: <id>.json (meta) + <id>.bin (base64 content)
            foreach ((array) glob($dir . '/*.json') as $meta_file) {
                if (!is_string($meta_file) || !preg_match('/^[a-f0-9]{8,64}\.json$/', basename($meta_file))) continue;
                $id = basename($meta_file, '.json');
                $blob_file = $dir . '/' . $id . '.bin';
                $meta = json_decode((string) @file_get_contents($meta_file), true);
                $content = is_file($blob_file) ? base64_decode((string) @file_get_contents($blob_file), true) : false;
                if (is_array($meta) && is_string($content)) {
                    self::store((string) ($meta['original'] ?? ''), $content, (int) ($meta['time'] ?? time()));
                }
                wp_delete_file($meta_file);
                wp_delete_file($blob_file);
            }
            // Very old format: "<time>_<name>.quarantine" (raw content, original path unknown)
            foreach ((array) glob($dir . '/*.quarantine') as $old) {
                if (!is_string($old)) continue;
                $content = @file_get_contents($old);
                if (is_string($content)) self::store(basename($old, '.quarantine'), $content, (int) @filemtime($old));
                wp_delete_file($old);
            }
            // Remove the emptied folder (protection files included)
            foreach (['.htaccess', 'index.php', 'index.html', 'web.config'] as $f) {
                if (is_file($dir . '/' . $f)) wp_delete_file($dir . '/' . $f);
            }
            @rmdir($dir); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir -- only succeeds when empty
        }
        delete_option('tegatai_quarantine_dir_v1');
        delete_option('tegatai_quarantine_migrated_v2');
    }

    // Inserts one entry; returns the id or ''.
    private static function store(string $original, string $content, int $time = 0): string {
        global $wpdb;
        $id = bin2hex(random_bytes(16));
        $ok = $wpdb->insert(self::table(), [
            'id'       => $id,
            'time'     => $time > 0 ? $time : time(),
            'original' => $original,
            'sha256'   => hash('sha256', $content),
            'size'     => strlen($content),
            'content'  => base64_encode($content),
        ], ['%s', '%d', '%s', '%s', '%d', '%s']);
        return $ok ? $id : '';
    }

    public static function quarantine_file(string $abs_path): array {
        $abs = realpath($abs_path);
        if (!$abs || !is_file($abs) || !is_readable($abs)) {
            return ['ok'=>false, 'error'=>'not_readable'];
        }
        self::maybe_install();
        if (!self::table_exists()) return ['ok'=>false, 'error'=>'no_table'];

        $size = (int) @filesize($abs);
        if ($size > self::MAX_BYTES) return ['ok'=>false, 'error'=>'too_large'];

        $data = @file_get_contents($abs);
        if (!is_string($data)) {
            return ['ok'=>false, 'error'=>'read_failed'];
        }

        $id = self::store($abs, $data);
        if ($id === '') return ['ok'=>false, 'error'=>'db_failed'];

        // Verify the stored copy before deleting the original
        $row = self::get($id);
        if (!$row || !hash_equals(hash('sha256', $data), (string) $row['sha256']) || base64_decode((string) $row['content'], true) !== $data) {
            self::delete($id);
            return ['ok'=>false, 'error'=>'verify_failed'];
        }

        // unlink() on purpose: the result decides whether the quarantine is rolled back
        if (!@unlink($abs)) { // phpcs:ignore WordPress.WP.AlternativeFunctions.unlink_unlink
            self::delete($id);
            return ['ok'=>false, 'error'=>'remove_failed'];
        }
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('QUARANTINE', 'File quarantined: ' . $abs);

        return ['ok' => true, 'id' => $id];
    }

    public static function get(string $id): ?array {
        global $wpdb;
        $id = preg_replace('/[^a-f0-9]/', '', $id);
        if ($id === '') return null;
        $row = $wpdb->get_row($wpdb->prepare('SELECT * FROM %i WHERE id = %s', self::table(), $id), ARRAY_A);
        return is_array($row) ? $row : null;
    }

    // Entries without content, newest first.
    public static function list(int $limit = 100): array {
        global $wpdb;
        if (!self::table_exists()) return [];
        $rows = $wpdb->get_results($wpdb->prepare('SELECT id, time, original, sha256, size FROM %i ORDER BY time DESC LIMIT %d', self::table(), max(1, $limit)), ARRAY_A);
        return is_array($rows) ? $rows : [];
    }

    public static function delete(string $id): bool {
        global $wpdb;
        $id = preg_replace('/[^a-f0-9]/', '', $id);
        if ($id === '') return false;
        return (bool) $wpdb->delete(self::table(), ['id' => $id], ['%s']);
    }

    // Sends the original content as a download (admin only, nonce-protected).
    public static function handle_download(): void {
        if (!current_user_can('manage_options')) wp_die(esc_html__('Access Denied', 'tegatai-secure'));
        $id = isset($_GET['id']) ? sanitize_key(wp_unslash($_GET['id'])) : '';
        check_admin_referer('tegatai_quarantine_' . $id);
        $row = self::get($id);
        if (!$row) wp_die(esc_html__('Quarantine entry not found.', 'tegatai-secure'));
        $content = base64_decode((string) $row['content'], true);
        if (!is_string($content)) wp_die(esc_html__('Quarantine entry is damaged.', 'tegatai-secure'));
        // ".txt" so the browser never treats the content as something to run or render
        $name = sanitize_file_name(basename((string) $row['original'])) . '.quarantined.txt';
        nocache_headers();
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . $name . '"');
        header('Content-Length: ' . strlen($content));
        header('X-Content-Type-Options: nosniff');
        echo $content; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- raw file download
        exit;
    }

    public static function handle_delete(): void {
        if (!current_user_can('manage_options')) wp_die(esc_html__('Access Denied', 'tegatai-secure'));
        $id = isset($_POST['id']) ? sanitize_key(wp_unslash($_POST['id'])) : '';
        check_admin_referer('tegatai_quarantine_' . $id);
        self::delete($id);
        wp_safe_redirect(admin_url('admin.php?page=tegatai-Secure&tab=malware#tegatai-quarantine'));
        exit;
    }

    // Table of quarantined files (Malware tab).
    public static function render_list(): void {
        $rows = self::list();
        echo '<div class="teg-card" id="tegatai-quarantine" style="grid-column: 1 / -1;"><h3>' . esc_html__('Quarantine', 'tegatai-secure') . '</h3>';
        echo '<p class="teg-switch-desc" style="display:block; margin-bottom:10px;">' . esc_html__('Quarantined files are deleted from the disk; their content is kept in the database. Tegatai does not write them back. If a file was flagged by mistake, download it and upload it again by hand (e.g. via SFTP).', 'tegatai-secure') . '</p>';
        if (!$rows) {
            echo '<p class="teg-switch-desc">' . esc_html__('The quarantine is empty.', 'tegatai-secure') . '</p></div>';
            return;
        }
        echo '<table class="teg-table"><thead><tr><th>' . esc_html__('Date', 'tegatai-secure') . '</th><th>' . esc_html__('Original path', 'tegatai-secure') . '</th><th>' . esc_html__('Size', 'tegatai-secure') . '</th><th></th></tr></thead><tbody>';
        foreach ($rows as $r) {
            $id = (string) $r['id'];
            $dl = wp_nonce_url(add_query_arg(['action' => 'tegatai_quarantine_download', 'id' => $id], admin_url('admin-post.php')), 'tegatai_quarantine_' . $id);
            echo '<tr><td>' . esc_html(wp_date('Y-m-d H:i', (int) $r['time'])) . '</td><td><code>' . esc_html((string) $r['original']) . '</code></td><td>' . esc_html(size_format((int) $r['size'])) . '</td><td style="white-space:nowrap;">';
            echo '<a class="button button-secondary" href="' . esc_url($dl) . '">' . esc_html__('Download', 'tegatai-secure') . '</a> ';
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline;">';
            echo '<input type="hidden" name="action" value="tegatai_quarantine_delete"><input type="hidden" name="id" value="' . esc_attr($id) . '">';
            wp_nonce_field('tegatai_quarantine_' . $id);
            echo '<button type="submit" class="button button-secondary">' . esc_html__('Delete', 'tegatai-secure') . '</button></form>';
            echo '</td></tr>';
        }
        echo '</tbody></table></div>';
    }
}
Tegatai_Quarantine::init();
