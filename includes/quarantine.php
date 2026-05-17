<?php
if (!defined('ABSPATH')) { exit; }


add_action('wp_ajax_tegatai_quarantine_restore', function() {
    if (!current_user_can('manage_options')) wp_die('Access denied');
    $id = sanitize_text_field($_POST['id'] ?? '');
    if (class_exists('Tegatai_Quarantine')) {
        $res = Tegatai_Quarantine::restore_file($id);
        if ($res['ok']) wp_send_json_success(['msg' => 'Datei erfolgreich wiederhergestellt: ' . $res['file']]);
        wp_send_json_error(['msg' => 'Fehler: ' . $res['error']]);
    }
});

class Tegatai_Quarantine {

    const OPT_DIR = 'teg_quarantine_dir_v1';

    public static function dir(): string {
        $base = WP_CONTENT_DIR . '/tegatai-quarantine';
        $custom = get_option(self::OPT_DIR, '');
        if (is_string($custom) && $custom !== '') {
            $rp = realpath($custom);
            if ($rp && is_dir($rp)) {
                $base = $rp;
            }
        }
        if (!is_dir($base)) {
            @wp_mkdir_p($base);
        }

        // Hardening files (Apache + generic)
        @file_put_contents($base . '/index.php', "<?php\\nexit;\\n");
        @file_put_contents($base . '/.htaccess', "Require all denied\\n");

        return $base;
    }

    public static function quarantine_file(string $abs_path): array {
        $abs = realpath($abs_path);
        if (!$abs || !is_file($abs) || !is_readable($abs)) {
            return ['ok'=>false, 'error'=>'not_readable'];
        }

        $dir = self::dir();
        $id = bin2hex(random_bytes(16));
        $meta_path = $dir . '/' . $id . '.json';
        $blob_path = $dir . '/' . $id . '.bin';

        $data = @file_get_contents($abs);
        if (!is_string($data)) {
            return ['ok'=>false, 'error'=>'read_failed'];
        }

        $meta = [
            'id' => $id,
            'time' => time(),
            'original' => $abs,
            'sha256' => hash('sha256', $data),
            'size' => strlen($data),
        ];

        // Store as base64 to avoid binary/encoding issues
        $ok1 = @file_put_contents($blob_path, base64_encode($data));
        $ok2 = @file_put_contents($meta_path, wp_json_encode($meta, JSON_UNESCAPED_SLASHES|JSON_PRETTY_PRINT));

        if ($ok1 === false || $ok2 === false) {
            return ['ok'=>false, 'error'=>'write_failed'];
        }

        // Rename original to non-executable extension (nginx-safe)
        $new_name = $abs . '.tegatai.quarantined';
        $renamed = @rename($abs, $new_name);

        return [
            'ok' => true,
            'id' => $id,
            'stored' => basename($blob_path),
            'meta' => basename($meta_path),
            'renamed' => $renamed ? $new_name : '',
        ];
    }

    public static function restore_file(string $id): array {
        $id = preg_replace('/[^a-f0-9]/', '', $id);
        if (empty($id)) return ['ok'=>false, 'error'=>'invalid_id'];
        
        $dir = self::dir();
        $meta = $dir . '/' . $id . '.json';
        $blob = $dir . '/' . $id . '.bin';
        
        if (!file_exists($meta) || !file_exists($blob)) return ['ok'=>false, 'error'=>'not_found'];
        
        $data = json_decode(file_get_contents($meta), true);
        if (empty($data['original'])) return ['ok'=>false, 'error'=>'meta_invalid'];
        
        $orig = $data['original'];
        $content = base64_decode(file_get_contents($blob));
        
        // Versuche, das Originalverzeichnis wiederherzustellen, falls es gelöscht wurde
        $orig_dir = dirname($orig);
        if (!is_dir($orig_dir)) { @wp_mkdir_p($orig_dir); }
        
        if (@file_put_contents($orig, $content) !== false) {
            @unlink($meta);
            @unlink($blob);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('QUARANTINE', "Datei wiederhergestellt: " . $orig);
            return ['ok'=>true, 'file'=>$orig];
        }
        return ['ok'=>false, 'error'=>'write_failed'];
    }

}
