<?php
if (!defined('ABSPATH')) { exit; }

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
}
