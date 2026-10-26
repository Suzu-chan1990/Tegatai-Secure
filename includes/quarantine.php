<?php
if (!defined('ABSPATH')) { exit; }

// Restore is handled by Tegatai_Admin::ajax_restore_quarantine() (wp_ajax_teg_restore_quarantine, nonce-protected).
// The former unprotected 'wp_ajax_tegatai_quarantine_restore' handler here allowed CSRF and was removed.

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

        // Hardening files (Apache + IIS); nginx is covered by the generated tegatai-nginx.conf
        if (function_exists('tegatai_protect_directory')) {
            tegatai_protect_directory($base);
        } else {
            if (!is_dir($base)) {
                @wp_mkdir_p($base);
            }
            if (!file_exists($base . '/index.php')) @file_put_contents($base . '/index.php', "<?php\n// Silence is golden.\n");
            if (!file_exists($base . '/.htaccess')) @file_put_contents($base . '/.htaccess', "Require all denied\n");
        }

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

        // Verify the stored copy before touching the original
        $stored = $ok1 !== false ? base64_decode((string)@file_get_contents($blob_path), true) : false;
        if ($ok1 === false || $ok2 === false || !is_string($stored) || !hash_equals($meta['sha256'], hash('sha256', $stored))) {
            @unlink($blob_path);
            @unlink($meta_path);
            return ['ok'=>false, 'error'=>'write_failed'];
        }

        // Remove the original. A renamed copy ("x.php.tegatai.quarantined") stayed readable over HTTP and
        // could still be executed by Apache AddHandler multi-extension setups. The verified blob is the backup.
        if (!@unlink($abs)) {
            // The malware is still in place: report failure and drop the orphaned copy
            @unlink($blob_path);
            @unlink($meta_path);
            return ['ok'=>false, 'error'=>'remove_failed'];
        }

        return [
            'ok' => true,
            'id' => $id,
            'stored' => basename($blob_path),
            'meta' => basename($meta_path),
            'renamed' => '',
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
        $content = base64_decode((string)file_get_contents($blob), true);
        if (!is_string($content)) return ['ok'=>false, 'error'=>'blob_invalid'];
        if (!empty($data['sha256']) && !hash_equals((string)$data['sha256'], hash('sha256', $content))) {
            return ['ok'=>false, 'error'=>'checksum_mismatch'];
        }
        
        // Versuche, das Originalverzeichnis wiederherzustellen, falls es gelöscht wurde
        $orig_dir = dirname($orig);
        if (!is_dir($orig_dir)) { @wp_mkdir_p($orig_dir); }
        
        if (@file_put_contents($orig, $content) !== false) {
            // Leftover renamed copy from older versions
            if (file_exists($orig . '.tegatai.quarantined')) @unlink($orig . '.tegatai.quarantined');
            @unlink($meta);
            @unlink($blob);
            if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('QUARANTINE', "Datei wiederhergestellt: " . $orig);
            return ['ok'=>true, 'file'=>$orig];
        }
        return ['ok'=>false, 'error'=>'write_failed'];
    }

}
