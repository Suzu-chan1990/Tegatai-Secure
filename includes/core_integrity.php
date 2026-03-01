<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Core_Integrity {
    public static function check(): array {
        global $wp_version;

        if (!function_exists('wp_get_core_checksums')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }

        $locale = function_exists('get_locale') ? get_locale() : 'en_US';
        $checksums = function_exists('wp_get_core_checksums') ? wp_get_core_checksums($wp_version, $locale) : null;
        if (!is_array($checksums) || empty($checksums)) {
            $checksums = function_exists('wp_get_core_checksums') ? wp_get_core_checksums($wp_version, 'en_US') : null;
        }
        if (!is_array($checksums) || empty($checksums)) {
            return ['ok'=>false, 'error'=>'checksums_unavailable', 'version'=>$wp_version];
        }

        $bad = [];
        $missing = [];
        $seen = [];

        foreach ($checksums as $rel => $hash) {
            $seen[$rel] = true;
            $abs = ABSPATH . $rel;
            if (!file_exists($abs)) { $missing[] = $rel; continue; }
            if (!is_readable($abs)) continue;

            $data = @file_get_contents($abs);
            if (!is_string($data)) continue;
            $h = md5($data);
            if (strtolower($h) !== strtolower((string)$hash)) { $bad[] = $rel; }
        }

        $extra = [];
        foreach (['wp-admin', 'wp-includes'] as $dir) {
            $root = ABSPATH . $dir;
            if (!is_dir($root)) continue;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $abs = $f->getPathname();
                $rel = ltrim(str_replace('\\', '/', str_replace(ABSPATH, '', $abs)), '/');
                if (!isset($seen[$rel])) {
                    $extra[] = $rel;
                    if (count($extra) >= 300) break;
                }
            }
        }

        if (class_exists('Tegatai_Timeline')) {
            if (!empty($bad) || !empty($missing) || !empty($extra)) {
                Tegatai_Timeline::add('core', 'Core integrity issues: modified=' . count($bad) . ', missing=' . count($missing) . ', extra=' . count($extra));
            }
        }

        return ['ok'=>true, 'version'=>$wp_version, 'bad'=>$bad, 'missing'=>$missing, 'extra'=>$extra];
    }
}
