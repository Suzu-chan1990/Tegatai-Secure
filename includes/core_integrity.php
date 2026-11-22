<?php
if (!defined('ABSPATH')) { exit; }

/**
 * Read-only check of the WordPress core files against the official checksums of wordpress.org.
 * Tegatai does not repair core files itself; damaged files are restored with WordPress' own
 * "Re-install version" (Dashboard > Updates).
 */
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
        // Core directories: wp-includes via WPINC, wp-admin has no constant (core uses ABSPATH . 'wp-admin' as well).
        $core_dirs = [ABSPATH . WPINC, ABSPATH . 'wp-admin'];
        foreach ($core_dirs as $root) {
            if (!is_dir($root)) continue;
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
            foreach ($it as $f) {
                if (!$f->isFile()) continue;
                $abs = $f->getPathname();
                // Path relative to the WordPress directory, the same form as the checksum list uses
                $rel = ltrim(str_replace('\\', '/', substr($abs, strlen(ABSPATH))), '/');
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
