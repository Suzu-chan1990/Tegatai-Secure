<?php
if (!defined('ABSPATH')) { exit; }

/* TEGATAI_CORE_INTEGRITY_MD5_V1 applied */
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

    /**
     * Lädt die Originaldatei von WP.org herunter, prüft den MD5-Hash und überschreibt die lokale Datei.
     */
    public static function heal_file($file_path) {
        global $wp_version;
        
        // Sicherheit: Pfad säubern und sicherstellen, dass wir nicht aus WP ausbrechen
        $clean_path = ltrim(str_replace('\\', '/', $file_path), '/');
        
        // Nur absolute WP-Core Pfade zulassen
        if (strpos($clean_path, 'wp-admin/') !== 0 && strpos($clean_path, 'wp-includes/') !== 0 && strpos($clean_path, '.php') === false) {
            return ['ok' => false, 'error' => __('Security warning: Invalid core path.', 'tegatai-secure')];
        }
        
        $abs_file = ABSPATH . $clean_path;
        
        // Die originale Datei vom offiziellen WP.org SVN Server anfordern
        $url = "https://core.svn.wordpress.org/tags/{$wp_version}/{$clean_path}";
        $response = wp_remote_get($url, ['timeout' => 15]);
        
        if (is_wp_error($response) || wp_remote_retrieve_response_code($response) !== 200) {
            return ['ok' => false, 'error' => sprintf(__('Could not load original file from WordPress.org (HTTP %d).', 'tegatai-secure'), wp_remote_retrieve_response_code($response))];
        }
        
        $body = wp_remote_retrieve_body($response);
        if (empty($body)) {
            return ['ok' => false, 'error' => __('Downloaded file is empty. Aborting.', 'tegatai-secure')];
        }

        // --- NEW: Strict MD5 Checksum Verification ---
        if (!function_exists('wp_get_core_checksums')) {
            require_once ABSPATH . 'wp-admin/includes/update.php';
        }
        $locale = function_exists('get_locale') ? get_locale() : 'en_US';
        $checksums = function_exists('wp_get_core_checksums') ? wp_get_core_checksums($wp_version, $locale) : null;
        if (!is_array($checksums) || empty($checksums)) {
            $checksums = function_exists('wp_get_core_checksums') ? wp_get_core_checksums($wp_version, 'en_US') : null;
        }

        if (is_array($checksums) && isset($checksums[$clean_path])) {
            $expected_hash = $checksums[$clean_path];
            $downloaded_hash = md5($body);
            
            if (strtolower($expected_hash) !== strtolower($downloaded_hash)) {
                if (class_exists('Tegatai_Logger')) {
                    Tegatai_Logger::log('SEC-WARN', "Heal aborted: MD5 mismatch for $clean_path. Expected: $expected_hash, Got: $downloaded_hash");
                }
                return ['ok' => false, 'error' => __('MD5 checksum mismatch! Downloaded file is corrupted or tampered.', 'tegatai-secure')];
            }
        }
        // ---------------------------------------------
        
        // Zielordner sicherstellen, falls es eine gelöschte Datei war
        $dir = dirname($abs_file);
        if (!is_dir($dir)) {
            @wp_mkdir_p($dir);
        }
        
        // Überschreiben
        $put = @file_put_contents($abs_file, $body);
        if ($put === false) {
            return ['ok' => false, 'error' => __('Missing write permissions. The file could not be overwritten.', 'tegatai-secure')];
        }
        
        if (class_exists('Tegatai_Logger')) {
            Tegatai_Logger::log('HEAL', sprintf(__('Core file successfully repaired and verified: %s', 'tegatai-secure'), $clean_path));
        }
        
        return ['ok' => true];
    }

}
