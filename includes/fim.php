<?php
if (!defined('ABSPATH')) { exit; }

/* TEGATAI_FIM_ABS_PATHS_V1 applied */
class Tegatai_FIM {

    const OPT_SNAPSHOT = 'teg_fim_snapshot_v1';
    const OPT_LASTRUN  = 'teg_fim_last_run_v1';

    private static function fim_paths(): array {
        // Auto-detect WP directories (works with renamed wp-content)
        $paths = [];

        if (defined('WP_PLUGIN_DIR')) {
            $paths['plugins'] = WP_PLUGIN_DIR;
        }
        if (defined('WPMU_PLUGIN_DIR')) {
            $paths['mu_plugins'] = WPMU_PLUGIN_DIR;
        }
        // Themes: get_theme_root() is safest
        $tr = function_exists('get_theme_root') ? get_theme_root() : '';
        if (!empty($tr) && is_dir($tr)) {
            $paths['themes'] = $tr;
        } elseif (defined('WP_CONTENT_DIR') && is_dir(WP_CONTENT_DIR . '/themes')) {
            $paths['themes'] = WP_CONTENT_DIR . '/themes';
        }

        // Normalize + ensure existing
        foreach ($paths as $k => $p) {
            $rp = realpath($p);
            if ($rp && is_dir($rp)) {
                $paths[$k] = $rp;
            } else {
                unset($paths[$k]);
            }
        }
        return $paths;
    }

    private static function iter_files(string $root): \Generator {
        $it = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::LEAVES_ONLY
        );
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            yield $f->getPathname();
        }
    }

    private static function relpath(string $path, string $root): string {
        $root = rtrim(str_replace('\\', '/', $root), '/') . '/';
        $p = str_replace('\\', '/', $path);
        if (strpos($p, $root) === 0) return substr($p, strlen($root));
        return basename($p);
    }

    private static function hash_file_safely(string $path): string {
        if (!is_readable($path)) return '';
        $h = @hash_file('sha256', $path);
        return is_string($h) ? $h : '';
    }

    public static function build_snapshot(): array {
        $paths = self::fim_paths();
        $snap = [
            'version' => 1,
            'created' => time(),
            'roots'   => $paths,
            'files'   => [],
        ];

        foreach ($paths as $root_key => $root) {
            foreach (self::iter_files($root) as $abs) {
                $rel = self::relpath($abs, $root);
                $st = @stat($abs);
                if (!$st) continue;
                $size = (int)($st['size'] ?? 0);
                $mtime = (int)($st['mtime'] ?? 0);
                $sha = self::hash_file_safely($abs);

                $key = $root_key . ':' . $rel;
                $snap['files'][$key] = [
                    'root'  => $root_key,
                    'rel'   => $rel,
                    'size'  => $size,
                    'mtime' => $mtime,
                    'sha'   => $sha,
                ];
            }
        }

        self::save_snapshot($snap);
        update_option(self::OPT_LASTRUN, ['time'=>time(), 'mode'=>'build'], false);
        return $snap;
    }

    private static function snapshot_file(): string {
        return wp_upload_dir()['basedir'] . '/tegatai-logs/fim_snapshot.json';
    }

    /**
     * The full snapshot lives in a file in the protected log directory. On large sites it was
     * several MB and could exceed max_allowed_packet as a single option. OPT_SNAPSHOT only keeps
     * a small stub ('files' = number of files) so existing "baseline exists?" checks keep working.
     */
    private static function save_snapshot(array $snap): bool {
        $file = self::snapshot_file();
        if (function_exists('tegatai_protect_directory')) {
            tegatai_protect_directory(dirname($file));
        } elseif (!is_dir(dirname($file))) {
            wp_mkdir_p(dirname($file));
        }
        $json = wp_json_encode($snap, JSON_UNESCAPED_SLASHES);
        if (!is_string($json) || @file_put_contents($file, $json, LOCK_EX) === false) return false;

        update_option(self::OPT_SNAPSHOT, [
            'version' => 2,
            'created' => (int)($snap['created'] ?? time()),
            'storage' => 'file',
            'files'   => count($snap['files'] ?? []),
        ], false);
        return true;
    }

    /**
     * Returns the full snapshot (or [] when none exists). Migrates a snapshot stored by older
     * versions in OPT_SNAPSHOT to the file once.
     */
    public static function get_snapshot(): array {
        $file = self::snapshot_file();
        if (file_exists($file)) {
            $snap = json_decode((string)@file_get_contents($file), true);
            return is_array($snap) ? $snap : [];
        }

        $legacy = get_option(self::OPT_SNAPSHOT, []);
        if (is_array($legacy) && !empty($legacy['files']) && is_array($legacy['files'])) {
            self::save_snapshot($legacy); // the option is only replaced by the stub if the file was written
            return $legacy;
        }
        return [];
    }

    public static function check_integrity(): array {
        $old = self::get_snapshot();
        if (empty($old) || empty($old['files']) || !is_array($old['files'])) {
            return ['ok'=>false, 'error'=>'no_snapshot', 'changed'=>[], 'new'=>[], 'deleted'=>[]];
        }
        $paths = self::fim_paths();
        $old_files = $old['files'];

        $current = [];
        foreach ($paths as $root_key => $root) {
            foreach (self::iter_files($root) as $abs) {
                $rel = self::relpath($abs, $root);
                $key = $root_key . ':' . $rel;
                $st = @stat($abs);
                if (!$st) continue;
                $size = (int)($st['size'] ?? 0);
                $mtime = (int)($st['mtime'] ?? 0);
                $current[$key] = ['root'=>$root_key,'rel'=>$rel,'size'=>$size,'mtime'=>$mtime,'abs'=>$abs];
            }
        }

        $changed = [];
        $deleted = [];
        $new = [];

        foreach ($old_files as $key => $meta) {
            if (!isset($current[$key])) {
                // TEGATAI_FIX: Konstruiere den absoluten Pfad für gelöschte Dateien
                $root_path = $paths[$meta['root']] ?? '';
                $meta['abs'] = $root_path ? rtrim($root_path, '/\\') . '/' . ltrim($meta['rel'], '/\\') : '';
                $deleted[$key] = $meta;
                continue;
            }
            $cur = $current[$key];

            if ((int)$meta['size'] !== (int)$cur['size'] || (int)$meta['mtime'] !== (int)$cur['mtime']) {
                $sha = self::hash_file_safely($cur['abs']);
                $oldsha = (string)($meta['sha'] ?? '');
                if ($sha !== $oldsha) {
                    // TEGATAI_FIX: Absoluten Pfad zum neuen Array hinzufügen
                    $changed[$key] = ['old'=>$meta, 'new'=>['size'=>$cur['size'],'mtime'=>$cur['mtime'],'sha'=>$sha,'abs'=>$cur['abs']]];
                }
            }
        }

        foreach ($current as $key => $cur) {
            if (!isset($old_files[$key])) {
                $sha = self::hash_file_safely($cur['abs']);
                // TEGATAI_FIX: Absoluten Pfad hinzufügen
                $new[$key] = ['root'=>$cur['root'],'rel'=>$cur['rel'],'size'=>$cur['size'],'mtime'=>$cur['mtime'],'sha'=>$sha,'abs'=>$cur['abs']];
            }
        }

        update_option(self::OPT_LASTRUN, ['time'=>time(), 'mode'=>'check', 'changed'=>count($changed), 'new'=>count($new), 'deleted'=>count($deleted)], false);

        return [
            'ok'      => true,
            'changed' => $changed,
            'new'     => $new,
            'deleted' => $deleted,
            'paths'   => $paths,
        ];
    }
}
