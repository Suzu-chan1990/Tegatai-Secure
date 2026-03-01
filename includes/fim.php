<?php
if (!defined('ABSPATH')) { exit; }

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

        update_option(self::OPT_SNAPSHOT, $snap, false);
        update_option(self::OPT_LASTRUN, ['time'=>time(), 'mode'=>'build'], false);
        return $snap;
    }

    public static function check_integrity(): array {
        $old = get_option(self::OPT_SNAPSHOT, []);
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
                $deleted[$key] = $meta;
                continue;
            }
            $cur = $current[$key];

            if ((int)$meta['size'] !== (int)$cur['size'] || (int)$meta['mtime'] !== (int)$cur['mtime']) {
                $sha = self::hash_file_safely($cur['abs']);
                $oldsha = (string)($meta['sha'] ?? '');
                if ($sha !== $oldsha) {
                    $changed[$key] = ['old'=>$meta, 'new'=>['size'=>$cur['size'],'mtime'=>$cur['mtime'],'sha'=>$sha]];
                }
            }
        }

        foreach ($current as $key => $cur) {
            if (!isset($old_files[$key])) {
                $sha = self::hash_file_safely($cur['abs']);
                $new[$key] = ['root'=>$cur['root'],'rel'=>$cur['rel'],'size'=>$cur['size'],'mtime'=>$cur['mtime'],'sha'=>$sha];
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
