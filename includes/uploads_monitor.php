<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Uploads_Monitor {

    const OPT_LAST = 'teg_uploads_hits_v1';

    public static function init(): void {}

    public static function scan(int $limit = 2000): array {
        $limit = max(200, min(20000, (int)$limit));
        $ud = wp_upload_dir();
        $base = isset($ud['basedir']) ? (string)$ud['basedir'] : '';
        if ($base === '' || !is_dir($base)) return ['ok'=>false, 'error'=>'uploads_missing'];

        $hits = [];
        $bad_ext = '/\.(php[1-8]?|pht|phtml?|phps|phar|cgi|pl|asp|aspx|jsp)$/i';

        $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
        foreach ($it as $f) {
            if (!$f->isFile()) continue;
            $p = $f->getPathname();
            if (preg_match($bad_ext, $p)) {
                $rel = ltrim(str_replace('\\', '/', str_replace($base, '', $p)), '/');
                $hits[] = 'uploads:' . $rel;
                if (count($hits) >= $limit) break;
            }
        }

        update_option(self::OPT_LAST, $hits, false);
        if (class_exists('Tegatai_Timeline') && !empty($hits)) {
            Tegatai_Timeline::add('uploads', 'Uploads suspicious files: ' . count($hits));
        }

        return ['ok'=>true, 'hits'=>$hits];
    }

    public static function quarantine_hits(int $max = 50): array {
        $max = max(1, min(200, (int)$max));
        $hits = get_option(self::OPT_LAST, []);
        $hits = is_array($hits) ? $hits : [];
        $ud = wp_upload_dir();
        $base = isset($ud['basedir']) ? (string)$ud['basedir'] : '';
        if ($base === '' || !is_dir($base)) return ['ok'=>false, 'error'=>'uploads_missing'];

        $done = 0; $fail = 0;

        if (!class_exists('Tegatai_Quarantine')) {
            return ['ok'=>false, 'error'=>'quarantine_missing', 'hits'=>$hits];
        }

        foreach ($hits as $h) {
            if ($done + $fail >= $max) break;
            $rel = (string)$h;
            if (strpos($rel, 'uploads:') !== 0) continue;
            $sub = substr($rel, 8);
            $abs = $base . DIRECTORY_SEPARATOR . ltrim($sub, '/\\');
            $r = Tegatai_Quarantine::quarantine_file($abs);
            if (!empty($r['ok'])) $done++; else $fail++;
        }

        if (class_exists('Tegatai_Timeline') && ($done > 0)) {
            Tegatai_Timeline::add('quarantine', 'Uploads quarantine: ok=' . $done . ', fail=' . $fail);
        }

        return ['ok'=>true, 'hits'=>$hits, 'quarantined_ok'=>$done, 'quarantined_fail'=>$fail];
    }
}
