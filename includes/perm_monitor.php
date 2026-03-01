<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Perm_Monitor {

    public static function check(): array {
        $paths = [];
        $paths[] = ABSPATH . 'wp-config.php';
        $paths[] = dirname(ABSPATH) . '/wp-config.php';
        $paths[] = ABSPATH . '.htaccess';
        $paths[] = ABSPATH . 'index.php';
        $paths[] = ABSPATH . 'wp-admin/.htaccess';

        $rows = [];
        $bad = [];

        foreach ($paths as $p) {
            $rp = realpath($p);
            if (!$rp || !file_exists($rp)) continue;

            $perm = @fileperms($rp);
            if ($perm === false) continue;
            $oct = substr(sprintf('%o', $perm), -4);

            $last = (int)substr($oct, -1);
            $is_bad = in_array($last, [2,3,6,7], true);

            $rows[] = ['path'=>$rp, 'perm'=>$oct, 'bad'=>$is_bad];
            if ($is_bad) $bad[] = $rp;
        }

        if (class_exists('Tegatai_Timeline') && !empty($bad)) {
            Tegatai_Timeline::add('perms', 'World-writable critical files: ' . count($bad));
        }

        return ['ok'=>true, 'rows'=>$rows, 'bad'=>$bad];
    }
}
