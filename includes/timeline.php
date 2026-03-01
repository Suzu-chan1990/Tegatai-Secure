<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Timeline {
    const OPT = 'teg_timeline_v1';

    public static function init(): void {}

    public static function add(string $type, string $msg): void {
        $ev = [
            'time' => time(),
            'type' => substr(preg_replace('/[^a-z0-9_\-]/i', '', $type), 0, 40),
            'msg'  => substr(wp_strip_all_tags($msg), 0, 300),
        ];
        $arr = get_option(self::OPT, []);
        $arr = is_array($arr) ? $arr : [];
        array_unshift($arr, $ev);
        if (count($arr) > 1000) { $arr = array_slice($arr, 0, 1000); }
        update_option(self::OPT, $arr, false);
    }

    public static function get(int $limit = 250): array {
        $arr = get_option(self::OPT, []);
        $arr = is_array($arr) ? $arr : [];
        return array_slice($arr, 0, max(1, min(1000, $limit)));
    }

    public static function clear(): void {
        update_option(self::OPT, [], false);
    }
}
