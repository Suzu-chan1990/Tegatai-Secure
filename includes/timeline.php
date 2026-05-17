<?php
if (!defined('ABSPATH')) { exit; }

/* TEGATAI_TIMELINE_PRUNING_V1 applied */
class Tegatai_Timeline {
    const OPT = 'teg_timeline_v1';

    public static function init(): void {
        // Hängt sich ressourcenschonend in den bestehenden Tegatai-Cron ein (läuft alle 6h)
        add_action('tegatai_malware_cron', [__CLASS__, 'prune_old_events']);
    }

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

    /**
     * Entfernt Events, die älter als $days Tage sind, um die wp_options sauber zu halten.
     */
    public static function prune_old_events(int $days = 30): void {
        $arr = get_option(self::OPT, []);
        if (!is_array($arr) || empty($arr)) return;

        $cutoff = time() - ($days * 86400);
        $filtered = array_filter($arr, function($ev) use ($cutoff) {
            return isset($ev['time']) && (int)$ev['time'] >= $cutoff;
        });

        // Die DB nur aktualisieren (Schreibzugriff), wenn wirklich alte Einträge gelöscht wurden
        if (count($filtered) !== count($arr)) {
            update_option(self::OPT, array_values($filtered), false);
        }
    }
}
