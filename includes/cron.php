<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Cron {

    const OPT_MW_LAST_SUMMARY = 'teg_mw_last_summary_v1';
    const OPT_FIM_LAST_SUMMARY = 'teg_fim_last_summary_v1';
    const OPT_SEAL_ENABLED = 'teg_seal_enabled_v1';
    const OPT_SEAL_PHRASE = 'teg_seal_phrase_v1';

    public static function init(): void {
        add_filter('cron_schedules', [__CLASS__, 'add_schedules']);
        add_action('tegatai_malware_cron', [__CLASS__, 'run_malware_cron']);
        add_action('tegatai_fim_cron', [__CLASS__, 'run_fim_cron']);

        // Login "site seal"
        add_filter('login_message', [__CLASS__, 'login_seal_message']);
    }

    public static function add_schedules($schedules) {
        if (!isset($schedules['tegatai_6h'])) {
            $schedules['tegatai_6h'] = [
                'interval' => 6 * HOUR_IN_SECONDS,
                'display'  => __('Every 6 hours (Tegatai)', 'tegatai-secure'),
            ];
        }
        return $schedules;
    }

    public static function activate(): void {
        self::maybe_seed_seal_phrase();

        if (!wp_next_scheduled('tegatai_malware_cron')) {
            wp_schedule_event(time() + 300, 'tegatai_6h', 'tegatai_malware_cron');
        }
        if (!wp_next_scheduled('tegatai_fim_cron')) {
            wp_schedule_event(time() + 600, 'tegatai_6h', 'tegatai_fim_cron');
        }
    }

    public static function deactivate(): void {
        $ts = wp_next_scheduled('tegatai_malware_cron');
        if ($ts) { wp_unschedule_event($ts, 'tegatai_malware_cron'); }
        $ts = wp_next_scheduled('tegatai_fim_cron');
        if ($ts) { wp_unschedule_event($ts, 'tegatai_fim_cron'); }
    }

    public static function run_malware_cron(): void {
        if (!class_exists('Tegatai_Malware_Scanner')) return;

        // Incremental run
        $res = Tegatai_Malware_Scanner::run(['limit' => 1200, 'reset' => false]);

        $hits = isset($res['hits']) && is_array($res['hits']) ? $res['hits'] : [];
        $summary = [
            'time' => time(),
            'done' => !empty($res['done']),
            'checked' => (int)($res['checked'] ?? 0),
            'total_files' => (int)($res['total_files'] ?? 0),
            'hit_count' => count($hits),
            'top_sev' => self::top_sev($hits),
        ];
        update_option(self::OPT_MW_LAST_SUMMARY, $summary, false);
    }

    public static function run_fim_cron(): void {
        if (!class_exists('Tegatai_FIM')) return;

        // Only if baseline exists
        $snap = get_option(Tegatai_FIM::OPT_SNAPSHOT, []);
        if (empty($snap) || empty($snap['files'])) return;

        $res = Tegatai_FIM::check_integrity();
        if (!is_array($res) || empty($res['ok'])) return;

        $changed = is_array($res['changed'] ?? null) ? count($res['changed']) : 0;
        $new     = is_array($res['new'] ?? null) ? count($res['new']) : 0;
        $deleted = is_array($res['deleted'] ?? null) ? count($res['deleted']) : 0;

        $summary = [
            'time' => time(),
            'changed' => $changed,
            'new' => $new,
            'deleted' => $deleted,
        ];
        update_option(self::OPT_FIM_LAST_SUMMARY, $summary, false);
    }

    private static function top_sev(array $hits): int {
        $top = 0;
        foreach ($hits as $h) {
            $sev = (int)($h['sev'] ?? 0);
            if ($sev > $top) $top = $sev;
        }
        return $top;
    }

    public static function maybe_seed_seal_phrase(): void {
        $enabled = get_option(self::OPT_SEAL_ENABLED, null);
        if ($enabled === null) {
            update_option(self::OPT_SEAL_ENABLED, 1, false);
        }
        $phrase = get_option(self::OPT_SEAL_PHRASE, '');
        if (!is_string($phrase) || $phrase === '') {
            // short human-friendly phrase
            $phrase = strtoupper(substr(wp_generate_password(16, false, false), 0, 16));
            update_option(self::OPT_SEAL_PHRASE, $phrase, false);
        }
    }

    public static function login_seal_message($message) {
        $enabled = (int)get_option(self::OPT_SEAL_ENABLED, 1);
        if ($enabled !== 1) return $message;

        $phrase = (string)get_option(self::OPT_SEAL_PHRASE, '');
        if ($phrase === '') {
            self::maybe_seed_seal_phrase();
            $phrase = (string)get_option(self::OPT_SEAL_PHRASE, '');
        }

        $host = isset($_SERVER['HTTP_HOST']) ? sanitize_text_field((string)$_SERVER['HTTP_HOST']) : '';
        $host = preg_replace('/[^a-z0-9\.\-:]/i', '', $host);

        $html  = '<div style="margin:14px 0 10px;padding:10px 12px;border:1px solid #dcdcde;border-radius:10px;background:#fff;">';
        $html .= '<div style="font-weight:800;margin-bottom:4px;">🔒 ' . esc_html__('Verified login page', 'tegatai-secure') . '</div>';
        if ($host !== '') {
            $html .= '<div style="color:#50575e;font-size:13px;">' . esc_html__('Domain', 'tegatai-secure') . ': <code>' . esc_html($host) . '</code></div>';
        }
        if ($phrase !== '') {
            $html .= '<div style="color:#50575e;font-size:13px;margin-top:2px;">' . esc_html__('Seal phrase', 'tegatai-secure') . ': <code>' . esc_html($phrase) . '</code></div>';
        }
        $html .= '</div>';

        return $message . $html;
    }
}
