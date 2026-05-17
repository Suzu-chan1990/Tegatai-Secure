<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Cron_Monitor {
    public static function init(): void {
        add_action('init', [__CLASS__, 'maybe_log_once_daily']);
    }

    public static function inspect(): array {
        $cron = _get_cron_array();
        $hooks = [];

        if (is_array($cron)) {
            foreach ($cron as $ts => $events) {
                if (!is_array($events)) continue;
                foreach ($events as $hook => $d) {
                    $next = is_numeric($ts) ? date_i18n('Y-m-d H:i', (int)$ts) : '-';
                    $flag = self::is_suspicious((string)$hook);
                    $hooks[] = ['hook'=>$hook, 'next'=>$next, 'flag'=>$flag];
                }
            }
        }

        $by = [];
        foreach ($hooks as $h) {
            $k = (string)$h['hook'];
            if (!isset($by[$k])) { $by[$k] = $h; }
        }

        $all = array_values($by);
        usort($all, function($a, $b) { return strcmp((string)$a['hook'], (string)$b['hook']); });
        $hits = array_values(array_filter($all, function($r){ return !empty($r['flag']); }));

        return ['ok'=>true, 'all'=>$all, 'hits'=>$hits];
    }

    private static function is_suspicious(string $hook): bool {
        $h = strtolower($hook);
        
        $whitelist = ['akismet', 'antispam', 'mailpoet', 'smtp', 'fluent', 'action_scheduler', 'woocommerce', 'exec_dir'];
        
        // Eigene Ausnahmen aus dem Dashboard laden
        $ops = get_option('tegatai_options', []);
        if (!empty($ops['cron_whitelist_hooks'])) {
            $custom = explode("\n", str_replace(["\r\n", "\r"], "\n", $ops['cron_whitelist_hooks']));
            foreach ($custom as $c) {
                $c = trim(strtolower($c));
                if ($c !== '') $whitelist[] = $c;
            }
        }
        
        foreach ($whitelist as $w) { if (strpos($h, $w) !== false) return false; }

        $bad = ['eval', 'base64', 'shell', 'exec', 'curl', 'wget', 'payload', 'inject', 'spam', 'mailer', 'crypto', 'miner'];
        foreach ($bad as $b) { if (strpos($h, $b) !== false) return true; }
        if (strlen($h) >= 28 && preg_match('/[a-f0-9]{20,}/', $h)) return true;
        return false;
    }

    public static function maybe_log_once_daily(): void {
        $k = 'teg_cron_monitor_lastlog_v1';
        $last = (int)get_option($k, 0);
        if ($last > (time() - DAY_IN_SECONDS)) return;

        $res = self::inspect();
        $hits = $res['hits'] ?? [];
        if (class_exists('Tegatai_Timeline') && !empty($hits)) {
            Tegatai_Timeline::add('cron', 'Suspicious cron hooks detected: ' . count($hits));
        }
        update_option($k, time(), false);
    }
}
