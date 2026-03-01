<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_Option_Scanner {
    public static function scan(int $limit = 2500): array {
        global $wpdb;
        $limit = max(200, min(10000, (int)$limit));
        $table = $wpdb->options;

        $rows = $wpdb->get_results($wpdb->prepare(
            "SELECT option_name, autoload, option_value FROM {$table} ORDER BY autoload DESC, option_id DESC LIMIT %d",
            $limit
        ), ARRAY_A);

        $hits = [];
        $patterns = [
            '/eval\s*\(/i',
            '/base64_decode\s*\(/i',
            '/gzinflate\s*\(/i',
            '/assert\s*\(/i',
            '/<\s*script\b/i',
            '/<\s*iframe\b/i',
            '/fromCharCode\s*\(/i',
        ];

        foreach ($rows as $r) {
            $name = (string)($r['option_name'] ?? '');
            $autoload = (string)($r['autoload'] ?? '');
            $val = (string)($r['option_value'] ?? '');

            if ($name === 'rewrite_rules' || $name === 'cron') continue;

            // Whitelist Check (Standard-Caches und Pagebuilder)
            $skip = false;
            $whitelist = ['_transient_', 'elementor_', 'wp_rocket', 'et_builder', 'litespeed', 'astra_', 'smush_'];
            
            // Eigene Ausnahmen aus dem Dashboard laden
            $ops = get_option('tegatai_options', []);
            if (!empty($ops['option_whitelist_names'])) {
                $custom = explode("\n", str_replace(["\r\n", "\r"], "\n", $ops['option_whitelist_names']));
                foreach ($custom as $c) {
                    $c = trim(strtolower($c));
                    if ($c !== '') $whitelist[] = $c;
                }
            }
            
            $name_lower = strtolower($name);
            foreach ($whitelist as $w) {
                if (strpos($name_lower, $w) !== false) {
                    $skip = true;
                    break;
                }
            }
            if ($skip) continue;

            $sus = false;
            foreach ($patterns as $p) {
                if (preg_match($p, $val)) { $sus = true; break; }
            }

            if (!$sus && strlen($val) > 8000 && preg_match('/[A-Za-z0-9\/\+=]{2000,}/', $val)) {
                $sus = true;
            }

            if ($sus) {
                $snip = substr(preg_replace('/\s+/', ' ', $val), 0, 220);
                $hits[] = ['name'=>$name, 'autoload'=>$autoload, 'snippet'=>$snip];
                if (count($hits) >= 500) break;
            }
        }

        if (class_exists('Tegatai_Timeline') && !empty($hits)) {
            Tegatai_Timeline::add('options', 'Dangerous options scan: hits=' . count($hits));
        }

        return ['ok'=>true, 'hits'=>$hits];
    }
}
