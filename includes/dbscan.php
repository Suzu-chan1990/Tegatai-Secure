<?php
if (!defined('ABSPATH')) { exit; }

class Tegatai_DBScan {

    public static function scan_stored_xss(int $limit = 200): array {
        global $wpdb;

        $prefix = $wpdb->prefix;
        $tables = [];

        $like = $wpdb->esc_like($prefix) . '%';
        $existing = $wpdb->get_col("SHOW TABLES LIKE '{$like}'");
        $existing = is_array($existing) ? $existing : [];

        $want = [
            $prefix . 'posts'     => ['id'=>'ID', 'fields'=>['post_content','post_excerpt','post_title']],
            $prefix . 'postmeta'  => ['id'=>'meta_id', 'fields'=>['meta_value']],
            $prefix . 'options'   => ['id'=>'option_id', 'fields'=>['option_value','autoload','option_name']],
            $prefix . 'comments'  => ['id'=>'comment_ID', 'fields'=>['comment_content','comment_author','comment_author_url']],
            $prefix . 'usermeta'  => ['id'=>'umeta_id', 'fields'=>['meta_value','meta_key']],
        ];

        foreach ($want as $t => $cfg) {
            if (in_array($t, $existing, true)) {
                $tables[$t] = $cfg;
            }
        }

        $patterns = [
            '/<\s*script\b/i',
            '/on\w+\s*=\s*["\']?/i',
            '/javascript\s*:/i',
            '/data\s*:\s*text\/html/i',
            '/<\s*iframe\b/i',
            '/<\s*object\b/i',
            '/<\s*embed\b/i',
            '/document\.write\s*\(/i',
            '/\beval\s*\(/i',
            '/atob\s*\(/i',
        ];

        // --- TEGATAI_FIX: Custom Patterns Injection ---
        $ops = get_option('tegatai_options', []);
        $extra_patterns_raw = isset($ops['dbscan_extra_patterns']) ? $ops['dbscan_extra_patterns'] : '';
        if (!empty(trim($extra_patterns_raw))) {
            $extra_lines = array_filter(array_map('trim', explode("\n", str_replace(["\r\n", "\r"], "\n", $extra_patterns_raw))));
            foreach ($extra_lines as $ep) {
                if (!empty($ep)) {
                    $patterns[] = $ep;
                }
            }
        }
        // ----------------------------------------------

        $hits = [];
        $checked = 0;

        foreach ($tables as $table => $cfg) {
            $idcol = $cfg['id'];
            $fields = $cfg['fields'];

            foreach ($fields as $field) {
                $sql = "SELECT {$idcol} AS id, {$field} AS val FROM {$table} ORDER BY {$idcol} DESC LIMIT %d";
                $rows = $wpdb->get_results($wpdb->prepare($sql, $limit), ARRAY_A);
                if (!is_array($rows)) continue;

                foreach ($rows as $r) {
                    $checked++;
                    $val = (string)($r['val'] ?? '');
                    if ($val === '') continue;

                    $matched = false;
                    foreach ($patterns as $pat) {
                        // @ unterdrückt PHP-Warnings bei fehlerhaften Custom-Regex-Eingaben
                        if (@preg_match($pat, $val)) { $matched = true; break; }
                    }
                    if (!$matched) continue;

                    $hits[] = [
                        'table' => $table,
                        'id'    => (string)($r['id'] ?? ''),
                        'field' => $field,
                        'snippet' => self::make_snippet($val),
                    ];

                    if (count($hits) >= 2000) { break 3; }
                }
            }
        }

        return [
            'prefix' => $prefix,
            'tables_scanned' => array_keys($tables),
            'rows_checked' => $checked,
            'hits' => $hits,
        ];
    }

    private static function make_snippet(string $s): string {
        $s = preg_replace('/\s+/', ' ', $s);
        $s = trim($s);
        if (strlen($s) <= 220) return $s;
        return substr($s, 0, 220) . '…';
    }
}
