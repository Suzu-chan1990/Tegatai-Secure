<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * AbuseIPDB reporting.
 *
 * Bans from the firewall honeypot URL, the 404 instant ban, the 404 scan and the login traps
 * (local and received through The Hive) are queued and sent to AbuseIPDB in the background
 * via WP-Cron, so a ban never waits for the remote API.
 *
 * API key: TEGATAI_ABUSEIPDB_KEY (secrets file or wp-config.php).
 * Comments contain only the type of the ban, never URLs, usernames or other request data.
 */
class Tegatai_AbuseIPDB {
    const ENDPOINT     = 'https://api.abuseipdb.com/api/v2/report';
    const QUEUE_OPTION = 'tegatai_abuseipdb_queue';
    const STATUS_OPTION = 'tegatai_abuseipdb_status';
    const CRON_HOOK    = 'tegatai_abuseipdb_send';
    const MAX_QUEUE    = 500;
    const BATCH        = 20;
    const MAX_TRIES    = 3;
    // AbuseIPDB accepts the same IP from one account only once per 15 minutes.
    const REPEAT_WINDOW = 15 * MINUTE_IN_SECONDS;

    // AbuseIPDB category IDs
    const CAT_HACKING     = 15;
    const CAT_BRUTE_FORCE = 18;
    const CAT_BAD_BOT     = 19;
    const CAT_WEB_ATTACK  = 21;

    public function __construct() {
        add_action('tegatai_ip_banned', [$this, 'on_local_ban'], 20, 3);
        add_action('tegatai_hive_ban_applied', [$this, 'on_hive_ban'], 20, 4);
        add_action(self::CRON_HOOK, [__CLASS__, 'process_queue']);
    }

    public static function key() {
        return defined('TEGATAI_ABUSEIPDB_KEY') && is_string(TEGATAI_ABUSEIPDB_KEY) ? trim(TEGATAI_ABUSEIPDB_KEY) : '';
    }

    public static function enabled() {
        $ops = tegatai_get_setting('tegatai_options', []);
        return is_array($ops) && !empty($ops['abuseipdb_enabled']) && self::key() !== '';
    }

    /**
     * Maps a Tegatai ban reason to AbuseIPDB categories and a neutral comment.
     * Unknown reasons return null and are not reported.
     */
    public static function classify($reason) {
        $reason = (string) $reason;
        if (strpos($reason, 'Honeypot URL') === 0) {
            return [[self::CAT_WEB_ATTACK], 'Requested a honeypot URL'];
        }
        if (strpos($reason, '404 instant ban:') === 0) {
            // The trigger comes from a fixed list of probe paths (.env, phpmyadmin, shell.php ...)
            $trigger = trim(substr($reason, strlen('404 instant ban:')));
            $trigger = preg_replace('/[^A-Za-z0-9._\/-]/', '', $trigger);
            return [[self::CAT_WEB_ATTACK, self::CAT_HACKING], 'Probed for sensitive files' . ($trigger !== '' ? ' (' . $trigger . ')' : '')];
        }
        if (strpos($reason, '404 scan') === 0) {
            return [[self::CAT_WEB_ATTACK, self::CAT_BAD_BOT], 'Vulnerability scan (many 404 requests in a short time)'];
        }
        if (strpos($reason, 'Login form honeypot') === 0) {
            return [[self::CAT_BRUTE_FORCE], 'Automated login attempt (login form honeypot)'];
        }
        if (strpos($reason, 'Admin username honeypot') === 0) {
            return [[self::CAT_BRUTE_FORCE], 'Login attempt with a trap username'];
        }
        return null;
    }

    public function on_local_ban($ip, $reason, $level = '') {
        self::enqueue($ip, $reason, false);
    }

    public function on_hive_ban($ip, $reason, $level = '', $node = '') {
        self::enqueue($ip, $reason, true);
    }

    public static function enqueue($ip, $reason, $via_hive) {
        if (!self::enabled()) return false;
        // Only public addresses; private, loopback and reserved ranges are never reported.
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) return false;
        $class = self::classify($reason);
        if ($class === null) return false;

        $queue = get_option(self::QUEUE_OPTION, []);
        if (!is_array($queue)) $queue = [];
        foreach ($queue as $item) {
            if (($item['ip'] ?? '') === $ip) return false; // already waiting
        }
        $comment = 'Tegatai Security: ' . $class[1] . ($via_hive ? ' [reported by a Tegatai Hive peer]' : '');
        $queue[] = [
            'ip'         => $ip,
            'categories' => implode(',', $class[0]),
            'comment'    => substr($comment, 0, 1000),
            'time'       => time(),
            'tries'      => 0,
        ];
        if (count($queue) > self::MAX_QUEUE) $queue = array_slice($queue, -self::MAX_QUEUE);
        update_option(self::QUEUE_OPTION, $queue, false);

        if (!wp_next_scheduled(self::CRON_HOOK)) {
            wp_schedule_single_event(time() + 10, self::CRON_HOOK);
        }
        return true;
    }

    public static function status() {
        $st = get_option(self::STATUS_OPTION, []);
        $st = is_array($st) ? $st : [];
        $today = wp_date('Y-m-d');
        if (($st['day'] ?? '') !== $today) { $st['day'] = $today; $st['sent_today'] = 0; }
        return $st + ['sent_today' => 0, 'sent_total' => 0, 'last_ok' => 0, 'last_error' => '', 'last_error_at' => 0, 'backoff_until' => 0];
    }

    private static function save_status($st) {
        update_option(self::STATUS_OPTION, $st, false);
    }

    private static function error($st, $msg) {
        $st['last_error'] = $msg;
        $st['last_error_at'] = time();
        if (class_exists('Tegatai_Logger')) Tegatai_Logger::log('ABUSEIPDB', $msg);
        return $st;
    }

    public static function queue_size() {
        $q = get_option(self::QUEUE_OPTION, []);
        return is_array($q) ? count($q) : 0;
    }

    // WP-Cron worker: sends up to BATCH reports, keeps the rest for the next run.
    public static function process_queue() {
        $key = self::key();
        $queue = get_option(self::QUEUE_OPTION, []);
        if (!is_array($queue) || !$queue) return;
        $st = self::status();

        if ($key === '') { self::save_status(self::error($st, 'No API key (TEGATAI_ABUSEIPDB_KEY) - reports are kept in the queue.')); return; }
        if ((int) $st['backoff_until'] > time()) {
            wp_schedule_single_event((int) $st['backoff_until'] + 5, self::CRON_HOOK);
            return;
        }

        $keep = [];
        $sent = 0;
        $stop = false;
        foreach ($queue as $item) {
            if ($stop || $sent >= self::BATCH) { $keep[] = $item; continue; }

            $last = get_transient('teg_aipdb_' . md5($item['ip']));
            if ($last) continue; // reported in the last 15 minutes

            $res = wp_remote_post(self::ENDPOINT, [
                'timeout' => 8,
                'headers' => ['Key' => $key, 'Accept' => 'application/json'],
                'body'    => [
                    'ip'         => $item['ip'],
                    'categories' => $item['categories'],
                    'comment'    => $item['comment'],
                    'timestamp'  => gmdate('c', (int) $item['time']),
                ],
            ]);

            if (is_wp_error($res)) {
                $item['tries'] = (int) $item['tries'] + 1;
                if ($item['tries'] < self::MAX_TRIES) $keep[] = $item;
                $st = self::error($st, 'Connection error: ' . $res->get_error_message());
                $stop = true; // network problem: try the rest later
                continue;
            }

            $code = (int) wp_remote_retrieve_response_code($res);
            if ($code >= 200 && $code < 300) {
                set_transient('teg_aipdb_' . md5($item['ip']), 1, self::REPEAT_WINDOW);
                $sent++;
                $st['sent_today'] = (int) $st['sent_today'] + 1;
                $st['sent_total'] = (int) $st['sent_total'] + 1;
                $st['last_ok'] = time();
            } elseif ($code === 429) {
                // Daily limit or rate limit reached: pause until the API says so
                $retry = (int) wp_remote_retrieve_header($res, 'retry-after');
                $reset = (int) wp_remote_retrieve_header($res, 'x-ratelimit-reset');
                $until = $retry > 0 ? time() + $retry : ($reset > time() ? $reset : time() + HOUR_IN_SECONDS);
                $st['backoff_until'] = $until;
                $st = self::error($st, 'Rate limit reached (HTTP 429) - paused until ' . wp_date('Y-m-d H:i', $until) . '.');
                $keep[] = $item;
                $stop = true;
            } elseif ($code === 422) {
                // Rejected (e.g. same IP within 15 minutes or invalid IP): drop it
                $st = self::error($st, 'Report for ' . $item['ip'] . ' rejected (HTTP 422): ' . self::api_message($res));
            } elseif ($code === 401 || $code === 403) {
                $st = self::error($st, 'API key rejected (HTTP ' . $code . '): ' . self::api_message($res));
                $keep[] = $item;
                $stop = true;
            } else {
                $item['tries'] = (int) $item['tries'] + 1;
                if ($item['tries'] < self::MAX_TRIES) $keep[] = $item;
                $st = self::error($st, 'Unexpected answer (HTTP ' . $code . '): ' . self::api_message($res));
            }
        }

        update_option(self::QUEUE_OPTION, $keep, false);
        self::save_status($st);
        if ($keep && !wp_next_scheduled(self::CRON_HOOK)) {
            $next = (int) $st['backoff_until'] > time() ? (int) $st['backoff_until'] + 5 : time() + 60;
            wp_schedule_single_event($next, self::CRON_HOOK);
        }
    }

    private static function api_message($res) {
        $body = json_decode((string) wp_remote_retrieve_body($res), true);
        $detail = $body['errors'][0]['detail'] ?? '';
        return substr(sanitize_text_field((string) $detail), 0, 200);
    }
}
new Tegatai_AbuseIPDB();
