<?php
if ( ! defined( 'ABSPATH' ) ) { exit; }

/**
 * Central, expiring IP ban list.
 *
 * Every ban decision (firewall traps, 404 scans, login honeypots, Hive peers) goes through
 * this class, and Tegatai_Firewall::run_checks() enforces it on every request. Previously
 * bans were only counters that were checked on 404 pages, so a "banned" IP could still use
 * all normal pages, wp-login.php, XML-RPC and REST.
 */
class Tegatai_Bans {
    const OPTION   = 'tegatai_bans';
    const MAX_BANS = 5000;

    private static $cache = null;

    private static function load() {
        if (self::$cache === null) {
            $bans = get_option(self::OPTION, []);
            self::$cache = is_array($bans) ? $bans : [];
        }
        return self::$cache;
    }

    public static function is_banned($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;
        $bans = self::load();
        return isset($bans[$ip]) && (int)($bans[$ip]['until'] ?? 0) > time();
    }

    /**
     * @param string $source 'local' or 'hive:<peer>'
     * @return bool true if the IP was not banned before
     */
    public static function add($ip, $ttl, $reason, $source = 'local', $level = 'critical') {
        if (!filter_var($ip, FILTER_VALIDATE_IP)) return false;

        $now  = time();
        $bans = array_filter(self::load(), function ($b) use ($now) { return (int)($b['until'] ?? 0) > $now; });
        $is_new = !isset($bans[$ip]);
        $until  = $now + max(60, (int)$ttl);
        if (!$is_new && (int)$bans[$ip]['until'] > $until) {
            $until = (int)$bans[$ip]['until']; // never shorten an existing ban
        }
        $bans[$ip] = ['until' => $until, 'reason' => (string)$reason, 'source' => (string)$source, 'level' => (string)$level];

        if (count($bans) > self::MAX_BANS) {
            uasort($bans, function ($a, $b) { return $a['until'] <=> $b['until']; });
            $bans = array_slice($bans, -self::MAX_BANS, null, true);
        }
        self::$cache = $bans;
        update_option(self::OPTION, $bans, false);
        return $is_new;
    }

    public static function remove($ip) {
        $bans = self::load();
        if (!isset($bans[$ip])) return;
        unset($bans[$ip]);
        self::$cache = $bans;
        update_option(self::OPTION, $bans, false);
    }

    public static function active() {
        $now = time();
        return array_filter(self::load(), function ($b) use ($now) { return (int)($b['until'] ?? 0) > $now; });
    }

    /**
     * Bans an IP locally and announces it to the Hive (which applies its own protections).
     * Callers are expected to have skipped whitelisted IPs already.
     */
    public static function ban_and_broadcast($ip, $ttl, $reason, $level = 'critical') {
        if (self::add($ip, $ttl, $reason, 'local', $level)) {
            do_action('tegatai_ip_banned', $ip, $reason, $level);
        }
    }
}
