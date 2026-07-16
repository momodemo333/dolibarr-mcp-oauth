<?php
declare(strict_types=1);

/*
 * Minimal pure-PHP stand-ins for the Dolibarr globals touched by
 * DolibarrMcpOAuth\OAuthServer, so the class can be unit-tested outside
 * a running Dolibarr instance. Intentionally trivial: no real crypto,
 * no real DB, no real syslog.
 */

if (!defined('MAIN_DB_PREFIX')) {
    define('MAIN_DB_PREFIX', 'llx_');
}

if (!function_exists('dol_now')) {
    function dol_now(): int
    {
        return time();
    }
}

if (!function_exists('dol_syslog')) {
    function dol_syslog(string $message, int $level = LOG_INFO): void
    {
        // no-op in tests; swap for an in-memory collector if a test needs to assert on log content
    }
}

if (!function_exists('dol_trunc')) {
    function dol_trunc(string $string, int $size = 40): string
    {
        return mb_strlen($string) > $size ? mb_substr($string, 0, $size) : $string;
    }
}

if (!function_exists('dolEncrypt')) {
    function dolEncrypt(string $chain, string $key2 = '', string $key3 = '', string $ext = ''): string
    {
        return 'test-encrypted:'.$chain;
    }
}

if (!function_exists('dolDecrypt')) {
    function dolDecrypt(string $chain): string
    {
        $prefix = 'test-encrypted:';
        return str_starts_with($chain, $prefix) ? substr($chain, strlen($prefix)) : $chain;
    }
}

if (!function_exists('dol_string_nounprintableascii')) {
    function dol_string_nounprintableascii(string $str, int $removetabcrlf = 1): string
    {
        $pattern = $removetabcrlf ? '/[\x00-\x1F\x7F]/u' : '/[\x00-\x08\x11-\x12\x14-\x1F\x7F]/u';
        return (string) preg_replace($pattern, '', $str);
    }
}

if (!isset($GLOBALS['conf'])) {
    $GLOBALS['conf'] = (object) ['entity' => 1];
}
