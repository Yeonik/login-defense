<?php

declare(strict_types=1);

return [

    /*
    |--------------------------------------------------------------------------
    | Master switch
    |--------------------------------------------------------------------------
    | When disabled the bridge middleware becomes a pass-through and Laravel's
    | default login behaviour is unchanged. Useful for staging or incident
    | rollback without removing the package.
    */
    'enabled' => true,

    /*
    |--------------------------------------------------------------------------
    | Escalation thresholds (per identifier + IP key)
    |--------------------------------------------------------------------------
    | Graduated friction: cheap for legitimate users, increasingly expensive for
    | automation. Below `captcha_after` a login is allowed; from there a captcha
    | is demanded; from `lockout_after` the key is locked for a growing window.
    */
    'captcha_after' => 3,
    'lockout_after' => 6,

    'lockout' => [
        // retryAfter = min(base_seconds * multiplier ^ (attempts - lockout_after), max_seconds)
        'base_seconds' => 60,
        'multiplier' => 2,
        'max_seconds' => 3600,
    ],

    // Sliding window (TTL) for the per-key failure counter.
    'window_seconds' => 900,

    /*
    |--------------------------------------------------------------------------
    | Global per-IP throttle (looser, never locks)
    |--------------------------------------------------------------------------
    | Distributed attempts spread across many usernames keep every per-key
    | counter low. This looser per-IP counter raises friction to a captcha once
    | an IP is noisy — but it never triggers a lockout, because an IP-only lock
    | would take out a whole NAT'd office and barely inconvenience a botnet.
    */
    'global_throttle' => [
        'max_attempts' => 100,
        'window_seconds' => 900,
    ],

    /*
    |--------------------------------------------------------------------------
    | Captcha verification
    |--------------------------------------------------------------------------
    | driver: null | recaptcha | hcaptcha. The `null` driver treats every token
    | as valid and is intended for local development only.
    |
    | fail_open: what to do when the captcha provider is unreachable. Default is
    | fail-closed (false) — a timed-out provider must not wave traffic through.
    | Either way a provider outage never escalates to a lockout; the user is not
    | punished for the provider's downtime.
    |
    | The secret is read from the environment, never hard-coded.
    */
    'captcha' => [
        'driver' => env('LOGIN_DEFENSE_CAPTCHA_DRIVER', 'null'),
        'fail_open' => (bool) env('LOGIN_DEFENSE_CAPTCHA_FAIL_OPEN', false),
        'secret' => env('LOGIN_DEFENSE_CAPTCHA_SECRET'),
    ],

];
