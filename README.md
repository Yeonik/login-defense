# login-defense

[![CI](https://github.com/Yeonik/login-defense/actions/workflows/ci.yml/badge.svg)](https://github.com/Yeonik/login-defense/actions/workflows/ci.yml)
[![PHP](https://img.shields.io/badge/PHP-8.3%2B-777BB4?logo=php&logoColor=white)](composer.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![PHPStan](https://img.shields.io/badge/PHPStan-level%206-2a5ea7.svg)](phpstan.neon.dist)

Progressive login protection for PHP: track failed attempts, escalate to a
captcha challenge, then to a timed lockout — with the escalation policy explicit,
configurable and tested. Framework-agnostic core, thin Laravel bridge included.

```
below the threshold        →  Allow
a few failures later       →  RequireCaptcha
too many failures          →  Lockout (retry-after grows, then caps)
```

---

## Why this exists

**"Why not just use the framework's rate limiter?"**
The built-ins are binary — under the limit you pass, over it you're blocked. Real
attacks live in between: slow credential stuffing that stays under any sane limit,
distributed attempts that never trip a per-IP counter. Production needs
*graduated friction* — cheap for legitimate users, increasingly expensive for
automation — plus an explicit, auditable policy for when each step engages. This
package makes that escalation a first-class, configurable, tested object instead
of scattered `if` statements in a controller.

**"Why is the core framework-agnostic?"**
Because abuse mitigation is domain logic, not HTTP plumbing. The rules for when to
demand a captcha do not depend on whether the request arrived through Laravel,
Symfony, or a queue worker. Keeping the decision in pure PHP behind PSR interfaces
means it is testable without booting a framework — and
[the core test suite proves it](#the-architecture-is-the-point) by running with no
framework installed at all.

---

## Install

```bash
composer require yeonik/login-defense
```

Requires PHP 8.3+. The core depends only on PSR interfaces
(`simple-cache`, `event-dispatcher`, `clock`, `http-client`, `http-factory`,
`http-server-middleware`). The Laravel bridge is auto-discovered when
`illuminate/support` is present.

Publish the config (Laravel):

```bash
php artisan vendor:publish --tag=login-defense-config
```

---

## The escalation ladder

The decision is a pure function of the failure count on a key and the config:

| Failures on the key            | Decision                                            |
| ------------------------------ | --------------------------------------------------- |
| `< captcha_after` (default 3)  | `Allow`                                             |
| `< lockout_after` (default 6)  | `RequireCaptcha`                                    |
| `>= lockout_after`             | `Lockout`, `retryAfter = min(base · mult^extra, max)` |

`retryAfter` starts at `base_seconds` (60s) and doubles with each further failure
until it hits `max_seconds` (1h), where it stays. All thresholds and windows are
configurable in `config/login-defense.php`.

---

## Usage

### Framework-agnostic core

The application owns its authentication; the guard owns the escalation decision.

```php
use LoginDefense\Core\LoginGuard;

// 1. Before checking credentials, ask the guard what to do.
$decision = $guard->check($email, $ip, $request->captchaToken());

if ($decision->isLockedOut()) {
    return response('Too many attempts', 429)
        ->withHeader('Retry-After', (string) $decision->retryAfter);
}

if ($decision->requiresCaptcha()) {
    return response('Captcha required', 422);
}

// 2. Now run your own credential check, and report the outcome back.
if ($this->credentialsAreValid($email, $password)) {
    $guard->recordSuccess($email, $ip);   // clears the counter for this key
} else {
    $guard->recordFailure($email, $ip);   // moves the key up the ladder
}
```

A ready-made [PSR-15 middleware](src/Core/Http/LoginDefenseMiddleware.php) is
included for stacks that prefer to gate the route directly.

### Laravel

Attach the middleware to your login route:

```php
Route::post('/login', LoginController::class)
    ->middleware(\LoginDefense\Bridge\Laravel\ProtectsLogin::class);
```

It reads the identifier (`email` or `username`), the client IP and
`captcha_token` from the request, and short-circuits with `429` (locked out) or
`422` (captcha required). Reporting the auth outcome stays with your controller
via `LoginGuard::recordFailure()` / `recordSuccess()` — the middleware enforces
consequences, it does not guess whether your credentials were correct. Set
`login-defense.enabled` to `false` and the middleware becomes a pass-through, with
Laravel's default behaviour unchanged.

---

## Security decisions, and why

Each of these is a deliberate call, commented at the point it is made in the code.

- **Combined key for lockout.** Keying on IP alone lets one NAT'd office lock out
  everyone behind it and does nothing against distributed attempts; keying on the
  username alone hands an attacker a denial-of-service against the victim's own
  account. The lockout key is `identifier + IP` (hashed), narrowing a lock to
  "this account, from this source". A separate, looser **global per-IP throttle**
  raises friction to a captcha when one IP is noisy across many usernames — but it
  never locks, precisely so it cannot take out a shared office.

- **No user enumeration.** Escalation is driven only by the attempt count on the
  key, never by whether a user record was found. The same code path and the same
  response shape run whether or not the account exists, so neither the body nor
  the timing leaks its existence.

- **Captcha outage: fail-closed by default.** If the captcha provider times out,
  the challenge stands (`fail_open = false`) — a provider we cannot reach must not
  wave traffic through. It is configurable. Either way, a provider outage never
  escalates a user into a lockout: you are not punished for the provider's
  downtime.

- **No secrets in logs.** Events (`CaptchaRequired`, `AccountLockedOut`) carry the
  hashed key and the decision — never the submitted password or the captcha token.
  The provider secret travels in the POST body, never a URL, and never appears in
  an exception message.

- **Reset semantics.** A successful authentication clears the counter for that
  key. The global per-IP throttle is intentionally left to decay on its own TTL,
  so one user's success does not hand a co-tenant attacker a clean slate.

### Tradeoff: counter atomicity

The bundled `PsrCacheAttemptStore` is backed by PSR-16, which has **no atomic
increment**. Its `increment()` is a read-modify-write, so under concurrent
requests two processes can both read a sub-threshold count, both add one, and both
be let through — the effective threshold can be exceeded by roughly the number of
in-flight requests.

This is not hidden. `AttemptStore` is an interface **precisely** so a backend with
a native atomic counter (e.g. Redis `INCR`) can implement the same contract
race-free, with no change to the decision logic above it. **For production under
sustained or adversarial load, back the tracker with such a store.** The bundled
PSR-16 store is correct for development, low-traffic apps, and the test suite.

---

## The architecture is the point

Two layers, one seam, visible in the directory structure:

```
src/Core/            pure PHP, PSR interfaces only — the decision logic
src/Bridge/Laravel/  thin adapter: service provider + middleware
```

`Core/` imports nothing from `Bridge/` and nothing from `Illuminate\*`. The proof
is a CI job that **installs no framework at all** and runs the core suite against
it:

| Job      | PHP        | Framework                     |
| -------- | ---------- | ----------------------------- |
| `core`   | 8.3, 8.4   | none installed                |
| `bridge` | 8.3, 8.4   | Laravel 12 (Orchestra Testbench) |

Every push runs `composer audit`, `pint --test`, `phpstan analyse` (level 6,
larastan on the bridge, no baseline, no ignores) and both suites.

```bash
composer install
vendor/bin/pint --test
vendor/bin/phpstan analyse
vendor/bin/phpunit --testsuite=core     # passes with no framework
vendor/bin/phpunit --testsuite=bridge
composer audit
```

---

## Scope

**Out of scope, on purpose:**

- **MFA / TOTP.** It answers a different question ("is this the right person?")
  than abuse mitigation ("is this traffic automated?"), and Laravel Fortify
  already covers it. A separate concern belongs in a separate package.
- **A Symfony bridge — planned, not in this release.** The core is already
  framework-free, so a Symfony bundle is a thin addition later; shipping it
  separately keeps this release small.
- No UI, no routes, no captcha widget rendering, no IP reputation feeds.

---

## License

MIT — see [LICENSE](LICENSE).
