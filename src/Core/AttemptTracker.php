<?php

declare(strict_types=1);

namespace LoginDefense\Core;

use LoginDefense\Core\Contracts\AttemptStore;

/**
 * Owns the key strategy: how a failure becomes a counter, and which counters a
 * given login touches. The policy decides *what* to do with a count; the tracker
 * decides *whose* count it is.
 */
final class AttemptTracker
{
    private const KEY_PREFIX = 'login-defense:key:';
    private const GLOBAL_PREFIX = 'login-defense:ip:';

    public function __construct(
        private readonly AttemptStore $store,
        private readonly int $windowSeconds,
        private readonly int $globalMaxAttempts,
        private readonly int $globalWindowSeconds,
    ) {
    }

    /**
     * Failures recorded against the combined identifier+IP key.
     */
    public function failures(string $identifier, string $ip): int
    {
        return $this->store->get($this->keyFor($identifier, $ip));
    }

    /**
     * Record one failed attempt. Two counters move: the combined key (which
     * drives escalation for this specific account-from-this-location) and the
     * looser global per-IP counter (which drives the anti-distribution throttle).
     */
    public function recordFailure(string $identifier, string $ip): void
    {
        $this->store->increment($this->globalKeyFor($ip), $this->globalWindowSeconds);
        $this->store->increment($this->keyFor($identifier, $ip), $this->windowSeconds);
    }

    /**
     * Clear the combined-key counter on successful authentication. The global
     * per-IP counter is intentionally left to decay on its own TTL: a legitimate
     * login should not hand an attacker sharing that IP a clean slate.
     */
    public function reset(string $identifier, string $ip): void
    {
        $this->store->reset($this->keyFor($identifier, $ip));
    }

    /**
     * True once an IP has been noisy enough to warrant extra friction. Read-only:
     * the throttle raises a captcha, never a lockout, so it needs no lock state.
     */
    public function globalThrottleExceeded(string $ip): bool
    {
        return $this->store->get($this->globalKeyFor($ip)) >= $this->globalMaxAttempts;
    }

    /**
     * The combined identifier+IP key, hashed.
     *
     * Combined on purpose: an IP-only lock takes out a whole NAT'd office and does
     * nothing against distributed attempts, while a username-only lock hands an
     * attacker a denial-of-service against the victim's own account. Keying on
     * both narrows a lock to "this account, from this source".
     *
     * Hashed on purpose: the identifier is often an email (PII). Hashing keeps raw
     * user input out of cache keys — and therefore out of any store's logs — and
     * sidesteps PSR-16's reserved-character rules in one move. The identifier is
     * lower-cased first so casing differences do not fork a user's counter.
     */
    public function keyFor(string $identifier, string $ip): string
    {
        return self::KEY_PREFIX . hash('sha256', strtolower($identifier) . '|' . $ip);
    }

    private function globalKeyFor(string $ip): string
    {
        return self::GLOBAL_PREFIX . hash('sha256', $ip);
    }
}
