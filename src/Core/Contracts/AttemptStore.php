<?php

declare(strict_types=1);

namespace LoginDefense\Core\Contracts;

/**
 * Persistence for failure counters, expressed as the smallest interface the
 * policy needs: read a count, increment it within a window, clear it.
 *
 * This is an interface on purpose. A PSR-16 cache has no atomic increment, so the
 * bundled PsrCacheAttemptStore carries a documented read-modify-write race. A
 * backend with an atomic counter (e.g. Redis INCR) can implement this contract
 * race-free without any change to the decision logic above it. For production
 * under load, prefer such a store — see the README's tradeoffs section.
 */
interface AttemptStore
{
    /**
     * Current failure count for the key. A key that was never written, or has
     * expired, reads as 0.
     */
    public function get(string $key): int;

    /**
     * Increment the counter and return the new value. The TTL bounds the sliding
     * window: counts decay on their own so a burst long ago does not haunt a key
     * forever.
     */
    public function increment(string $key, int $ttlSeconds): int;

    /**
     * Clear the counter for the key. Called on successful authentication.
     */
    public function reset(string $key): void;
}
