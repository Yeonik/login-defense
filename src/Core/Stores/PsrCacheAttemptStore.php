<?php

declare(strict_types=1);

namespace LoginDefense\Core\Stores;

use LoginDefense\Core\Contracts\AttemptStore;
use Psr\SimpleCache\CacheInterface;

/**
 * PSR-16 backed counter store. The default that works everywhere a PSR-16 cache
 * is available.
 *
 * ATOMICITY — read this before running it under real load. PSR-16 offers no
 * atomic increment, so `increment()` below is a read-modify-write: it reads the
 * current count, adds one, and writes it back. Under concurrent requests two
 * processes can read the same sub-threshold value, both add one, and both write
 * the same result — so several in-flight requests can slip past a threshold that,
 * counted atomically, they should have tripped. The effective threshold can be
 * exceeded by roughly the number of simultaneous attempts.
 *
 * This is not hidden by design: AttemptStore is an interface precisely so that a
 * backend with a native atomic counter (e.g. Redis INCR) can implement the same
 * contract without the race. For production under sustained or adversarial load,
 * back the tracker with such a store rather than this one. The bundled store is
 * correct for development, low-traffic apps, and the test suite.
 */
final class PsrCacheAttemptStore implements AttemptStore
{
    public function __construct(
        private readonly CacheInterface $cache,
    ) {
    }

    public function get(string $key): int
    {
        $value = $this->cache->get($key, 0);

        return is_int($value) ? $value : 0;
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        // Non-atomic read-modify-write. See the class-level note on the race this
        // carries and when to swap in an atomic store instead.
        $next = $this->get($key) + 1;
        $this->cache->set($key, $next, $ttlSeconds);

        return $next;
    }

    public function reset(string $key): void
    {
        $this->cache->delete($key);
    }
}
