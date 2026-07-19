<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core\Doubles;

use LoginDefense\Core\Contracts\AttemptStore;

/**
 * A deterministic in-memory store for the core suite. TTLs are accepted and
 * ignored: expiry is the store backend's concern, and every escalation property
 * we care about is provable without simulating the clock. Keeping it trivial
 * keeps the tests honest about what they exercise.
 */
final class InMemoryAttemptStore implements AttemptStore
{
    /**
     * @var array<string, int>
     */
    private array $counts = [];

    public function get(string $key): int
    {
        return $this->counts[$key] ?? 0;
    }

    public function increment(string $key, int $ttlSeconds): int
    {
        return $this->counts[$key] = $this->get($key) + 1;
    }

    public function reset(string $key): void
    {
        unset($this->counts[$key]);
    }
}
