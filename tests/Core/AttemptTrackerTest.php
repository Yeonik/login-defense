<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core;

use LoginDefense\Core\AttemptTracker;
use LoginDefense\Tests\Core\Doubles\InMemoryAttemptStore;
use PHPUnit\Framework\TestCase;

/**
 * Proves the key strategy directly: the tracker is where "whose counter is this"
 * is decided, and the combined identifier+IP key is the security decision the
 * brief calls out first.
 */
final class AttemptTrackerTest extends TestCase
{
    public function test_the_same_identifier_from_two_ips_keeps_independent_counters(): void
    {
        $tracker = $this->tracker();

        // Six failures for one account from one IP...
        for ($i = 0; $i < 6; $i++) {
            $tracker->recordFailure('victim@example.test', '203.0.113.10');
        }

        // ...leave that same account, seen from a different IP, untouched. This is why
        // a username-only lock is wrong: it would let one attacker lock the real user
        // out of their own account from anywhere.
        self::assertSame(6, $tracker->failures('victim@example.test', '203.0.113.10'));
        self::assertSame(0, $tracker->failures('victim@example.test', '198.51.100.7'));
    }

    public function test_a_failure_increments_both_the_per_key_and_the_global_counter(): void
    {
        $tracker = $this->tracker(globalMax: 3);

        $tracker->recordFailure('alice@example.test', '203.0.113.10');
        $tracker->recordFailure('bob@example.test', '203.0.113.10');
        $tracker->recordFailure('carol@example.test', '203.0.113.10');

        // No single account reached its own threshold, yet the shared IP has tripped
        // the looser global throttle.
        self::assertSame(1, $tracker->failures('alice@example.test', '203.0.113.10'));
        self::assertTrue($tracker->globalThrottleExceeded('203.0.113.10'));
    }

    public function test_reset_clears_the_key_but_leaves_the_global_throttle_to_decay(): void
    {
        $tracker = $this->tracker(globalMax: 2);

        $tracker->recordFailure('alice@example.test', '203.0.113.10');
        $tracker->recordFailure('bob@example.test', '203.0.113.10');

        $tracker->reset('alice@example.test', '203.0.113.10');

        // Alice's own counter is cleared by her success...
        self::assertSame(0, $tracker->failures('alice@example.test', '203.0.113.10'));
        // ...but the IP-level throttle is not, so a success does not hand a co-tenant
        // attacker a clean slate.
        self::assertTrue($tracker->globalThrottleExceeded('203.0.113.10'));
    }

    public function test_the_key_is_hashed_and_hides_the_raw_identifier(): void
    {
        $tracker = $this->tracker();

        $key = $tracker->keyFor('alice@example.test', '203.0.113.10');

        self::assertStringNotContainsString('alice', $key);
        self::assertStringNotContainsString('203.0.113.10', $key);
    }

    public function test_the_key_is_case_insensitive_in_the_identifier(): void
    {
        $tracker = $this->tracker();

        // Casing must not fork a user's counter, or an attacker could sidestep the
        // limit by varying the capitalisation of the same username.
        self::assertSame(
            $tracker->keyFor('Alice@Example.test', '203.0.113.10'),
            $tracker->keyFor('alice@example.test', '203.0.113.10'),
        );
    }

    private function tracker(int $globalMax = 100): AttemptTracker
    {
        return new AttemptTracker(
            new InMemoryAttemptStore(),
            windowSeconds: 900,
            globalMaxAttempts: $globalMax,
            globalWindowSeconds: 900,
        );
    }
}
