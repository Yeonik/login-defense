<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core\Doubles;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * A clock that does not move unless told to. Proves the point of injecting time:
 * event timestamps are testable without a real wall clock and without sleeping.
 */
final class FrozenClock implements ClockInterface
{
    public function __construct(
        private DateTimeImmutable $now = new DateTimeImmutable('2026-01-01T00:00:00+00:00'),
    ) {
    }

    public function now(): DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(string $interval): void
    {
        $this->now = $this->now->modify($interval);
    }
}
