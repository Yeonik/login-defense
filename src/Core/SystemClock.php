<?php

declare(strict_types=1);

namespace LoginDefense\Core;

use DateTimeImmutable;
use Psr\Clock\ClockInterface;

/**
 * The one place allowed to read the wall clock. Everything else takes time as an
 * injected PSR clock, so tests can freeze or advance it without sleeping.
 */
final class SystemClock implements ClockInterface
{
    public function now(): DateTimeImmutable
    {
        return new DateTimeImmutable();
    }
}
