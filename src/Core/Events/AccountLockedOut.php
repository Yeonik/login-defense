<?php

declare(strict_types=1);

namespace LoginDefense\Core\Events;

use DateTimeImmutable;

/**
 * Dispatched (via PSR-14) when a key crosses the lockout threshold.
 *
 * Carries the hashed key, the attempt count, the retry-after window, and when it
 * happened — enough to alert and to explain a lockout after the fact. As with
 * every event here: no password, no captcha token, nothing that must not be
 * logged.
 */
final class AccountLockedOut
{
    public function __construct(
        public readonly string $key,
        public readonly int $attempts,
        public readonly int $retryAfter,
        public readonly DateTimeImmutable $occurredAt,
    ) {
    }
}
