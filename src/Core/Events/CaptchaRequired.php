<?php

declare(strict_types=1);

namespace LoginDefense\Core\Events;

use DateTimeImmutable;

/**
 * Dispatched (via PSR-14) when a key crosses the captcha threshold.
 *
 * Carries the hashed key, the attempt count, and when it happened — the facts a
 * SIEM needs to alert on. It deliberately does NOT carry the submitted password
 * or the captcha token: events land in logs, and secrets must never reach them.
 */
final class CaptchaRequired
{
    public function __construct(
        public readonly string $key,
        public readonly int $attempts,
        public readonly DateTimeImmutable $occurredAt,
    ) {
    }
}
