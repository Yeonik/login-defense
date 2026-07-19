<?php

declare(strict_types=1);

namespace LoginDefense\Core;

use InvalidArgumentException;

/**
 * The outcome of an escalation check: Allow, RequireCaptcha, or Lockout.
 *
 * A Lockout carries `retryAfter` (seconds) so the caller can answer with a
 * precise Retry-After without consulting a clock. The value is immutable — a
 * decision is a fact about a moment, not a mutable state.
 */
final class Decision
{
    private function __construct(
        public readonly Outcome $outcome,
        public readonly ?int $retryAfter = null,
    ) {
    }

    public static function allow(): self
    {
        return new self(Outcome::Allow);
    }

    public static function requireCaptcha(): self
    {
        return new self(Outcome::RequireCaptcha);
    }

    public static function lockout(int $retryAfter): self
    {
        if ($retryAfter < 1) {
            // A lockout with no wait is not a lockout; reject it at construction so a
            // config or arithmetic bug can never emit a zero-second "lock".
            throw new InvalidArgumentException('Lockout retryAfter must be at least 1 second.');
        }

        return new self(Outcome::Lockout, $retryAfter);
    }

    public function isAllowed(): bool
    {
        return $this->outcome === Outcome::Allow;
    }

    public function requiresCaptcha(): bool
    {
        return $this->outcome === Outcome::RequireCaptcha;
    }

    public function isLockedOut(): bool
    {
        return $this->outcome === Outcome::Lockout;
    }
}
