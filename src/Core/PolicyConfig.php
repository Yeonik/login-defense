<?php

declare(strict_types=1);

namespace LoginDefense\Core;

use InvalidArgumentException;

/**
 * Immutable configuration for the escalation ladder.
 *
 * Kept as a typed value object rather than a loose array so the policy is a pure
 * function of (attempt count, config) and every threshold is validated once, at
 * the edge, instead of being re-checked deep inside the decision logic.
 */
final class PolicyConfig
{
    public function __construct(
        public readonly int $captchaAfter,
        public readonly int $lockoutAfter,
        public readonly int $lockoutBaseSeconds,
        public readonly int $lockoutMultiplier,
        public readonly int $lockoutMaxSeconds,
    ) {
        if ($captchaAfter < 1) {
            throw new InvalidArgumentException('captchaAfter must be at least 1.');
        }

        if ($lockoutAfter <= $captchaAfter) {
            // The captcha step has to sit strictly below the lockout step, otherwise
            // there is no graduated friction — the point of the whole package.
            throw new InvalidArgumentException('lockoutAfter must be greater than captchaAfter.');
        }

        if ($lockoutBaseSeconds < 1) {
            throw new InvalidArgumentException('lockoutBaseSeconds must be at least 1.');
        }

        if ($lockoutMultiplier < 1) {
            throw new InvalidArgumentException('lockoutMultiplier must be at least 1.');
        }

        if ($lockoutMaxSeconds < $lockoutBaseSeconds) {
            throw new InvalidArgumentException('lockoutMaxSeconds must be at least lockoutBaseSeconds.');
        }
    }

    /**
     * Build from the published config array. Casts are explicit so a string from
     * an env var never leaks into the arithmetic as a surprise.
     *
     * @param array<string, mixed> $config
     */
    public static function fromArray(array $config): self
    {
        $lockout = is_array($config['lockout'] ?? null) ? $config['lockout'] : [];

        return new self(
            captchaAfter: (int) ($config['captcha_after'] ?? 3),
            lockoutAfter: (int) ($config['lockout_after'] ?? 6),
            lockoutBaseSeconds: (int) ($lockout['base_seconds'] ?? 60),
            lockoutMultiplier: (int) ($lockout['multiplier'] ?? 2),
            lockoutMaxSeconds: (int) ($lockout['max_seconds'] ?? 3600),
        );
    }
}
