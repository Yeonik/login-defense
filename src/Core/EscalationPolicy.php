<?php

declare(strict_types=1);

namespace LoginDefense\Core;

/**
 * The escalation ladder as a pure function: given how many failures a key has
 * accumulated and the config, return the Decision. No I/O, no clock, no state —
 * which is exactly why the lockout backoff is testable without ever sleeping.
 */
final class EscalationPolicy
{
    public function decide(int $attempts, PolicyConfig $config): Decision
    {
        if ($attempts < $config->captchaAfter) {
            return Decision::allow();
        }

        if ($attempts < $config->lockoutAfter) {
            return Decision::requireCaptcha();
        }

        return Decision::lockout($this->retryAfter($attempts, $config));
    }

    /**
     * Exponential backoff, capped. Computed by repeated multiplication with an
     * early break at the ceiling: this both avoids integer overflow on a large
     * attempt count and guarantees the result never exceeds lockoutMaxSeconds.
     */
    private function retryAfter(int $attempts, PolicyConfig $config): int
    {
        $seconds = $config->lockoutBaseSeconds;
        $extra = $attempts - $config->lockoutAfter;

        for ($i = 0; $i < $extra; $i++) {
            $seconds *= $config->lockoutMultiplier;

            if ($seconds >= $config->lockoutMaxSeconds) {
                return $config->lockoutMaxSeconds;
            }
        }

        return $seconds;
    }
}
