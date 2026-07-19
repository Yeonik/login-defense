<?php

declare(strict_types=1);

namespace LoginDefense\Core;

use LoginDefense\Core\Contracts\CaptchaVerifier;
use LoginDefense\Core\Events\AccountLockedOut;
use LoginDefense\Core\Events\CaptchaRequired;
use LoginDefense\Core\Exceptions\CaptchaVerificationException;
use Psr\Clock\ClockInterface;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * The one object an application talks to. It reads the failure count, asks the
 * pure policy for a decision, resolves a presented captcha, and emits events —
 * the seam between "how many failures" and "what should happen next".
 *
 * Deliberately framework-free: everything it needs arrives as a PSR interface, so
 * the exact same object runs under Laravel, Symfony, a queue worker, or a plain
 * PHPUnit test with no framework installed at all.
 */
final class LoginGuard
{
    public function __construct(
        private readonly AttemptTracker $tracker,
        private readonly EscalationPolicy $policy,
        private readonly PolicyConfig $config,
        private readonly CaptchaVerifier $verifier,
        private readonly ClockInterface $clock,
        private readonly EventDispatcherInterface $events,
        private readonly bool $captchaFailOpen = false,
    ) {
    }

    /**
     * Decide what to do with a login attempt *before* credentials are checked.
     *
     * The decision is driven purely by the attempt count on the key, never by
     * whether the account exists — same code path, same timing, whether or not a
     * user record is ever looked up. That is what keeps the response from leaking
     * account existence to an attacker.
     */
    public function check(string $identifier, string $ip, ?string $captchaToken = null): Decision
    {
        $attempts = $this->tracker->failures($identifier, $ip);
        $decision = $this->policy->decide($attempts, $this->config);

        // Distributed attempts keep every per-key counter low. When a single IP has
        // been noisy across many usernames, raise friction to a captcha even for a
        // key that is individually clean — but never to a lockout, because an
        // IP-only lock would take out a whole NAT'd office.
        if ($decision->isAllowed() && $this->tracker->globalThrottleExceeded($ip)) {
            $decision = Decision::requireCaptcha();
        }

        $key = $this->tracker->keyFor($identifier, $ip);

        if ($decision->isLockedOut()) {
            $this->events->dispatch(
                new AccountLockedOut($key, $attempts, (int) $decision->retryAfter, $this->clock->now()),
            );

            return $decision;
        }

        if ($decision->requiresCaptcha()) {
            if ($captchaToken !== null && $this->captchaPasses($captchaToken, $ip)) {
                // A valid captcha clears the challenge for this attempt. The failure
                // counter is untouched: solving a captcha proves a human is present,
                // it does not forgive the failures that raised the challenge.
                return Decision::allow();
            }

            $this->events->dispatch(new CaptchaRequired($key, $attempts, $this->clock->now()));

            return Decision::requireCaptcha();
        }

        return $decision;
    }

    /**
     * Record a failed authentication. Call this after credentials are rejected.
     */
    public function recordFailure(string $identifier, string $ip): void
    {
        $this->tracker->recordFailure($identifier, $ip);
    }

    /**
     * Record a successful authentication: clears the per-key counter. The global
     * per-IP throttle is left to decay on its own TTL and is not reset here.
     */
    public function recordSuccess(string $identifier, string $ip): void
    {
        $this->tracker->reset($identifier, $ip);
    }

    private function captchaPasses(string $token, string $ip): bool
    {
        try {
            return $this->verifier->verify($token, $ip);
        } catch (CaptchaVerificationException) {
            // Provider outage. Default is fail-closed: a captcha we could not verify
            // is treated as unsolved, so the challenge stands. Either way the caller
            // still only sees RequireCaptcha, never a lockout — a user is never
            // locked out because the captcha provider timed out.
            return $this->captchaFailOpen;
        }
    }
}
