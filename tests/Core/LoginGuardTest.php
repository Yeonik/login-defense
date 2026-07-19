<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core;

use LoginDefense\Core\AttemptTracker;
use LoginDefense\Core\Contracts\CaptchaVerifier;
use LoginDefense\Core\EscalationPolicy;
use LoginDefense\Core\Events\AccountLockedOut;
use LoginDefense\Core\Events\CaptchaRequired;
use LoginDefense\Core\LoginGuard;
use LoginDefense\Core\PolicyConfig;
use LoginDefense\Tests\Core\Doubles\FrozenClock;
use LoginDefense\Tests\Core\Doubles\InMemoryAttemptStore;
use LoginDefense\Tests\Core\Doubles\ProgrammableCaptchaVerifier;
use LoginDefense\Tests\Core\Doubles\RecordingEventDispatcher;
use PHPUnit\Framework\TestCase;

/**
 * The guard wired against fakes only — no framework, no clock, no network. Every
 * property the brief promises is asserted here as an outcome, never as an attack.
 */
final class LoginGuardTest extends TestCase
{
    private const IDENTIFIER = 'alice@example.test';
    private const IP = '203.0.113.10';

    private InMemoryAttemptStore $store;

    private RecordingEventDispatcher $events;

    protected function setUp(): void
    {
        $this->store = new InMemoryAttemptStore();
        $this->events = new RecordingEventDispatcher();
    }

    public function test_below_the_first_threshold_it_allows_without_demanding_a_captcha(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::accepting());
        $this->fail_n_times($guard, 2);

        $decision = $guard->check(self::IDENTIFIER, self::IP);

        self::assertTrue($decision->isAllowed());
        self::assertSame([], $this->events->events);
    }

    public function test_at_the_captcha_threshold_it_requires_a_captcha_and_emits_an_event(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::rejecting());
        $this->fail_n_times($guard, 3);

        $decision = $guard->check(self::IDENTIFIER, self::IP);

        self::assertTrue($decision->requiresCaptcha());
        self::assertTrue($this->events->has(CaptchaRequired::class));
    }

    public function test_a_valid_captcha_token_clears_the_challenge(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::accepting());
        $this->fail_n_times($guard, 3);

        $decision = $guard->check(self::IDENTIFIER, self::IP, 'a-valid-token');

        self::assertTrue($decision->isAllowed());
    }

    public function test_an_invalid_captcha_token_does_not_clear_the_challenge(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::rejecting());
        $this->fail_n_times($guard, 3);

        $decision = $guard->check(self::IDENTIFIER, self::IP, 'a-bogus-token');

        self::assertTrue($decision->requiresCaptcha());
    }

    public function test_at_the_lockout_threshold_it_locks_with_a_retry_after_and_emits_an_event(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::accepting());
        $this->fail_n_times($guard, 6);

        $decision = $guard->check(self::IDENTIFIER, self::IP);

        self::assertTrue($decision->isLockedOut());
        self::assertSame(60, $decision->retryAfter);
        self::assertTrue($this->events->has(AccountLockedOut::class));
    }

    public function test_retry_after_grows_on_repeated_failures(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::accepting());

        $this->fail_n_times($guard, 6);
        self::assertSame(60, $guard->check(self::IDENTIFIER, self::IP)->retryAfter);

        $this->fail_n_times($guard, 1);
        self::assertSame(120, $guard->check(self::IDENTIFIER, self::IP)->retryAfter);
    }

    public function test_successful_authentication_resets_the_counter(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::accepting());
        $this->fail_n_times($guard, 6);
        self::assertTrue($guard->check(self::IDENTIFIER, self::IP)->isLockedOut());

        $guard->recordSuccess(self::IDENTIFIER, self::IP);

        self::assertTrue($guard->check(self::IDENTIFIER, self::IP)->isAllowed());
    }

    public function test_a_provider_outage_is_fail_closed_by_default(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::unreachable(), failOpen: false);
        $this->fail_n_times($guard, 3);

        $decision = $guard->check(self::IDENTIFIER, self::IP, 'any-token');

        // The challenge stands when the provider cannot be reached...
        self::assertTrue($decision->requiresCaptcha());
        // ...but the outage never escalates the user into a lockout.
        self::assertFalse($decision->isLockedOut());
    }

    public function test_a_provider_outage_can_be_configured_fail_open(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::unreachable(), failOpen: true);
        $this->fail_n_times($guard, 3);

        $decision = $guard->check(self::IDENTIFIER, self::IP, 'any-token');

        self::assertTrue($decision->isAllowed());
    }

    public function test_a_noisy_ip_raises_a_captcha_for_an_otherwise_clean_key(): void
    {
        // Global throttle of 5: five failures spread across five different accounts
        // on one IP keeps every per-key counter at 1 (below the captcha threshold),
        // yet a sixth, fresh account from that IP is met with a captcha.
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::rejecting(), globalMax: 5);

        for ($i = 0; $i < 5; $i++) {
            $guard->recordFailure("user{$i}@example.test", self::IP);
        }

        $decision = $guard->check('newcomer@example.test', self::IP);

        self::assertTrue($decision->requiresCaptcha());
        // The global throttle raises friction but must never lock a whole IP out.
        self::assertFalse($decision->isLockedOut());
    }

    public function test_a_clean_key_from_a_quiet_ip_is_still_allowed(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::rejecting(), globalMax: 5);

        for ($i = 0; $i < 5; $i++) {
            $guard->recordFailure("user{$i}@example.test", self::IP);
        }

        $decision = $guard->check('newcomer@example.test', '198.51.100.7');

        self::assertTrue($decision->isAllowed());
    }

    public function test_emitted_events_never_carry_the_raw_identifier_or_the_token(): void
    {
        $guard = $this->makeGuard(ProgrammableCaptchaVerifier::rejecting());
        $this->fail_n_times($guard, 3);

        $guard->check(self::IDENTIFIER, self::IP, 'super-secret-token');

        $event = $this->events->events[0];
        self::assertInstanceOf(CaptchaRequired::class, $event);
        // The event key is a hash: neither the email nor the submitted token appears.
        self::assertStringNotContainsString('alice', $event->key);
        self::assertStringNotContainsString('super-secret-token', $event->key);
    }

    private function fail_n_times(LoginGuard $guard, int $times): void
    {
        for ($i = 0; $i < $times; $i++) {
            $guard->recordFailure(self::IDENTIFIER, self::IP);
        }
    }

    private function makeGuard(
        CaptchaVerifier $verifier,
        bool $failOpen = false,
        int $globalMax = 100,
    ): LoginGuard {
        $config = new PolicyConfig(
            captchaAfter: 3,
            lockoutAfter: 6,
            lockoutBaseSeconds: 60,
            lockoutMultiplier: 2,
            lockoutMaxSeconds: 3600,
        );

        $tracker = new AttemptTracker(
            $this->store,
            windowSeconds: 900,
            globalMaxAttempts: $globalMax,
            globalWindowSeconds: 900,
        );

        return new LoginGuard(
            $tracker,
            new EscalationPolicy(),
            $config,
            $verifier,
            new FrozenClock(),
            $this->events,
            $failOpen,
        );
    }
}
