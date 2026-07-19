<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core;

use LoginDefense\Core\EscalationPolicy;
use LoginDefense\Core\Outcome;
use LoginDefense\Core\PolicyConfig;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The policy is a pure function, so it gets a pure decision-table test: no store,
 * no clock, no I/O. This is the ledger a reviewer reads to know exactly when each
 * step of the ladder engages.
 */
final class EscalationPolicyTest extends TestCase
{
    private function config(): PolicyConfig
    {
        return new PolicyConfig(
            captchaAfter: 3,
            lockoutAfter: 6,
            lockoutBaseSeconds: 60,
            lockoutMultiplier: 2,
            lockoutMaxSeconds: 3600,
        );
    }

    /**
     * @return iterable<string, array{int, Outcome}>
     */
    public static function decisionTable(): iterable
    {
        yield 'no failures allows' => [0, Outcome::Allow];
        yield 'below captcha allows' => [2, Outcome::Allow];
        yield 'at captcha threshold demands captcha' => [3, Outcome::RequireCaptcha];
        yield 'between thresholds demands captcha' => [5, Outcome::RequireCaptcha];
        yield 'at lockout threshold locks' => [6, Outcome::Lockout];
        yield 'above lockout threshold locks' => [9, Outcome::Lockout];
    }

    #[DataProvider('decisionTable')]
    public function test_it_maps_attempt_count_to_the_expected_outcome(int $attempts, Outcome $expected): void
    {
        $decision = (new EscalationPolicy())->decide($attempts, $this->config());

        self::assertSame($expected, $decision->outcome);
    }

    public function test_lockout_backoff_grows_then_caps(): void
    {
        $policy = new EscalationPolicy();
        $config = $this->config();

        // First lockout at the threshold uses the base window; each further failure
        // doubles it until it reaches the ceiling and stays there.
        self::assertSame(60, $policy->decide(6, $config)->retryAfter);
        self::assertSame(120, $policy->decide(7, $config)->retryAfter);
        self::assertSame(240, $policy->decide(8, $config)->retryAfter);
        self::assertSame(3600, $policy->decide(20, $config)->retryAfter, 'runaway backoff must be capped');
    }

    public function test_allow_and_captcha_decisions_carry_no_retry_after(): void
    {
        $policy = new EscalationPolicy();
        $config = $this->config();

        self::assertNull($policy->decide(0, $config)->retryAfter);
        self::assertNull($policy->decide(3, $config)->retryAfter);
    }
}
