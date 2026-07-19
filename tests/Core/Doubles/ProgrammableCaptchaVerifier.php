<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core\Doubles;

use LoginDefense\Core\Contracts\CaptchaVerifier;
use LoginDefense\Core\Exceptions\CaptchaVerificationException;

/**
 * A captcha verifier whose answer the test dictates: pass, fail, or simulate a
 * provider outage by throwing. Lets the guard's fail-open / fail-closed handling
 * be exercised without any network.
 */
final class ProgrammableCaptchaVerifier implements CaptchaVerifier
{
    private function __construct(
        private readonly bool $result,
        private readonly bool $throws,
    ) {
    }

    public static function accepting(): self
    {
        return new self(true, false);
    }

    public static function rejecting(): self
    {
        return new self(false, false);
    }

    public static function unreachable(): self
    {
        return new self(false, true);
    }

    public function verify(string $token, ?string $ip = null): bool
    {
        if ($this->throws) {
            throw new CaptchaVerificationException('simulated provider outage');
        }

        return $this->result;
    }
}
