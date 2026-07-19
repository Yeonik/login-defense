<?php

declare(strict_types=1);

namespace LoginDefense\Core\Verifiers;

use LoginDefense\Core\Contracts\CaptchaVerifier;

/**
 * Accepts every token. For local development and the test suite only — it is the
 * default `null` driver so a fresh install runs without provider credentials.
 * Never select this driver in production: it disables the captcha step entirely.
 */
final class NullVerifier implements CaptchaVerifier
{
    public function verify(string $token, ?string $ip = null): bool
    {
        return true;
    }
}
