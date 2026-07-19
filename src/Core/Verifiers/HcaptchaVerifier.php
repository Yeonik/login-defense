<?php

declare(strict_types=1);

namespace LoginDefense\Core\Verifiers;

/**
 * hCaptcha over the shared siteverify protocol. Drop-in alternative to reCAPTCHA:
 * same request shape, same success field, different endpoint.
 */
final class HcaptchaVerifier extends SiteVerifyVerifier
{
    protected function endpoint(): string
    {
        return 'https://api.hcaptcha.com/siteverify';
    }
}
