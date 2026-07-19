<?php

declare(strict_types=1);

namespace LoginDefense\Core\Verifiers;

/**
 * Google reCAPTCHA over the shared siteverify protocol.
 */
final class RecaptchaVerifier extends SiteVerifyVerifier
{
    protected function endpoint(): string
    {
        return 'https://www.google.com/recaptcha/api/siteverify';
    }
}
