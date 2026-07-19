<?php

declare(strict_types=1);

namespace LoginDefense\Core\Contracts;

use LoginDefense\Core\Exceptions\CaptchaVerificationException;

/**
 * One interface, many providers. The decision logic never knows which vendor is
 * behind the token — swapping reCAPTCHA for hCaptcha, or stubbing it in a test,
 * is a binding change, not a code change.
 */
interface CaptchaVerifier
{
    /**
     * Return true when the token is valid, false when it is not.
     *
     * A false result means "this token did not check out" — an ordinary,
     * expected answer. It must NOT be used to signal that the provider was
     * unreachable: a transport/provider failure throws instead, so the caller
     * can apply its own fail-open / fail-closed policy rather than mistaking an
     * outage for a bad token.
     *
     * @throws CaptchaVerificationException when the provider cannot be reached.
     */
    public function verify(string $token, ?string $ip = null): bool;
}
