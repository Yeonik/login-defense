<?php

declare(strict_types=1);

namespace LoginDefense\Core\Exceptions;

use RuntimeException;

/**
 * Signals that the captcha provider could not be reached — an outage, not a bad
 * token. The message must never carry the submitted token or the provider
 * secret: an exception often lands straight in a log, and that is exactly where
 * secrets must not appear.
 */
final class CaptchaVerificationException extends RuntimeException
{
}
