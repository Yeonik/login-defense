<?php

declare(strict_types=1);

namespace LoginDefense\Core\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Pulls the three things the guard keys on out of a PSR-7 request. Kept behind an
 * interface because "which field holds the username" and "how do we learn the
 * client IP behind a proxy" are application decisions the package must not guess.
 */
interface CredentialsExtractor
{
    public function identifier(ServerRequestInterface $request): ?string;

    public function ip(ServerRequestInterface $request): ?string;

    public function captchaToken(ServerRequestInterface $request): ?string;
}
