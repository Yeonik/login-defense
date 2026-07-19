<?php

declare(strict_types=1);

namespace LoginDefense\Core\Http;

use Psr\Http\Message\ServerRequestInterface;

/**
 * Default extractor for a classic form POST: identifier and captcha token from
 * the parsed body, client IP from a server param.
 *
 * The IP is read from REMOTE_ADDR only — the direct peer, which cannot be spoofed
 * by a request header. Forwarded-for headers are deliberately ignored here: an
 * attacker controls those, and trusting them would let one attacker rotate the
 * throttle key at will. An application behind a trusted proxy should supply its
 * own extractor that consults its proxy configuration.
 */
final class FormCredentialsExtractor implements CredentialsExtractor
{
    /**
     * @param list<string> $identifierFields
     */
    public function __construct(
        private readonly array $identifierFields = ['email', 'username'],
        private readonly string $captchaField = 'captcha_token',
    ) {
    }

    public function identifier(ServerRequestInterface $request): ?string
    {
        $body = $request->getParsedBody();

        if (!is_array($body)) {
            return null;
        }

        foreach ($this->identifierFields as $field) {
            $value = $body[$field] ?? null;

            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }

    public function ip(ServerRequestInterface $request): ?string
    {
        $remote = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($remote) && $remote !== '' ? $remote : null;
    }

    public function captchaToken(ServerRequestInterface $request): ?string
    {
        $body = $request->getParsedBody();

        if (!is_array($body)) {
            return null;
        }

        $value = $body[$this->captchaField] ?? null;

        return is_string($value) && $value !== '' ? $value : null;
    }
}
