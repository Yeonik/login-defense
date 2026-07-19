<?php

declare(strict_types=1);

namespace LoginDefense\Core\Verifiers;

use LoginDefense\Core\Contracts\CaptchaVerifier;
use LoginDefense\Core\Exceptions\CaptchaVerificationException;
use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;

/**
 * Shared implementation of the "siteverify" protocol that reCAPTCHA and hCaptcha
 * both speak: POST { secret, response, remoteip } and read { "success": bool }.
 * The two providers differ only in their endpoint, so that is the one thing
 * subclasses supply.
 *
 * HTTP is injected as PSR-18 (client) plus PSR-17 (request + stream factories),
 * never instantiated here — the verifier stays testable against a stubbed client
 * and free of any concrete HTTP library.
 */
abstract class SiteVerifyVerifier implements CaptchaVerifier
{
    public function __construct(
        private readonly ClientInterface $httpClient,
        private readonly RequestFactoryInterface $requestFactory,
        private readonly StreamFactoryInterface $streamFactory,
        private readonly string $secret,
    ) {
    }

    /**
     * The provider's verification endpoint.
     */
    abstract protected function endpoint(): string;

    public function verify(string $token, ?string $ip = null): bool
    {
        $fields = [
            'secret' => $this->secret,
            'response' => $token,
        ];

        if ($ip !== null) {
            $fields['remoteip'] = $ip;
        }

        // Secret travels in the POST body, not the query string: a URL can be logged
        // by proxies or leak via Referer, a body is far less likely to.
        $body = http_build_query($fields);

        $request = $this->requestFactory
            ->createRequest('POST', $this->endpoint())
            ->withHeader('Content-Type', 'application/x-www-form-urlencoded')
            ->withBody($this->streamFactory->createStream($body));

        try {
            $response = $this->httpClient->sendRequest($request);
        } catch (ClientExceptionInterface $e) {
            // Transport failure = provider outage. Re-thrown so the caller decides
            // fail-open vs fail-closed. The message carries neither the token nor the
            // secret — an exception is one keystroke from a log line.
            throw new CaptchaVerificationException('Captcha provider could not be reached.', 0, $e);
        }

        $decoded = json_decode((string) $response->getBody(), true);

        // Anything that is not an explicit success is a failure. A malformed or
        // partial body counts as "not verified", never as a pass.
        return is_array($decoded) && ($decoded['success'] ?? false) === true;
    }
}
