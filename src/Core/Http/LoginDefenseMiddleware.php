<?php

declare(strict_types=1);

namespace LoginDefense\Core\Http;

use LoginDefense\Core\LoginGuard;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * A PSR-15 gate in front of a login route. It runs the guard's check *before* the
 * handler and short-circuits when the decision says so:
 *   - Lockout       -> 429 with a Retry-After header
 *   - RequireCaptcha (unsolved) -> 422
 * Otherwise the request passes through untouched.
 *
 * It is a pre-filter, not a bookkeeper: recording failures and successes stays
 * with the application's own authentication code, which alone knows whether the
 * credentials were correct. The middleware enforces the consequences; the app
 * reports the outcomes via LoginGuard::recordFailure()/recordSuccess().
 */
final class LoginDefenseMiddleware implements MiddlewareInterface
{
    public function __construct(
        private readonly LoginGuard $guard,
        private readonly CredentialsExtractor $extractor,
        private readonly ResponseFactoryInterface $responseFactory,
    ) {
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $identifier = $this->extractor->identifier($request);
        $ip = $this->extractor->ip($request);

        // Nothing to key on (no identifier, or no trustworthy client IP). Do not
        // guess or fabricate a key — pass the request through and let the handler
        // deal with the missing field. Blocking here would be a signal in itself.
        if ($identifier === null || $ip === null) {
            return $handler->handle($request);
        }

        $decision = $this->guard->check($identifier, $ip, $this->extractor->captchaToken($request));

        if ($decision->isLockedOut()) {
            return $this->responseFactory
                ->createResponse(429)
                ->withHeader('Retry-After', (string) $decision->retryAfter);
        }

        if ($decision->requiresCaptcha()) {
            // Same status regardless of whether the account exists — the block is a
            // function of attempt count, not of any user lookup, so it reveals nothing.
            return $this->responseFactory->createResponse(422);
        }

        return $handler->handle($request);
    }
}
