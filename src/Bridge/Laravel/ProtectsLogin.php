<?php

declare(strict_types=1);

namespace LoginDefense\Bridge\Laravel;

use Closure;
use Illuminate\Contracts\Config\Repository as ConfigRepository;
use Illuminate\Http\Request;
use LoginDefense\Core\LoginGuard;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Exception\HttpException;

/**
 * The Laravel-facing gate. A thin adapter: it reads identifier / IP / captcha
 * token off the Laravel request and hands the decision to the core LoginGuard,
 * exactly as the PSR-15 middleware does for a framework-agnostic stack. All the
 * escalation logic lives in the core; this class only translates HTTP.
 */
final class ProtectsLogin
{
    /**
     * Fields checked, in order, for the login identifier.
     *
     * @var list<string>
     */
    private const IDENTIFIER_FIELDS = ['email', 'username'];

    public function __construct(
        private readonly LoginGuard $guard,
        private readonly ConfigRepository $config,
    ) {
    }

    /**
     * @param Closure(Request): Response $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        // Master switch off: become a pass-through so Laravel's default login
        // behaviour is exactly unchanged. Nothing is read, nothing is blocked.
        if ($this->config->get('login-defense.enabled', true) !== true) {
            return $next($request);
        }

        $identifier = $this->identifier($request);
        $ip = $request->ip();

        // Nothing to key on: let the request through to the app's own validation
        // rather than emitting a block that would itself be a signal.
        if ($identifier === null || $ip === null) {
            return $next($request);
        }

        $token = $request->input('captcha_token');
        $decision = $this->guard->check($identifier, $ip, is_string($token) ? $token : null);

        if ($decision->isLockedOut()) {
            throw new HttpException(
                429,
                'Too Many Requests',
                null,
                ['Retry-After' => (string) $decision->retryAfter],
            );
        }

        if ($decision->requiresCaptcha()) {
            // 422 with no hint about account existence: the block is a function of
            // attempt count, never of a user lookup.
            throw new HttpException(422, 'Captcha required');
        }

        return $next($request);
    }

    private function identifier(Request $request): ?string
    {
        foreach (self::IDENTIFIER_FIELDS as $field) {
            $value = $request->input($field);

            if (is_string($value) && $value !== '') {
                return $value;
            }
        }

        return null;
    }
}
