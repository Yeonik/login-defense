<?php

declare(strict_types=1);

namespace LoginDefense\Bridge\Laravel;

use Illuminate\Contracts\Cache\Repository as CacheRepository;
use Illuminate\Contracts\Events\Dispatcher as EventDispatcher;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Support\ServiceProvider;
use LoginDefense\Core\AttemptTracker;
use LoginDefense\Core\Contracts\CaptchaVerifier;
use LoginDefense\Core\EscalationPolicy;
use LoginDefense\Core\LoginGuard;
use LoginDefense\Core\PolicyConfig;
use LoginDefense\Core\Stores\PsrCacheAttemptStore;
use LoginDefense\Core\SystemClock;
use LoginDefense\Core\Verifiers\HcaptchaVerifier;
use LoginDefense\Core\Verifiers\NullVerifier;
use LoginDefense\Core\Verifiers\RecaptchaVerifier;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestFactoryInterface;
use Psr\Http\Message\StreamFactoryInterface;
use RuntimeException;
use Throwable;

/**
 * Wires the framework-free core onto Laravel's cache, events and config. This is
 * the whole of the "how Laravel supplies the plumbing" story — the core classes
 * above it never mention Illuminate.
 */
final class LoginDefenseServiceProvider extends ServiceProvider
{
    private const CONFIG_PATH = __DIR__ . '/../../../config/login-defense.php';

    public function register(): void
    {
        $this->mergeConfigFrom(self::CONFIG_PATH, 'login-defense');

        $this->app->singleton(LoginGuard::class, function (Application $app): LoginGuard {
            $settings = $this->settings($app);
            $global = is_array($settings['global_throttle'] ?? null) ? $settings['global_throttle'] : [];
            $captcha = is_array($settings['captcha'] ?? null) ? $settings['captcha'] : [];

            // Laravel's cache repository implements PSR-16, so it drops straight into
            // the core store with no adapter of its own.
            $store = new PsrCacheAttemptStore($app->make(CacheRepository::class));

            $tracker = new AttemptTracker(
                $store,
                (int) ($settings['window_seconds'] ?? 900),
                (int) ($global['max_attempts'] ?? 100),
                (int) ($global['window_seconds'] ?? 900),
            );

            return new LoginGuard(
                $tracker,
                new EscalationPolicy(),
                PolicyConfig::fromArray($settings),
                $this->makeVerifier($app, $captcha),
                new SystemClock(),
                new PsrEventDispatcher($app->make(EventDispatcher::class)),
                (bool) ($captcha['fail_open'] ?? false),
            );
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes(
                [self::CONFIG_PATH => $this->app->configPath('login-defense.php')],
                'login-defense-config',
            );
        }
    }

    /**
     * @return array<string, mixed>
     */
    private function settings(Application $app): array
    {
        $settings = $app->make('config')->get('login-defense');

        return is_array($settings) ? $settings : [];
    }

    /**
     * @param array<string, mixed> $captcha
     */
    private function makeVerifier(Application $app, array $captcha): CaptchaVerifier
    {
        $driver = is_string($captcha['driver'] ?? null) ? $captcha['driver'] : 'null';

        if ($driver === 'null') {
            return new NullVerifier();
        }

        $secret = is_string($captcha['secret'] ?? null) ? $captcha['secret'] : '';

        if ($secret === '') {
            // Fail loudly at wiring time rather than silently accepting every token:
            // a captcha driver with no secret would verify nothing.
            throw new RuntimeException(
                "login-defense: captcha driver [{$driver}] requires LOGIN_DEFENSE_CAPTCHA_SECRET to be set.",
            );
        }

        [$client, $requestFactory, $streamFactory] = $this->resolveHttp($app, $driver);

        return match ($driver) {
            'recaptcha' => new RecaptchaVerifier($client, $requestFactory, $streamFactory, $secret),
            'hcaptcha' => new HcaptchaVerifier($client, $requestFactory, $streamFactory, $secret),
            default => throw new RuntimeException("login-defense: unknown captcha driver [{$driver}]."),
        };
    }

    /**
     * The HTTP verifiers need a PSR-18 client and PSR-17 factories. The package
     * does not bundle a concrete implementation — the host application binds the
     * one it already uses — so resolve them from the container and, if they are
     * missing, say exactly what to provide.
     *
     * @return array{0: ClientInterface, 1: RequestFactoryInterface, 2: StreamFactoryInterface}
     */
    private function resolveHttp(Application $app, string $driver): array
    {
        try {
            return [
                $app->make(ClientInterface::class),
                $app->make(RequestFactoryInterface::class),
                $app->make(StreamFactoryInterface::class),
            ];
        } catch (Throwable $e) {
            throw new RuntimeException(
                "login-defense: captcha driver [{$driver}] needs a PSR-18 client and PSR-17 "
                . 'factories bound in the container (bind ClientInterface, RequestFactoryInterface '
                . 'and StreamFactoryInterface).',
                0,
                $e,
            );
        }
    }
}
