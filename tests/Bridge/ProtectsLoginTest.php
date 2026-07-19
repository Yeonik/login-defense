<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Bridge;

use Illuminate\Routing\Router;
use LoginDefense\Bridge\Laravel\ProtectsLogin;
use LoginDefense\Core\LoginGuard;

/**
 * The Laravel middleware end to end: a real route, real container-resolved guard,
 * real cache. Drives the escalation ladder through HTTP status codes.
 */
final class ProtectsLoginTest extends BridgeTestCase
{
    private const IDENTIFIER = 'user@example.test';
    private const IP = '127.0.0.1';

    /**
     * @param Router $router
     */
    protected function defineRoutes($router): void
    {
        $router->post('login', fn () => 'ok')->middleware(ProtectsLogin::class);
    }

    public function test_a_login_below_any_threshold_passes_through(): void
    {
        $this->post('login', ['email' => self::IDENTIFIER])
            ->assertOk()
            ->assertSee('ok');
    }

    public function test_it_answers_the_captcha_threshold_with_422(): void
    {
        $this->seedFailures(3);

        $this->post('login', ['email' => self::IDENTIFIER])->assertStatus(422);
    }

    public function test_a_valid_captcha_token_clears_the_challenge(): void
    {
        // The default 'null' driver accepts any token, so a present token clears the
        // captcha step and the request proceeds.
        $this->seedFailures(3);

        $this->post('login', ['email' => self::IDENTIFIER, 'captcha_token' => 'anything'])
            ->assertOk();
    }

    public function test_it_answers_the_lockout_threshold_with_429_and_a_retry_after_header(): void
    {
        $this->seedFailures(6);

        $this->post('login', ['email' => self::IDENTIFIER])
            ->assertStatus(429)
            ->assertHeader('Retry-After', '60');
    }

    public function test_disabling_the_package_restores_default_behaviour(): void
    {
        config()->set('login-defense.enabled', false);
        $this->seedFailures(6);

        // Even past the lockout threshold, a disabled package is a pure pass-through.
        $this->post('login', ['email' => self::IDENTIFIER])->assertOk();
    }

    private function seedFailures(int $times): void
    {
        $guard = $this->app->make(LoginGuard::class);

        for ($i = 0; $i < $times; $i++) {
            $guard->recordFailure(self::IDENTIFIER, self::IP);
        }
    }
}
