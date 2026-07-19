<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Bridge;

use Illuminate\Support\ServiceProvider;
use LoginDefense\Bridge\Laravel\LoginDefenseServiceProvider;
use LoginDefense\Core\LoginGuard;

final class ServiceProviderTest extends BridgeTestCase
{
    public function test_it_merges_the_package_config(): void
    {
        self::assertSame(3, config('login-defense.captcha_after'));
        self::assertSame(6, config('login-defense.lockout_after'));
        self::assertSame('null', config('login-defense.captcha.driver'));
    }

    public function test_it_binds_a_ready_to_use_login_guard(): void
    {
        // The core object resolves fully wired from Laravel's container: cache-backed
        // store, PSR-14 events adapter, system clock — all supplied by the bridge.
        self::assertInstanceOf(LoginGuard::class, $this->app->make(LoginGuard::class));
    }

    public function test_the_login_guard_is_a_singleton(): void
    {
        self::assertSame(
            $this->app->make(LoginGuard::class),
            $this->app->make(LoginGuard::class),
        );
    }

    public function test_the_config_file_is_publishable(): void
    {
        $paths = ServiceProvider::pathsToPublish(
            LoginDefenseServiceProvider::class,
            'login-defense-config',
        );

        self::assertNotEmpty($paths);
    }
}
