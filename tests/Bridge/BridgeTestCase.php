<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Bridge;

use LoginDefense\Bridge\Laravel\LoginDefenseServiceProvider;
use Orchestra\Testbench\TestCase;

/**
 * Shared base for the bridge suite. This suite exists to prove the wiring — that
 * the framework-free core binds cleanly onto Laravel's cache, events and config —
 * so it, and only it, boots a framework.
 */
abstract class BridgeTestCase extends TestCase
{
    /**
     * @param \Illuminate\Foundation\Application $app
     * @return list<class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [LoginDefenseServiceProvider::class];
    }
}
