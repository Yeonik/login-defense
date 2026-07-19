<?php

declare(strict_types=1);

namespace LoginDefense\Bridge\Laravel;

use Illuminate\Contracts\Events\Dispatcher;
use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Adapts Laravel's event dispatcher to the PSR-14 interface the core depends on.
 * Laravel dispatches an object event under its class name, so the core's
 * CaptchaRequired / AccountLockedOut events reach any listener bound to those
 * classes — while the core itself never learns it is running inside Laravel.
 */
final class PsrEventDispatcher implements EventDispatcherInterface
{
    public function __construct(
        private readonly Dispatcher $dispatcher,
    ) {
    }

    public function dispatch(object $event): object
    {
        $this->dispatcher->dispatch($event);

        return $event;
    }
}
