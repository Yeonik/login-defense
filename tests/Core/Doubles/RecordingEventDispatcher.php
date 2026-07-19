<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core\Doubles;

use Psr\EventDispatcher\EventDispatcherInterface;

/**
 * Captures dispatched events so a test can assert what the guard announced — and,
 * just as importantly, assert that what it announced never contains a secret.
 */
final class RecordingEventDispatcher implements EventDispatcherInterface
{
    /**
     * @var list<object>
     */
    public array $events = [];

    public function dispatch(object $event): object
    {
        $this->events[] = $event;

        return $event;
    }

    /**
     * @param class-string $type
     */
    public function has(string $type): bool
    {
        foreach ($this->events as $event) {
            if ($event instanceof $type) {
                return true;
            }
        }

        return false;
    }
}
