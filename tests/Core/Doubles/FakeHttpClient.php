<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core\Doubles;

use Psr\Http\Client\ClientExceptionInterface;
use Psr\Http\Client\ClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

/**
 * A PSR-18 client that returns a canned response or, to model an outage, throws a
 * ClientExceptionInterface. It also records the last request so a test can prove
 * the secret was never placed in the URL.
 */
final class FakeHttpClient implements ClientInterface
{
    public ?RequestInterface $lastRequest = null;

    private function __construct(
        private readonly ?ResponseInterface $response,
        private readonly bool $throws,
    ) {
    }

    public static function returning(ResponseFactoryInterface $factory, string $body): self
    {
        $response = $factory->createResponse(200);
        $response->getBody()->write($body);

        return new self($response, false);
    }

    public static function offline(): self
    {
        return new self(null, true);
    }

    public function sendRequest(RequestInterface $request): ResponseInterface
    {
        $this->lastRequest = $request;

        if ($this->throws || $this->response === null) {
            throw new class ('connection refused') extends RuntimeException implements ClientExceptionInterface {
            };
        }

        $this->response->getBody()->rewind();

        return $this->response;
    }
}
