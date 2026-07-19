<?php

declare(strict_types=1);

namespace LoginDefense\Tests\Core;

use LoginDefense\Core\Exceptions\CaptchaVerificationException;
use LoginDefense\Core\Verifiers\RecaptchaVerifier;
use LoginDefense\Tests\Core\Doubles\FakeHttpClient;
use Nyholm\Psr7\Factory\Psr17Factory;
use PHPUnit\Framework\TestCase;

/**
 * The HTTP verifier tested against a real PSR-17 factory and a stubbed PSR-18
 * client. It asserts the two outcomes the guard relies on — verified / not
 * verified — plus the two security promises: an outage throws (so the guard, not
 * the verifier, chooses fail-open vs fail-closed) and the secret never leaves the
 * request body.
 */
final class RecaptchaVerifierTest extends TestCase
{
    private const SECRET = 'test-secret-value';

    public function test_a_success_response_verifies_the_token(): void
    {
        $factory = new Psr17Factory();
        $client = FakeHttpClient::returning($factory, '{"success": true}');
        $verifier = new RecaptchaVerifier($client, $factory, $factory, self::SECRET);

        self::assertTrue($verifier->verify('a-token', '203.0.113.10'));
    }

    public function test_a_failure_response_rejects_the_token(): void
    {
        $factory = new Psr17Factory();
        $client = FakeHttpClient::returning($factory, '{"success": false}');
        $verifier = new RecaptchaVerifier($client, $factory, $factory, self::SECRET);

        self::assertFalse($verifier->verify('a-token'));
    }

    public function test_a_malformed_body_is_treated_as_not_verified(): void
    {
        $factory = new Psr17Factory();
        $client = FakeHttpClient::returning($factory, 'not json at all');
        $verifier = new RecaptchaVerifier($client, $factory, $factory, self::SECRET);

        self::assertFalse($verifier->verify('a-token'));
    }

    public function test_a_provider_outage_throws_rather_than_returning_false(): void
    {
        $factory = new Psr17Factory();
        $verifier = new RecaptchaVerifier(FakeHttpClient::offline(), $factory, $factory, self::SECRET);

        $this->expectException(CaptchaVerificationException::class);

        $verifier->verify('a-token');
    }

    public function test_the_secret_is_never_placed_in_the_request_url(): void
    {
        $factory = new Psr17Factory();
        $client = FakeHttpClient::returning($factory, '{"success": true}');
        $verifier = new RecaptchaVerifier($client, $factory, $factory, self::SECRET);

        $verifier->verify('a-token');

        self::assertNotNull($client->lastRequest);
        self::assertStringNotContainsString(self::SECRET, (string) $client->lastRequest->getUri());
    }
}
