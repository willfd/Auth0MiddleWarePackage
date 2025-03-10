<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Illuminate\Http\Request;
use Mockery;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class ConfigValidationTest extends Auth0AuthenticateTest
{
    public function testHandleNoBearerToken()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'requiredScopes' => ['fake:read-scope'],
            'adminScopes' => ['fake:admin-scope'],
            'audience' => ['fake-audience'],
        ];

        $fakeRequest = Mockery::mock(Request::class);

        $middleware = new Auth0AuthenticateMiddleware(
            $fakeConfig['domain'],
            $fakeConfig['clientId'],
            $fakeConfig['cookieSecret'],
            $fakeConfig['audience'],
            $fakeConfig['requiredScopes'],
            $fakeConfig['adminScopes'],
            $this->logger
        );

        $fakeRequest->shouldReceive('bearerToken')
            ->once()
            ->andReturn(null);

        $response = $middleware->handle($fakeRequest, $this->closure);

        // check debug log is logged
        $this->assertEquals("debug", $this->logger->logs[0]['level']);
        // check debug log is clear and useful
        $this->assertEquals("Auth0AuthenticateMiddleware ERROR: Domain not set", $this->logger->logs[0]['message']);

        $this->assertEquals(401, $response->status());
        $this->assertEquals("No authentication config setup", $response->getContent());

//        print_r($this->logger->logs);
    }
}
