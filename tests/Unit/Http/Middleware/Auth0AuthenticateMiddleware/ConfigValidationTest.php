<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Auth0\SDK\Token;
use Illuminate\Http\Request;
use Mockery;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class ConfigValidationTest extends Auth0AuthenticateTest
{
    public function testHandleInvalidScope()
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

        $middleware = Mockery::mock(Auth0AuthenticateMiddleware::class, [
            $fakeConfig['domain'],
            $fakeConfig['clientId'],
            $fakeConfig['cookieSecret'],
            $fakeConfig['audience'],
            $fakeConfig['requiredScopes'],
            $fakeConfig['adminScopes'],
            $this->mockConfig,
            $this->logger
            ]
        )->makePartial();

        $fakeRequest->shouldReceive('bearerToken')
            ->once()
            ->andReturn('token');

        $mockedToken = Mockery::mock('overload:' . Token::Class);
        
        $middleware->shouldReceive('validateToken')
            ->once()
            ->with('token')
            ->andReturn($mockedToken);

        $middleware->shouldReceive('decodeToken')
            ->once()
            ->with($mockedToken)
            ->andReturn(['buyerId' => 'buyerId', 'scope' => 'invalid:read-scope']);

        $response = $middleware->handle($fakeRequest, $this->closure);

        // check debug log is logged
        $this->assertEquals("debug", $this->logger->logs[1]['level']);
        // check debug log is clear and useful
        $this->assertEquals("Authentication Failed: Invalid Scopes", $this->logger->logs[1]['message']);

        $this->assertEquals(401, $response->status());
        $this->assertEquals("No authentication token invalid", $response->getContent());

//        print_r($this->logger->logs);
    }
}
