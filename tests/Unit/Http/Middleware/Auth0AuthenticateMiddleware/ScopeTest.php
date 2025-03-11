<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Auth0\SDK\Token;
use Illuminate\Http\Request;
use Mockery;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class ScopeTest extends Auth0AuthenticateTest
{
    public function testHandleInvalidScopeNotAdmin()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['admin:app-test'],
            'audience' => ['fake-audience'],
        ];

        $fakeRequest = Mockery::mock(Request::class);

        $middleware = Mockery::mock(Auth0AuthenticateMiddleware::class, [
            $fakeConfig['domain'],
            $fakeConfig['clientId'],
            $fakeConfig['cookieSecret'],
            $fakeConfig['audience'],
            $fakeConfig['adminScopes'],
            $this->mockConfig,
            $this->logger
            ]
        )->makePartial();

        $fakeRequest->shouldReceive('bearerToken')
            ->once()
            ->andReturn('token');

        $fakeRequest->shouldReceive('scope')
            ->once()
            ->andReturn('read:app-test');

        $mockedToken = Mockery::mock('overload:' . Token::Class);

        $middleware->shouldReceive('validateToken')
            ->once()
            ->with('token')
            ->andReturn($mockedToken);

        $middleware->shouldReceive('decodeToken')
            ->once()
            ->with($mockedToken)
            ->andReturn(['buyerId' => 'buyerId', 'scope' => 'invalid:read-scope']);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:test-app');

        // check debug log is logged
        $this->assertEquals("debug", $this->logger->logs[1]['level']);
        // check debug log is clear and useful
        $this->assertEquals("Authentication Failed: Invalid Scopes", $this->logger->logs[1]['message']);

        $this->assertEquals(401, $response->status());
        $this->assertEquals("No authentication token invalid", $response->getContent());

//        print_r($this->logger->logs);
    }

    public function testHandleInvalidScopeAdmin()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['admin:test-app'],
            'audience' => ['fake-audience'],
        ];

        $fakeRequest = Request::create('/', 'GET');
        $fakeRequest->headers->set('Authorization', 'Bearer token');
        $fakeRequest->attributes->set('scope', 'read:app-test');

        $middleware = Mockery::mock(Auth0AuthenticateMiddleware::class, [
                $fakeConfig['domain'],
                $fakeConfig['clientId'],
                $fakeConfig['cookieSecret'],
                $fakeConfig['audience'],
                $fakeConfig['adminScopes'],
                $this->mockConfig,
                $this->logger
            ]
        )->makePartial();

        $mockedToken = Mockery::mock('overload:' . Token::Class);

        $middleware->shouldReceive('validateToken')
            ->once()
            ->with('token')
            ->andReturn($mockedToken);

        $middleware->shouldReceive('decodeToken')
            ->once()
            ->with($mockedToken)
            ->andReturn(['buyerId' => 'buyerId', 'scope' => 'invalid:read-scope']);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:test-app');

        $this->assertEquals(200, $response->status());

        // Check if the middleware added attributes correctly
        $this->assertTrue($this->capturedRequest->attributes->has('isAdmin'));
        $this->assertTrue($this->capturedRequest->attributes->has('tokenBuyerId'));

        // Assert values of attributes
        $this->assertTrue($this->capturedRequest->attributes->get('isAdmin'));
        $this->assertEquals('buyerId', $this->capturedRequest->attributes->get('tokenBuyerId'));
    }

    public function testHandleValidScope()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['admin:fake-test'],
            'audience' => ['fake-audience'],
        ];

        $fakeRequest = Request::create('/', 'GET');
        $fakeRequest->headers->set('Authorization', 'Bearer token');
        $fakeRequest->attributes->set('scope', 'read:app-test');

        $middleware = Mockery::mock(Auth0AuthenticateMiddleware::class, [
                $fakeConfig['domain'],
                $fakeConfig['clientId'],
                $fakeConfig['cookieSecret'],
                $fakeConfig['audience'],
                $fakeConfig['adminScopes'],
                $this->mockConfig,
                $this->logger
            ]
        )->makePartial();

        $mockedToken = Mockery::mock('overload:' . Token::Class);

        $middleware->shouldReceive('validateToken')
            ->once()
            ->with('token')
            ->andReturn($mockedToken);

        $middleware->shouldReceive('decodeToken')
            ->once()
            ->with($mockedToken)
            ->andReturn(['buyerId' => 'buyerId', 'scope' => 'read:app-test']);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:app-test');

        $this->assertEquals(200, $response->status());

        // Check if the middleware added attributes correctly
        $this->assertTrue($this->capturedRequest->attributes->has('isAdmin'));
        $this->assertTrue($this->capturedRequest->attributes->has('tokenBuyerId'));

        // Assert values of attributes
        $this->assertFalse($this->capturedRequest->attributes->get('isAdmin'));
        $this->assertEquals('buyerId', $this->capturedRequest->attributes->get('tokenBuyerId'));
    }
}
