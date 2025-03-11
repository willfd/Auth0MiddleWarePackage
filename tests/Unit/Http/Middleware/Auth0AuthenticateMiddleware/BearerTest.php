<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Auth0\SDK\Token;
use Illuminate\Http\Request;
use Mockery;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class BearerTest extends Auth0AuthenticateTest
{
    public function testHandleAdminScopesNoBearer()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['admin:fake-test','admin:app-test'],
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
            ->andReturn(['scope' => 'read:app-test']);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:app-test');

        $this->assertEquals(200, $response->status());

        // Check if the middleware added attributes correctly
        $this->assertTrue($this->capturedRequest->attributes->has('isAdmin'));
        $this->assertTrue($this->capturedRequest->attributes->has('tokenBuyerId'));

        // Assert values of attributes
        $this->assertTrue($this->capturedRequest->attributes->get('isAdmin'));
        $this->assertEquals(null, $this->capturedRequest->attributes->get('tokenBuyerId'));
    }

    public function testHandleNotAdminScopesNoBearer()
    {
        $fakeConfig = [
            'domain' => '',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['admin:fake-test','admin:test-fake'],
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
            ->andReturn(['scope' => 'read:app-test']);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:app-test');

        $this->assertEquals(401, $response->status());
    }

}
