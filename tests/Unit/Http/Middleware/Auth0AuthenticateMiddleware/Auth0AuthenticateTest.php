<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Mock\Event;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Mockery;
use Tests\Unit\TestLogger;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class Auth0AuthenticateTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        $this->closure = function () {
            return response()->json(['status' => 'success']);
        };
        $this->logger =  new TestLogger();
        $this->mockConfig = Mockery::mock('overload:'.SdkConfiguration::class);
    }

    public function testHandleNoBearerToken()
    {
        $fakeConfig = [
            'domain' => 'www.fakeDomain.com',
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
            $this->mockConfig,
            $this->logger
        );

        $fakeRequest->shouldReceive('bearerToken')
            ->once()
            ->andReturn(null);

        $response = $middleware->handle($fakeRequest, $this->closure);

        $this->assertEquals(401, $response->status());
        $this->assertEquals("No authentication token provided", $response->getContent());

//        print_r($this->logger->logs);
    }

}
