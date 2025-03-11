<?php

namespace Tests\Unit\Http\Middleware\Auth0AuthenticateMiddleware;

use Auth0\SDK\Configuration\SdkConfiguration;
use Illuminate\Http\Response;
use Illuminate\Http\Request;
use PHPUnit\Framework\TestCase;
use Mockery;
use Tests\Unit\TestLogger;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class Auth0AuthenticateTest extends TestCase
{
    protected ?Request $capturedRequest = null;
    protected function setUp(): void
    {
        parent::setUp();

        $this->closure = function ($request) {
            $this->capturedRequest = $request;

            return new Response('Next middleware executed', 200);
        };

//        $this->closure = function () {
//            return new Response();
//        };
        $this->logger =  new TestLogger();
        $this->mockConfig = Mockery::mock('overload:'.SdkConfiguration::class);
    }

    public function testHandleNoBearerToken()
    {
        $fakeConfig = [
            'domain' => 'www.fakeDomain.com',
            'clientId' => 'clientId123',
            'cookieSecret' => 'secret123',
            'adminScopes' => ['fake:admin-scope'],
            'audience' => ['fake-audience'],
        ];

        $fakeRequest = Mockery::mock(Request::class);

        $middleware = new Auth0AuthenticateMiddleware(
            $fakeConfig['domain'],
            $fakeConfig['clientId'],
            $fakeConfig['cookieSecret'],
            $fakeConfig['audience'],
            $fakeConfig['adminScopes'],
            $this->mockConfig,
            $this->logger
        );

        $fakeRequest->shouldReceive('bearerToken')
            ->once()
            ->andReturn(null);

        $response = $middleware->handle($fakeRequest, $this->closure, 'read:app-test');

        $this->assertEquals(401, $response->status());
        $this->assertEquals("No authentication token provided", $response->getContent());

//        print_r($this->logger->logs);
    }

}
