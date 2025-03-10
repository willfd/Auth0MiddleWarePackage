<?php

namespace willfd\auth0middlewarepackage\Http\Middleware;

use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Exception\ConfigurationException;
use Auth0\SDK\Token;
use Closure;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Psr\Log\LoggerInterface;

class Auth0AuthenticateMiddleware
{
    protected SdkConfiguration $sdkConfiguration;

    /**
     * @throws ConfigurationException
     */
    public function __construct(
        protected string $domain,
        protected string $clientId,
        protected string $cookieSecret,
        protected array $audience,
        protected array $scopes,
        protected array $adminScopes,
        protected LoggerInterface $logger
    ) {
        $this->sdkConfiguration = new SdkConfiguration([
            'domain' => $this->domain,
            'clientId' => $this->clientId,
            'cookieSecret' => $this->cookieSecret,
            'audience' => $this->audience,
        ]);
    }
    public function handle(Request $request, Closure $next)
    {

        if ( $this->domain == '' ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Domain not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->clientId == '' ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Client Id not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->cookieSecret == '' ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Client Secret not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->audience == [''] ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Audience not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->scopes == [''] ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Scopes not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        $bearerToken = $request->bearerToken();
        if ($bearerToken === null) {
            return new Response("No authentication token provided", 401, ['content-type' => 'application/json'] );
        }

        $token = $this->validateToken($bearerToken);
        if ( !$token ) {
            $this->logger->debug("Authentication Failed: Token Validation Failed");
            return new Response("Token failed authentication", 401, ['content-type' => 'application/json'] );
        }

	 // Add custom middleware logic here
        return $next($request);
    }

    protected function validateToken(string $bearerToken): ?Token
    {
        try {
            $token = new Token($this->sdkConfiguration, $bearerToken);

            $token->verify();
            $token->validate();
        } catch (Exception) {
            return null;
        }

        return $token;
    }
}
