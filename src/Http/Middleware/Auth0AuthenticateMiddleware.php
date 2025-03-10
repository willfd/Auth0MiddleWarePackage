<?php

namespace willfd\auth0middlewarepackage\Http\Middleware;

use Illuminate\Support\Facades\Log;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Psr\Log\LoggerInterface;

class Auth0AuthenticateMiddleware
{

    public function __construct(
        protected string $domain,
        protected string $clientId,
        protected string $cookieSecret,
        protected array $audience,
        protected array $scopes,
        protected array $adminScopes,
        protected LoggerInterface $logger
    ) {
//        $this->logger->debug("Middleware Started with auth0 config", ["domain" => $this->domain, "clientId" => $this->clientId, "audience" => $this->audience, "scopes" => $this->scopes, "adminScopes" => $this->adminScopes]);
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

	 // Add custom middleware logic here
        return $next($request);
    }
}
