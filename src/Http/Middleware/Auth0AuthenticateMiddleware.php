<?php

namespace willfd\auth0middlewarepackage\Http\Middleware;

use Illuminate\Support\Facades\Log;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;

class Auth0AuthenticateMiddleware
{
    public function __construct(
        protected string $domain,
        protected string $clientId,
        protected string $cookieSecret,
        protected array $audience,
        protected array $scopes,
        protected array $adminScopes,
    ) {
        Log::debug("Middleware Started with auth0 config", ["domain" => $this->domain, "clientId" => $this->clientId, "audience" => $this->audience, "scopes" => $this->scopes, "adminScopes" => $this->adminScopes]);
    }
    public function handle(Request $request, Closure $next)
    {
       	Log::debug("Package HIT");

        if ( $this->domain == '' ) {
            Log::debug("Auth0AuthenticateMiddleware ERROR: Domain not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->clientId == '' ) {
            Log::debug("Auth0AuthenticateMiddleware ERROR: Client Id not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->cookieSecret == '' ) {
            Log::debug("Auth0AuthenticateMiddleware ERROR: Client Secret not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->audience == [''] ) {
            Log::debug("Auth0AuthenticateMiddleware ERROR: Audience not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

        if ( $this->scopes == [''] ) {
            Log::debug("Auth0AuthenticateMiddleware ERROR: Scopes not set");
            return new Response("No authentication config setup", 401, ['content-type' => 'application/json'] );
        }

	 // Add custom middleware logic here
        return $next($request);
    }
}
