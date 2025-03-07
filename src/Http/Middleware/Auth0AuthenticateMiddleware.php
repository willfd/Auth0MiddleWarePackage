<?php

namespace willfd\auth0middlewarepackage\Http\Middleware;

use Illuminate\Support\Facades\Log;
use Closure;
use Illuminate\Http\Request;

class Auth0AuthenticateMiddleware
{
    public function __construct(
//        protected string $domain,
//        protected string $clientId,
//        protected string $cookieSecret,
//        protected array $audience,
    ) {
//        Log::debug("Middleware Started with auth0 config", ["domain" => $this->domain, "clientId" => $this->clientId, "audience" => $this->audience]);
    }
    public function handle(Request $request, Closure $next)
    {
       	Log::debug("Package HIT");

	 // Add custom middleware logic here
        return $next($request);
    }
}
