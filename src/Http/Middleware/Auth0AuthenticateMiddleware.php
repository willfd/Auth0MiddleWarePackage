<?php

namespace willfd\MyMiddlewarePackage\Http\Middleware;

use Illuminate\Support\Facades\Log;
use Closure;
use Illuminate\Http\Request;

class Auth0AuthenticateMiddleware
{
    public function handle(Request $request, Closure $next)
    {
       	Log::debug("Package HIT");
	 // Add custom middleware logic here
        return $next($request);
    }
}
