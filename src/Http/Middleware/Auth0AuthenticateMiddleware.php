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
    /**
     * @throws ConfigurationException
     */
    public function __construct(
        protected string $domain,
        protected string $clientId,
        protected string $cookieSecret,
        protected array $audience,
        protected array $adminScopes,
        protected ?SdkConfiguration $sdkConfiguration,
        protected LoggerInterface $logger
    ) {
        //
    }
    public function handle(Request $request, Closure $next, string $requiredScope)
    {
        if( is_null( $this->sdkConfiguration ) ){
            return new Response("Authentication Config internal ERROR", 500);
        }

        if ( $requiredScope == '' ) {
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

        $decoded = $this->decodeToken($token);

        $this->logger->debug("Auth0AuthenticateMiddleware Token Decoded: " . json_encode($decoded));

        $buyerId = $decoded['buyerId'] ?? null;
        if ( !is_string($buyerId) || empty($buyerId)) {
            $this->logger->debug("Authentication Failed: No Buyer Id in Token");
            return new Response("No authentication token invalid", 401, ['content-type' => 'application/json'] );
        }

        $scopes = $decoded['scope'] ?? '';
        $tokenScopes = is_string($scopes) ? explode(' ', $scopes) : [];

        $isAdmin = false;
        $seperatedScope = explode(':', $requiredScope);

        // Check Admin Scopes for scope with matching second half after : to required scope
        foreach ( $this->adminScopes as $adminScope){
            $seperatedAdminScope = explode(':', $adminScope);
            if(count($seperatedAdminScope) > 1 && $seperatedAdminScope[1] == $seperatedScope[1]){
                $isAdmin = true;
            }
        }

        if ( !in_array($requiredScope, $tokenScopes, true) && !$isAdmin ) {
            $this->logger->debug("Authentication Failed: Invalid Scopes");
            return new Response("No authentication token invalid" , 401, ['content-type' => 'application/json'] );
        }


        $request->attributes->add([
            'isAdmin' => $isAdmin,
            'tokenBuyerId' => $decoded['buyerId'],
        ]);

	 // Add custom middleware logic here
        return $next($request);
    }

    public function validateToken(string $bearerToken): ?Token
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

    public function decodeToken(Token $token): array
    {
        return $token->toArray();
    }
}
