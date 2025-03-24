<?php

namespace willfd\auth0middlewarepackage\Services;

use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Exception\InvalidTokenException;
use Auth0\SDK\Token;
use Illuminate\Http\Request;
use Psr\Log\LoggerInterface;
use willfd\auth0middlewarepackage\Exceptions\AuthenticationException;
use willfd\auth0middlewarepackage\Exceptions\ConfigurationException;
use willfd\auth0middlewarepackage\Exceptions\TokenConfigurationException;

class AuthenticationService
{
    public function __construct(protected LoggerInterface $logger)
    {
        //
    }

    /**
     * @throws ConfigurationException
     * @throws TokenConfigurationException
     * @throws AuthenticationException
     * @throws InvalidTokenException
     */
    public function authenticateScopesAndBuyer(Request $request, ?SdkConfiguration $sdkConfig, string $requiredScope, array $adminScopes): Request
    {
        $isTesting = in_array( config('app.env','default'),  ['test','testing','behat'] );

        if( is_null( $sdkConfig ) && !$isTesting){
            throw new ConfigurationException("Authentication config not set");
        }

        if ( $requiredScope == '' ) {
            $this->logger->debug("Auth0AuthenticateMiddleware ERROR: Scopes not set");
            throw new ConfigurationException("Authentication scope not set");
        }

        $bearerToken = $request->bearerToken();
        if ($bearerToken === null) {
            throw new TokenConfigurationException("Bearer token not set");
        }

        if( !$isTesting ){
            $token = $this->validateToken($sdkConfig, $bearerToken);
            if ( !$token ) {
                $this->logger->debug("Authentication Failed: Token Validation Failed");
                throw new AuthenticationException("Token failed authentication");
            }
        }

        $decoded = $this->decodeToken($bearerToken);

        $this->logger->debug("Auth0AuthenticateMiddleware Token Decoded: " . json_encode($decoded));

        $isAdmin = false;
        $seperatedScope = explode(':', $requiredScope);

        $scopes = $decoded['scope'] ?? '';
        $tokenScopes = is_string($scopes) ? explode(' ', $scopes) : [];

        // Check Admin Scopes for scope with matching second half after : to required scope
        foreach ( $adminScopes as $adminScope){
            $seperatedAdminScope = explode(':', $adminScope);
            // check if admin scope exists for required scope
            if(count($seperatedAdminScope) > 1 && $seperatedAdminScope[1] == $seperatedScope[1]){
                // check if admin scope in token scopes
                if( in_array( $adminScope, $tokenScopes) ){
                    $isAdmin = true;
                }
            }
        }

        $buyerId = $decoded['buyerId'] ?? null;
        if ( !$isAdmin && (!is_string($buyerId) || empty($buyerId)) ) {
            $this->logger->debug("Authentication Failed: No Buyer Id in Token");
            throw new AuthenticationException("Buyer Id not set and not admin");
        }

        if ( !in_array($requiredScope, $tokenScopes, true) && !$isAdmin ) {
            $this->logger->debug("Authentication Failed: Invalid Scopes");
            throw new AuthenticationException("Invalid Scopes");
        }

        $request->attributes->add([
            'isAdmin' => $isAdmin,
            'tokenBuyerId' => $decoded['buyerId'] ?? null,
        ]);

        return $request;
    }

    /**
     * @throws InvalidTokenException
     */
    public function validateToken(?SdkConfiguration $sdkConfiguration, string $bearerToken): ?Token
    {
        try{
            $token = new Token($sdkConfiguration, $bearerToken);

            $token->verify();
            $token->validate();

            return $token;
        }
        catch(InvalidTokenException $e){
            $this->logger->debug("Authentication Token Validation Failed: ".$e->getMessage());
            throw $e;
        }

    }

    public function decodeToken(string $token): array
    {
        list($header, $payload, $signature) = explode('.', $token);
        return json_decode( base64_decode($payload), true);
    }
}