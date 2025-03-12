<?php

namespace willfd\auth0middlewarepackage\Http\Middleware;

use Auth0\SDK\Configuration\SdkConfiguration;
use Auth0\SDK\Exception\InvalidTokenException;
use Closure;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Psr\Log\LoggerInterface;
use willfd\auth0middlewarepackage\Exceptions\AuthenticationException;
use willfd\auth0middlewarepackage\Exceptions\TokenConfigurationException;
use willfd\auth0middlewarepackage\Services\AuthenticationService;
use willfd\auth0middlewarepackage\Exceptions\ConfigurationException;


class Auth0AuthenticateMiddleware
{
    protected array $errorResponseHeaders;
    public function __construct(
        protected AuthenticationService $authenticationService,
        protected array $adminScopes,
        protected ?SdkConfiguration $sdkConfiguration,
        protected LoggerInterface $logger
    ) {
        $this->errorResponseHeaders = ['content-type' => 'application/json'];
    }
    public function handle(Request $request, Closure $next, string $requiredScope){

        try{
            $request = $this->authenticationService->authenticateScopesAndBuyer($request, $this->sdkConfiguration, $requiredScope, $this->adminScopes);
            return $next($request);
        }
        catch(AuthenticationException $e){
            return new Response(
                "Authentication Fail - failed authentication",
                403,
                $this->errorResponseHeaders
            );
        } catch (ConfigurationException $e) {
            return new Response(
                "Authentication Fail - Config internal ERROR",
                500,
                $this->errorResponseHeaders
            );
        } catch (TokenConfigurationException $e) {
            return new Response(
                "Authentication Fail - invalid request",
                401,
                $this->errorResponseHeaders
            );
        } catch (InvalidTokenException $e) {
            return new Response(
                "Authentication Fail - failed Auth0 authentication",
                403,
                $this->errorResponseHeaders
            );
        }
    }
}
