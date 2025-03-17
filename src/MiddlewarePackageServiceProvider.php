<?php

namespace willfd\auth0middlewarepackage;

use Auth0\SDK\Configuration\SdkConfiguration;
use Exception;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;
use willfd\auth0middlewarepackage\Services\AuthenticationService;

class MiddlewarePackageServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected bool $defer = false;

    /**
     * Bootstrap the application events.
     */
    public function boot(): void
    {
        $this->publishes([
            __DIR__.'/../config/Auth0AuthenticateMiddleware.php' => config_path('Auth0AuthenticateMiddleware.php'),
        ]);
    }

    /**
     * Register the service provider.
     */
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/Auth0AuthenticateMiddleware.php', 'Auth0AuthenticateMiddleware');

        $sdkConfig = $this->setUpSDKConfiguration();

        $this->app->singleton(Auth0AuthenticateMiddleware::class, function ($app) use ($sdkConfig) {
            return new Auth0AuthenticateMiddleware(
                new AuthenticationService( app('log') ),
                config('Auth0AuthenticateMiddleware.adminScopes'),
                $sdkConfig,
                app('log')
            );
        });
    }

    protected function setUpSDKConfiguration(): ?SdkConfiguration
    {
        try {
            $domain = config('Auth0AuthenticateMiddleware.domain');
            if ($domain == '') {
                throw new Exception("Auth0AuthenticateMiddleware ERROR: Domain not set");
            }

            $clientId = config('Auth0AuthenticateMiddleware.clientId');
            if ($clientId == '') {
                throw new Exception("Auth0AuthenticateMiddleware ERROR: Client Id not set");
            }

            $cookieSecret = config('Auth0AuthenticateMiddleware.cookieSecret');
            if ($cookieSecret == '') {
                throw new Exception("Auth0AuthenticateMiddleware ERROR: Client Secret not set");
            }

            $audience = config('Auth0AuthenticateMiddleware.audience');
            if ($audience == ['']) {
                throw new Exception("Auth0AuthenticateMiddleware ERROR: Audience not set");
            }

            return new SdkConfiguration([
                'domain' => $domain,
                'clientId' => $clientId,
                'cookieSecret' => $cookieSecret,
                'audience' => $audience,
            ]);
        }
        catch (Exception $e) {
            Log::error($e->getMessage());
            return null;
        }
    }
}
