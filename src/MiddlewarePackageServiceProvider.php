<?php

namespace willfd\auth0middlewarepackage;

use Illuminate\Support\Facades\Log;
use Illuminate\Support\ServiceProvider;
use willfd\auth0middlewarepackage\Http\Middleware\Auth0AuthenticateMiddleware;

class MiddlewarePackageServiceProvider extends ServiceProvider
{
    /**
     * Indicates if loading of the provider is deferred.
     *
     * @var bool
     */
    protected $defer = false;

    /**
     * Bootstrap the application events.
     */
    public function boot()
    {
        $this->publishes([
            __DIR__.'/../config/Auth0AuthenticateMiddleware.php' => config_path('Auth0AuthenticateMiddleware.php'),
        ]);

        Log::debug('config', ['domain' => config('Auth0AuthenticateMiddleware.domain')] );

    }

    /**
     * Register the service provider.
     */
    public function register()
    {
        $this->mergeConfigFrom(__DIR__.'/../config/Auth0AuthenticateMiddleware.php', 'Auth0AuthenticateMiddleware');

        $this->app->singleton(Auth0AuthenticateMiddleware::class, function ($app) {
            return new Auth0AuthenticateMiddleware(
                config('Auth0AuthenticateMiddleware.domain'),
                config('Auth0AuthenticateMiddleware.clientId'),
                config('Auth0AuthenticateMiddleware.cookieSecret'),
                config('Auth0AuthenticateMiddleware.audience')
            );
        });
    }
}
