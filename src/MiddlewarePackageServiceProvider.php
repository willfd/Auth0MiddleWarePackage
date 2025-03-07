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
    }

    /**
     * Register the service provider.
     */
    public function register()
    {
        Log::debug('config', ['domain' => config('domain')] );

        $this->app->singleton('Auth0AuthenticateMiddleware', function ($app) {
//            Log::debug('config', ['domain' => config('domain')] );
            return new Auth0AuthenticateMiddleware();
        });
//        $this->mergeConfigFrom(__DIR__.'/../config/Auth0AuthenticateMiddleware.php', 'Auth0AuthenticateMiddleware');
    }
}
