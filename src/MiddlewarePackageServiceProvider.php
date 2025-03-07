<?php

namespace willfd\auth0middlewarepackage\src;

use Illuminate\Support\ServiceProvider;

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
        $this->mergeConfigFrom(__DIR__.'/../config/Auth0AuthenticateMiddleware.php', 'Auth0AuthenticateMiddleware.php');
    }
}
