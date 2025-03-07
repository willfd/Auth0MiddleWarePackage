<?php

namespace willfd\MyMiddlewarePackage;

use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class MyMiddlewarePackageServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('my-middleware-package')
            ->hasConfigFile();
    }
}
