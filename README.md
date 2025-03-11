# Auth0MiddlewarePackage

## Package Implementation

### Add Package to app
#### Add package to composer.json
Add Repo package is located at for composer to find package
```json
"repositories": [
    {
      "url": "https://github.com/willfd/Auth0MiddleWarePackage",
      "type": "git"
    }
],
```
Add package requirement
```json
"require-dev": {
  "willfd/auth0middlewarepackage": "dev-main"
},
```

### App Config
#### create config file for package
```bash
php artisan vendor:publish
```

#### set env variables 
```text
AUTH0_DOMAIN=          STRING                   ie https://domain-staging.uk.auth0.com
AUTH0_CLIENT_ID=       STRING                   ie ABcD1eFgHiJkL23Mn4opQ5rSTuVwXyzA
AUTH0_AUDIENCE=        STRING                   ie tmf-api
AUTH0_REQUIRED_SCOPES= STRING COMMA SEPERATED   ie write:app-example,read:app-example
AUTH0_ADMIN_SCOPES=    STRING COMMA SEPERATED   ie admin:app-example
```

#### Set Middleware Alias (optional)
In bootstrap/app.php add below. The alias can be called anything, the alias shall be used to reference the middleware within the routes
```php
$middleware->alias([
    'package' => Auth0AuthenticateMiddleware::class,
]);
```

#### route setup
Add middleware to desired routes. "package" is the middlewares alias, "write:example-scope" is the required scope any routes within the middleware route.
```php
Route::middleware('package:write:example-scope')
```

## Details
If admin scopes are provided within the env. required scopes can be ignored if an admin scope is provided in the env with a matching name ie if the required scope is read:example-app then admin:example-app would bypass the required scope.

## Local Dev

### Docker
Spin up container using below (first time also include --build)
```bash
docker-compose up
```


### tests
```bash
vendor/bin/phpunit tests/
```