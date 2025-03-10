# Auth0MiddlewarePackage

## Package Implementation

### Add Package to app
Add package to composer.json
```json
"require-dev": {
  "willfd/auth0middlewarepackage": "dev-main"
},
```

### App Config
create a config file for the package to use run
```bash
php artisan vendor:publish
```


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