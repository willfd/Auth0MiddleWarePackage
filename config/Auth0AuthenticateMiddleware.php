<?php

return [
    'domain' => env('AUTH0_DOMAIN', ''),
    'clientId' => env('AUTH0_CLIENT_ID', '_'),
    'cookieSecret' => env('AUTH0_COOKIE_SECRET', '_'),
    'audience' => explode(',', env('AUTH0_AUDIENCE', '')),
];
