# AuthFI PHP SDK

Official PHP SDK for [AuthFI](https://authfi.io) — the identity control plane.

## Install

```bash
composer require authfi/authfi
```

## Quick Start (Laravel)

```php
// app/Providers/AppServiceProvider.php
$this->app->singleton(AuthFI::class, fn() =>
    new AuthFI('acme', env('AUTHFI_API_KEY'))
);

// routes/api.php
Route::get('/api/users', function (Request $request) {
    $auth = app(AuthFI::class);
    $user = $auth->authenticate($request);
    $auth->requirePermissions($user, ['read:users']);
    return User::all();
});

// On deploy
$auth->sync();
```

## Features

- JWT verification (RS256 via JWKS)
- Permission checks — `requirePermissions($user, ['read:users'])`
- Role checks — `requireRole($user, ['admin'])`
- Permission auto-sync to AuthFI console
- Works with Laravel, Symfony, Slim, plain PHP

## Token Verification

```php
$claims = $auth->verifyToken($token);
// $claims->sub, $claims->email, $claims->roles, $claims->permissions
```

## Cloud Credentials

```php
$creds = $auth->cloudCredentials($userToken, 'gcp', project: 'my-project');
// $creds->access_token (short-lived GCP token)
```

## Running Tests

```bash
composer install   # pulls firebase/php-jwt
php test_authfi.php
```

Signature tests generate an in-process RSA keypair, so they run offline and
need the OpenSSL extension enabled.

## License

MIT
