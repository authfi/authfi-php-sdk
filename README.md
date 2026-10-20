# AuthFI PHP SDK

Official PHP SDK for [AuthFI](https://authfi.io) — the identity control plane.

It verifies the access tokens AuthFI issues, for people and for AI agents, and checks
roles and permissions on the claims.

## Install

The SDK is installed from git. It is not published to Packagist yet.

```json
{
  "repositories": [
    { "type": "vcs", "url": "https://github.com/authfi/authfi-php-sdk" }
  ],
  "require": { "authfi/authfi": "dev-main#<commit>" }
}
```

Then run `composer update authfi/authfi`. Pin `<commit>` to a commit so installs are
reproducible. Requires PHP 8.1 or later with the openssl, sodium and curl extensions.

## Quick Start (Laravel)

```php
// app/Providers/AppServiceProvider.php
$this->app->singleton(AuthFI::class, fn() =>
    new AuthFI(
        'acme',
        issuer: 'https://acme.authfi.io',  // your project's issuer
        audience: 'app_xxxxxxxx',          // the client id(s) your API accepts
    )
);

// routes/api.php
Route::get('/api/users', function (Request $request) {
    $auth = app(AuthFI::class);
    $user = $auth->authenticate($request);
    $auth->requirePermissions($user, ['read:users']);
    return User::all();
});
```

Any framework can use `verifyToken($token)` with the bearer token it already reads.

## Token verification

```php
$claims = $auth->verifyToken($token);
// $claims->sub, $claims->email, $claims->roles, $claims->permissions
```

`verifyToken` accepts a token only when all of these hold. Otherwise it throws
`AuthFIException` (status 401) with a fixed message that never contains the token.

- The signature verifies against the project's published keys. The keys are found by
  discovery: the SDK reads `<issuer>/.well-known/openid-configuration` and fetches the
  `jwks_uri` it names. RS256 (people, machine clients) and EdDSA (AI agents) are accepted.
- The header `typ` is `at+jwt`. An ID token is refused.
- `iss` equals the issuer exactly.
- `aud` contains one of the configured audiences. With no `audience` configured, every
  token is refused. The issuer itself, and anything under it such as `<issuer>/mcp`, is
  refused as an audience.
- `exp` is present and in the future, with `leeway` seconds of clock skew (default 60).
- `sub` is present.

A custom domain is set with `issuer`. Without it the issuer is `https://<tenant>.authfi.io`.
The keys are cached for `jwksTtl` seconds (default 300). A token naming an unknown key
refetches them at most once every 30 seconds.

## Keeping secrets out of logs

The token and the API key are marked `#[\SensitiveParameter]`, so a stack trace on PHP 8.2 or
later shows them redacted. On PHP 8.1 the attribute does not exist: keep
`zend.exception_ignore_args=On`, which is the `php.ini-production` default, so traces carry no
arguments.

## Roles and permissions

```php
$auth->requirePermissions($claims, ['read:users']);  // all of them, else 403
$auth->requireRole($claims, ['admin', 'editor']);    // any of them, else 403
```

## Running tests

```bash
composer install
php test_authfi.php
```

## License

Apache-2.0
