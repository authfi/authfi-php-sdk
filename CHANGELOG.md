# Changelog

All notable changes to this package. It follows [Semantic Versioning](https://semver.org): before 1.0 a minor
version may break, but only with an entry here.

## 0.2.0

The first version published to Packagist. Earlier versions were installed from git.

### Added

- Verification of EdDSA access tokens, which is how AuthFI signs an AI agent's token, beside RS256. Each algorithm
  is accepted only with a key of the matching type.
- Key discovery from the issuer: the key set is read from the `jwks_uri` in
  `<issuer>/.well-known/openid-configuration` (falling back to `oauth-authorization-server`), and the issuer in
  the document must match the one you configured.

### Changed

- **Verification is strict.** A token is accepted only when its `typ` is `at+jwt`, its `iss` matches exactly, its
  `aud` contains an audience you configured (with none configured, every token is refused) and `exp` is present.
  ID tokens and tokens minted for another API are refused. **Breaking** for code that relied on the earlier,
  looser checks.
- Keys with private members, `use=enc`, an `alg` that does not match the key, or an RSA modulus under 2048 bits
  are refused. An unknown `kid` refetches the key set at most once every 30 seconds.
- The package requires `firebase/php-jwt` 7, because 6.x is under a security advisory.
- The `firebase/php-jwt` global leeway is restored after each call.
- The client no longer prints its API key (`var_dump`, `print_r`, `var_export`, `serialize`, stack traces), and a
  refusal never carries the token.
- PHP 8.1 or later is required, with the `curl`, `json`, `openssl` and `sodium` extensions.

### Removed

- The cloud credentials section of the README, which described a method the SDK does not have.
