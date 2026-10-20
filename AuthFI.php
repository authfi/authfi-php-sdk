<?php
/**
 * AuthFI PHP SDK
 *
 * Usage (Laravel):
 *   $auth = new AuthFI(
 *       'acme',
 *       env('AUTHFI_API_KEY'),                 // only needed for sync()
 *       issuer: 'https://acme.authfi.io',      // your project's issuer
 *       audience: 'app_xxxxxxxx',              // the client id(s) your API accepts
 *   );
 *
 *   // Middleware
 *   Route::get('/api/users', function (Request $request) use ($auth) {
 *       $user = $auth->authenticate($request);
 *       $auth->requirePermissions($user, ['read:users']);
 *       return User::all();
 *   });
 *
 *   // On startup
 *   $auth->sync();
 */

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class AuthFI {
    /** The only signing algorithms a token may use: RS256 (people, machines) and EdDSA (AI agents). */
    public const ALLOWED_ALGS = ['RS256', 'EdDSA'];
    /** An access token's `typ` header (RFC 9068). An ID token carries `JWT`, so it is never accepted. */
    public const ACCESS_TOKEN_TYPES = ['at+jwt', 'application/at+jwt'];
    public const VERSION = '0.2.0';
    public const MAX_TOKEN_BYTES = 16384;
    public const MAX_DOC_BYTES = 262144;
    /** An unknown `kid` triggers at most one JWKS refetch per this many seconds. */
    public const JWKS_MIN_REFETCH_SECONDS = 30;
    private const PRIVATE_JWK_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'];

    private string $tenant;
    /**
     * The api keys, by key holder. The key is kept outside the instance, so var_dump, var_export,
     * print_r, (array) casts, serialize and the debug dumpers of an instance never show it. The
     * holder is an empty object that a clone shares, so a clone keeps the key; it is dropped with
     * the last client that uses it.
     *
     * @var \WeakMap<object, ?string>|null
     */
    private static ?\WeakMap $apiKeys = null;
    private object $keyHolder;
    private string $apiUrl;
    private ?string $applicationId;
    private array $registeredPermissions = [];

    /** Seconds to cache discovery and the JWKS in-memory before refetching. */
    private int $jwksTtl;
    /** Clock-skew tolerance (seconds) applied to exp/nbf/iat. */
    private int $leeway;
    private string $issuer;
    /** @var string[] */
    private array $audiences;

    private ?array $jwks = null;
    private int $jwksFetchedAt = 0;
    private ?string $jwksUri = null;
    private int $jwksUriFetchedAt = 0;

    /**
     * @param string               $tenant   the project slug
     * @param string|null          $apiKey   only needed for sync()
     * @param string|null          $issuer   the project's issuer URL; defaults to https://<tenant>.authfi.io.
     *                                       Discovery, the JWKS and the expected `iss` all come from it.
     * @param string|string[]|null $audience the `aud` value(s) your API accepts. Required to verify tokens:
     *                                       with none configured every token is refused.
     */
    public function __construct(
        string $tenant,
        #[\SensitiveParameter] ?string $apiKey = null,
        string $apiUrl = 'https://api.authfi.io',
        ?string $applicationId = null,
        int $jwksTtl = 300,
        int $leeway = 60,
        ?string $issuer = null,
        string|array|null $audience = null
    ) {
        $this->tenant = $tenant;
        self::$apiKeys ??= new \WeakMap();
        $this->keyHolder = new \stdClass();
        self::$apiKeys[$this->keyHolder] = $apiKey;
        $this->apiUrl = $apiUrl;
        $this->applicationId = $applicationId;
        $this->jwksTtl = $jwksTtl;
        $this->leeway = $leeway;
        $this->issuer = $this->validateIssuer($issuer ?? "https://{$tenant}.authfi.io");
        $this->audiences = $this->validateAudiences($audience);
    }

    /** A configuration object never prints its secret. */
    public function __debugInfo(): array {
        return ['tenant' => $this->tenant, 'issuer' => $this->issuer];
    }

    public function __serialize(): array {
        throw new \LogicException('AuthFI holds credentials and cannot be serialized');
    }

    /**
     * Authenticate request and return decoded claims.
     */
    public function authenticate($request = null): object {
        $token = $this->extractToken($request);
        if (!$token) {
            throw new AuthFIException('Missing authorization', 401);
        }
        return $this->verifyToken($token);
    }

    /**
     * Verify an access token and return its claims.
     *
     * Requires: a compact JWS of three parts; alg RS256 or EdDSA, matching the issuer's
     * published key for the token's kid; typ at+jwt; a valid signature; iss equal to the
     * configured issuer; aud containing a configured audience; exp present and not past;
     * sub present. Any failure throws AuthFIException (401) with a fixed message that
     * never contains the token.
     *
     * @return object decoded claims (stdClass).
     * @throws AuthFIException on any verification failure.
     */
    public function verifyToken(#[\SensitiveParameter] string $token): object {
        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            throw new AuthFIException('Invalid token', 401);
        }
        $parts = explode('.', $token);
        if (count($parts) !== 3) {
            throw new AuthFIException('Invalid token', 401);
        }
        // Every segment is base64url without padding; the standard alphabet is not accepted.
        foreach ($parts as $part) {
            if (!preg_match('/\A[A-Za-z0-9_-]+\z/', $part)) {
                throw new AuthFIException('Invalid token', 401);
            }
        }

        $header = $this->decodeSegment($parts[0]);
        $alg = $header['alg'] ?? null;
        if (!is_string($alg) || !in_array($alg, self::ALLOWED_ALGS, true)) {
            throw new AuthFIException('Unsupported token algorithm', 401);
        }
        $typ = $header['typ'] ?? null;
        if (!is_string($typ) || !in_array(strtolower($typ), self::ACCESS_TOKEN_TYPES, true)) {
            throw new AuthFIException('Token is not an access token', 401);
        }
        $kid = $header['kid'] ?? null;
        if (!is_string($kid) || $kid === '') {
            throw new AuthFIException('Invalid token header', 401);
        }
        if (array_key_exists('crit', $header)) {
            throw new AuthFIException('Unsupported token header', 401);
        }

        $key = $this->signingKey($kid, $alg);

        // firebase/php-jwt verifies the signature against exactly this key and algorithm
        // and enforces exp/nbf/iat with the leeway; the claims below are ours.
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = $this->leeway;
        try {
            $payload = JWT::decode($token, $key);
        } catch (\Throwable $e) {
            throw new AuthFIException($this->decodeFailure($e), 401);
        } finally {
            JWT::$leeway = $previousLeeway;
        }

        $this->validateClaims($payload);
        return $payload;
    }

    private function decodeFailure(\Throwable $e): string {
        return match (true) {
            $e instanceof \Firebase\JWT\ExpiredException => 'Token expired',
            $e instanceof \Firebase\JWT\BeforeValidException => 'Token not yet valid',
            $e instanceof \Firebase\JWT\SignatureInvalidException => 'Invalid token signature',
            default => 'Invalid token',
        };
    }

    private function validateClaims(object $claims): void {
        if (($claims->iss ?? null) !== $this->issuer) {
            throw new AuthFIException('Invalid token issuer', 401);
        }

        if ($this->audiences === []) {
            throw new AuthFIException('Token audience not configured', 401);
        }
        $aud = $claims->aud ?? null;
        $aud = is_string($aud) ? [$aud] : $aud;
        if (!is_array($aud) || array_intersect($this->audiences, array_filter($aud, 'is_string')) === []) {
            throw new AuthFIException('Invalid token audience', 401);
        }

        $exp = $claims->exp ?? null;
        if (!is_int($exp) && !is_float($exp)) {
            throw new AuthFIException('Invalid token expiry', 401);
        }

        $sub = $claims->sub ?? null;
        if (!is_string($sub) || $sub === '') {
            throw new AuthFIException('Invalid token subject', 401);
        }
    }

    private function isLoopback(string $host): bool {
        return in_array($host, ['localhost', '127.0.0.1', '::1', '[::1]'], true);
    }

    private function validateIssuer(string $value): string {
        $u = parse_url($value);
        $ok = is_array($u) && isset($u['scheme'], $u['host'])
            && !isset($u['query']) && !isset($u['fragment']) && !isset($u['user']) && !isset($u['pass'])
            && ($u['path'] ?? '') === '' && !str_ends_with($value, '/')
            && ($u['scheme'] === 'https' || ($u['scheme'] === 'http' && $this->isLoopback($u['host'])));
        if (!$ok) {
            throw new \InvalidArgumentException('issuer must be an https URL (http only for localhost) with no path, query or trailing slash');
        }
        return $value;
    }

    /**
     * AuthFI's own audiences name the gateway, not your API. Accepting one would let a
     * token minted for the gateway be replayed at your API.
     *
     * @param string|string[]|null $value
     * @return string[]
     */
    private function validateAudiences(string|array|null $value): array {
        $list = array_values(array_filter(array_map('strval', (array) $value), fn($a) => $a !== ''));
        foreach ($list as $a) {
            if ($this->isOwnAudience($a)) {
                throw new \InvalidArgumentException("audience $a is AuthFI's own; use your API's client id");
            }
        }
        return $list;
    }

    /**
     * An audience is AuthFI's own when it is the issuer or a URL under it, compared after the
     * scheme and host are lower-cased and a default port is dropped.
     */
    private function isOwnAudience(string $audience): bool {
        $issuer = $this->normalizeUrl($this->issuer);
        $candidate = $this->normalizeUrl($audience);
        return $candidate === $issuer || str_starts_with($candidate, $issuer . '/');
    }

    private function normalizeUrl(string $value): string {
        $u = parse_url($value);
        if (!is_array($u) || !isset($u['scheme'], $u['host']) || !in_array(strtolower($u['scheme']), ['http', 'https'], true)) {
            return $value;
        }
        $scheme = strtolower($u['scheme']);
        $port = $u['port'] ?? ($scheme === 'https' ? 443 : 80);
        $default = $scheme === 'https' ? 443 : 80;
        return $scheme . '://' . rtrim(strtolower($u['host']), '.') . ($port === $default ? '' : ':' . $port) . ($u['path'] ?? '');
    }

    private function decodeSegment(string $segment): array {
        $json = base64_decode(strtr($segment, '-_', '+/'), true);
        $obj = $json === false ? null : json_decode($json, true);
        if (!is_array($obj) || array_is_list($obj)) {
            throw new AuthFIException('Invalid token', 401);
        }
        return $obj;
    }

    /** The key published for $kid as a php-jwt Key, for the token's alg. */
    private function signingKey(string $kid, string $alg): Key {
        $jwk = $this->findJwk($this->fetchJwks(), $kid)
            ?? $this->findJwk($this->fetchJwks(true), $kid);
        if ($jwk === null) {
            throw new AuthFIException('Unknown signing key', 401);
        }
        if (isset($jwk['alg']) && $jwk['alg'] !== $alg) {
            throw new AuthFIException('Signing key does not match token algorithm', 401);
        }
        $kty = $jwk['kty'] ?? null;
        if ($alg === 'RS256') {
            // RSA keys must be at least 2048 bits.
            if ($kty !== 'RSA' || $this->bitLength($this->b64urlDecode((string) ($jwk['n'] ?? ''))) < 2048) {
                throw new AuthFIException('Signing key does not match token algorithm', 401);
            }
        } elseif ($kty !== 'OKP' || ($jwk['crv'] ?? null) !== 'Ed25519'
            || strlen($this->b64urlDecode((string) ($jwk['x'] ?? ''))) !== 32) {
            throw new AuthFIException('Signing key does not match token algorithm', 401);
        }
        try {
            $key = JWK::parseKey($jwk, $alg);
        } catch (\Throwable $e) {
            throw new AuthFIException('Invalid signing key', 401);
        }
        if ($key === null) {
            throw new AuthFIException('Invalid signing key', 401);
        }
        return $key;
    }

    /** The bit length of a big-endian unsigned integer. */
    private function bitLength(string $bytes): int {
        $bytes = ltrim($bytes, "\0");
        return $bytes === '' ? 0 : (strlen($bytes) - 1) * 8 + strlen(decbin(ord($bytes[0])));
    }

    private function b64urlDecode(string $s): string {
        $d = base64_decode(strtr($s, '-_', '+/'), false);
        return $d === false ? '' : $d;
    }

    private function findJwk(array $doc, string $kid): ?array {
        foreach ($doc['keys'] ?? [] as $k) {
            if (!is_array($k) || ($k['kid'] ?? null) !== $kid) {
                continue;
            }
            if (isset($k['use']) && $k['use'] !== 'sig') {
                continue;
            }
            foreach (self::PRIVATE_JWK_MEMBERS as $m) {
                if (array_key_exists($m, $k)) {
                    continue 2;
                }
            }
            return $k;
        }
        return null;
    }

    protected function now(): int {
        return time();
    }

    /**
     * The issuer's JWKS, at the jwks_uri its discovery document names. Cached for $jwksTtl
     * seconds. $force (an unknown kid) bypasses the cache, but only once per
     * JWKS_MIN_REFETCH_SECONDS. A failure is never cached.
     *
     * @throws AuthFIException if the JWKS cannot be fetched or parsed.
     */
    private function fetchJwks(bool $force = false): array {
        $now = $this->now();
        $age = $now - $this->jwksFetchedAt;
        if ($this->jwks !== null) {
            if (!$force && $age < $this->jwksTtl) {
                return $this->jwks;
            }
            if ($force && $age < self::JWKS_MIN_REFETCH_SECONDS) {
                return $this->jwks;
            }
        }
        $doc = $this->fetchJson($this->discoverJwksUri($now));
        if (!isset($doc['keys']) || !is_array($doc['keys'])) {
            throw new AuthFIException('Invalid JWKS response', 401);
        }
        $this->jwks = $doc;
        $this->jwksFetchedAt = $now;
        return $doc;
    }

    /**
     * The jwks_uri from <issuer>/.well-known/openid-configuration, falling back to
     * oauth-authorization-server. The document's issuer must equal ours.
     */
    private function discoverJwksUri(int $now): string {
        if ($this->jwksUri !== null && ($now - $this->jwksUriFetchedAt) < $this->jwksTtl) {
            return $this->jwksUri;
        }
        $doc = null;
        foreach (['openid-configuration', 'oauth-authorization-server'] as $name) {
            try {
                $candidate = $this->fetchJson("{$this->issuer}/.well-known/{$name}");
                if ($candidate !== [] && !array_is_list($candidate)) {
                    $doc = $candidate;
                    break;
                }
            } catch (AuthFIException $e) {
                continue;
            }
        }
        if ($doc === null) {
            throw new AuthFIException('Discovery failed', 401);
        }
        if (($doc['issuer'] ?? null) !== $this->issuer) {
            throw new AuthFIException('Discovery issuer mismatch', 401);
        }
        $uri = $doc['jwks_uri'] ?? null;
        $u = is_string($uri) ? parse_url($uri) : false;
        // Plain http is allowed only for a loopback jwks_uri of a loopback http issuer, so a remote
        // issuer cannot point the SDK at a service on this host.
        $localHttp = is_array($u) && ($u['scheme'] ?? '') === 'http' && $this->isLoopback($u['host'] ?? '')
            && str_starts_with($this->issuer, 'http://');
        if (!is_array($u) || !isset($u['scheme'], $u['host']) || !($u['scheme'] === 'https' || $localHttp)) {
            throw new AuthFIException('Discovery document has no valid jwks_uri', 401);
        }
        $this->jwksUri = $uri;
        $this->jwksUriFetchedAt = $now;
        return $uri;
    }

    private function fetchJson(string $url): array {
        [$status, $body] = $this->httpGet($url);
        if ($status !== 200) {
            throw new AuthFIException("Fetch failed: HTTP $status", 401);
        }
        $data = json_decode($body, true);
        if (!is_array($data)) {
            throw new AuthFIException('Fetch failed: not JSON', 401);
        }
        return $data;
    }

    /**
     * One GET: no redirects followed, bounded time and size.
     *
     * @return array{0:int,1:string} status and body
     */
    protected function httpGet(string $url): array {
        $ch = curl_init($url);
        $body = '';
        $tooLarge = false;
        curl_setopt_array($ch, [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
            // The edge refuses requests that carry no recognisable User-Agent.
            CURLOPT_USERAGENT => 'authfi-php/' . self::VERSION . ' (php ' . PHP_VERSION . ')',
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
            CURLOPT_WRITEFUNCTION => function ($ch, $chunk) use (&$body, &$tooLarge) {
                $body .= $chunk;
                if (strlen($body) > self::MAX_DOC_BYTES) {
                    $tooLarge = true;
                    return -1;
                }
                return strlen($chunk);
            },
        ]);
        $ok = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($tooLarge) {
            throw new AuthFIException('Fetch failed: response too large', 401);
        }
        if ($ok === false) {
            throw new AuthFIException('Fetch failed: transport error', 401);
        }
        return [$status, $body];
    }

    /**
     * Check ALL permissions are present.
     */
    public function requirePermissions(object $claims, array $permissions): void {
        $userPerms = $claims->permissions ?? [];
        $missing = array_diff($permissions, $userPerms);

        foreach ($permissions as $p) {
            $this->registerPermission($p);
        }

        if (!empty($missing)) {
            throw new AuthFIException('Missing permissions: ' . implode(', ', $missing), 403);
        }
    }

    /**
     * Check ANY role matches.
     */
    public function requireRole(object $claims, array $roles): void {
        $userRoles = $claims->roles ?? [];
        foreach ($roles as $r) {
            if (in_array($r, $userRoles)) return;
        }
        throw new AuthFIException('Insufficient role', 403);
    }

    public function registerPermission(string $name, ?string $description = null): void {
        $this->registeredPermissions[$name] = $description;
    }

    /**
     * Sync registered permissions with AuthFI. Call on deployment/startup.
     */
    public function sync(): void {
        if (empty($this->registeredPermissions)) return;
        $apiKey = self::$apiKeys[$this->keyHolder] ?? null;
        if ($apiKey === null || $apiKey === '') {
            throw new AuthFIException('apiKey is required to sync permissions', 500);
        }

        $perms = [];
        foreach ($this->registeredPermissions as $name => $desc) {
            $p = ['name' => $name];
            if ($desc) $p['description'] = $desc;
            $perms[] = $p;
        }

        $body = ['permissions' => $perms];
        if ($this->applicationId) $body['application_id'] = $this->applicationId;

        // No /manage/ prefix exists on the platform; those routes are /v1/*.
        $url = "{$this->apiUrl}/{$this->tenant}/v1/permissions/sync";
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_CUSTOMREQUEST => 'PUT',
            CURLOPT_POSTFIELDS => json_encode($body),
            CURLOPT_HTTPHEADER => [
                'X-API-Key: ' . $apiKey,
                'Content-Type: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
        ]);

        $response = curl_exec($ch);
        $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($status < 400) {
            $data = json_decode($response);
            error_log("[authfi] Synced {$data->synced} permissions ({$data->total} total)");
        } else {
            error_log("[authfi] Sync failed: HTTP $status");
        }
    }

    private function extractToken($request): ?string {
        // Laravel Request
        if ($request && method_exists($request, 'bearerToken')) {
            return $request->bearerToken();
        }
        // Raw PHP
        $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (str_starts_with($auth, 'Bearer ')) {
            return substr($auth, 7);
        }
        return null;
    }
}

class AuthFIException extends \RuntimeException {
    public int $status;
    public function __construct(string $message, int $status = 401) {
        parent::__construct($message);
        $this->status = $status;
    }
}
