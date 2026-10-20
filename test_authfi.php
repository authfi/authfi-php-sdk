<?php
/**
 * AuthFI PHP SDK Tests
 * Run: php test_authfi.php
 *
 * Requires Composer deps (firebase/php-jwt) and the openssl, sodium and curl extensions:
 *   composer install
 *
 * Tokens are signed here with openssl and sodium directly, independent of the SDK's own
 * verification code. Discovery and the JWKS are served by an in-memory fake that answers
 * 404 for every URL the platform does not serve, so a wrong URL fails exactly as it does
 * live.
 */

if (is_file(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}
require_once __DIR__ . '/AuthFI.php';

use Firebase\JWT\JWT;

$passed = 0;
$failed = 0;

function test($name, $fn) {
    global $passed, $failed;
    try {
        $fn();
        echo "  ✓ $name\n";
        $passed++;
    } catch (Throwable $e) {
        echo "  ✗ $name — {$e->getMessage()}\n";
        $failed++;
    }
}

function assert_eq($expected, $actual, $msg = '') {
    if ($expected !== $actual) {
        throw new RuntimeException("Expected " . var_export($expected, true) . ", got " . var_export($actual, true) . " $msg");
    }
}

function assert_not_contains(string $needle, string $haystack, string $msg = '') {
    if (str_contains($haystack, $needle)) {
        throw new RuntimeException("Output contains the secret $msg");
    }
}

function assert_throws($class, $fn) {
    try {
        $fn();
    } catch (\Throwable $e) {
        if (!($e instanceof $class)) {
            throw new RuntimeException("Expected $class, got " . get_class($e) . ": " . $e->getMessage());
        }
        return $e;
    }
    throw new RuntimeException("Expected $class to be thrown");
}

function refused(callable $fn, ?string $message = null): AuthFIException {
    $e = assert_throws(AuthFIException::class, $fn);
    assert_eq(401, $e->status);
    if ($message !== null) assert_eq($message, $e->getMessage());
    return $e;
}

const ISSUER = 'https://acme.authfi.io';
const JWKS_URI = 'https://acme.authfi.io/oauth/jwks';
const AUDIENCE = 'app_acme';
const SECRET = 'sk_live_SECRET_VALUE_123';

function b64url(string $bin): string {
    return rtrim(strtr(base64_encode($bin), '+/', '-_'), '=');
}

function rsa_key(int $bits = 2048): array {
    $res = openssl_pkey_new(['private_key_bits' => $bits, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($res, $pem);
    return [$pem, openssl_pkey_get_details($res)['rsa']];
}

function rsa_jwk(array $rsa, string $kid, array $extra = []): array {
    return $extra + ['kty' => 'RSA', 'kid' => $kid, 'use' => 'sig', 'alg' => 'RS256',
        'n' => b64url($rsa['n']), 'e' => b64url($rsa['e'])];
}

function ed_key(): array {
    $kp = sodium_crypto_sign_keypair();
    return [sodium_crypto_sign_secretkey($kp), sodium_crypto_sign_publickey($kp)];
}

function ed_jwk(string $pub, string $kid, array $extra = []): array {
    return $extra + ['kty' => 'OKP', 'crv' => 'Ed25519', 'kid' => $kid, 'use' => 'sig', 'x' => b64url($pub)];
}

[$RS_PEM, $RS_RSA] = rsa_key();
[$ATTACKER_PEM, $ATTACKER_RSA] = rsa_key();
[$SMALL_PEM, $SMALL_RSA] = rsa_key(1024);
[$ED_SECRET, $ED_PUBLIC] = ed_key();
[$ATTACKER_ED, ] = ed_key();

function jwks(array $extra = []): array {
    global $RS_RSA, $ED_PUBLIC;
    return ['keys' => array_merge([rsa_jwk($RS_RSA, 'rs-1'), ed_jwk($ED_PUBLIC, 'ed-1')], $extra)];
}

function claims(array $over = []): array {
    return $over + ['sub' => 'usr_123', 'iss' => ISSUER, 'aud' => [AUDIENCE], 'tenant_id' => 't1',
        'roles' => ['admin', 'editor'], 'permissions' => ['read:users', 'write:users'],
        'iat' => time(), 'exp' => time() + 3600];
}

/** Sign by hand; $alg is written into the header and the signature made with $alg's primitive. */
function hand(array $claims, string $alg, $secret, string $kid, ?string $typ = 'at+jwt', array $headerExtra = []): string {
    $header = ['alg' => $alg, 'kid' => $kid] + $headerExtra;
    if ($typ !== null) $header['typ'] = $typ;
    $input = b64url(json_encode($header)) . '.' . b64url(json_encode($claims));
    if ($alg === 'EdDSA') {
        $sig = sodium_crypto_sign_detached($input, $secret);
    } elseif ($alg === 'HS256') {
        $sig = hash_hmac('sha256', $input, $secret, true);
    } else {
        openssl_sign($input, $sig, $secret, OPENSSL_ALGO_SHA256);
    }
    return $input . '.' . b64url($sig);
}

function rs256(array $claims, ?string $pem = null, string $kid = 'rs-1', ?string $typ = 'at+jwt'): string {
    global $RS_PEM;
    return hand($claims, 'RS256', $pem ?? $RS_PEM, $kid, $typ);
}

function eddsa(array $claims, ?string $secret = null, string $kid = 'ed-1', ?string $typ = 'at+jwt'): string {
    global $ED_SECRET;
    return hand($claims, 'EdDSA', $secret ?? $ED_SECRET, $kid, $typ);
}

/** The SDK with its HTTP seam and clock replaced. */
class TestAuthFI extends AuthFI {
    /** @var callable */
    public $web;
    public array $calls = [];
    public ?int $clock = null;
    protected function httpGet(string $url): array {
        $this->calls[] = $url;
        return ($this->web)($url);
    }
    protected function now(): int {
        return $this->clock ?? time();
    }
}

/** A fake of the platform's HTTP surface: only the listed URLs exist. */
function fake_web(array $routes): callable {
    return function (string $url) use (&$routes) {
        $r = $routes[$url] ?? null;
        if (is_callable($r)) $r = $r();
        if ($r === null) return [404, 'not found'];
        return [200, is_string($r) ? $r : json_encode($r)];
    };
}

function platform(?array $jwks = null, ?array $doc = null, string $docPath = 'openid-configuration'): callable {
    return fake_web([
        ISSUER . "/.well-known/$docPath" => $doc ?? ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI],
        JWKS_URI => $jwks ?? jwks(),
    ]);
}

function client(array $opts = [], ?callable $web = null): TestAuthFI {
    $opts = $opts + ['tenant' => 'acme', 'audience' => AUDIENCE];
    $a = new TestAuthFI(...$opts);
    $a->web = $web ?? platform();
    return $a;
}

function verify(string $token, array $opts = [], ?callable $web = null) {
    return client($opts, $web)->verifyToken($token);
}

echo "\nAuthFI PHP SDK Tests\n";
echo str_repeat('=', 40) . "\n\n";

echo "Discovery:\n";
test('the JWKS comes from discovery, not a built URL', function() {
    $a = client();
    $c = $a->verifyToken(rs256(claims()));
    assert_eq('usr_123', $c->sub);
    assert_eq([ISSUER . '/.well-known/openid-configuration', JWKS_URI], $a->calls);
});

test('falls back to oauth-authorization-server', function() {
    $c = verify(rs256(claims()), [], platform(docPath: 'oauth-authorization-server'));
    assert_eq('usr_123', $c->sub);
});

test('refuses a discovery document whose issuer is another', function() {
    refused(fn() => verify(rs256(claims()), [], platform(doc: ['issuer' => 'https://evil.example.com', 'jwks_uri' => JWKS_URI])));
});

test('refuses a discovery document without a jwks_uri', function() {
    refused(fn() => verify(rs256(claims()), [], platform(doc: ['issuer' => ISSUER])));
});

test('refuses a plain-http jwks_uri', function() {
    refused(fn() => verify(rs256(claims()), [], platform(doc: ['issuer' => ISSUER, 'jwks_uri' => 'http://acme.authfi.io/jwks'])));
});

test('a failed fetch is not cached', function() {
    $up = false;
    $a = client([], fake_web([
        ISSUER . '/.well-known/openid-configuration' => function() use (&$up) { return $up ? ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI] : null; },
        JWKS_URI => function() use (&$up) { return $up ? jwks() : null; },
    ]));
    $t = rs256(claims());
    refused(fn() => $a->verifyToken($t));
    $up = true;
    assert_eq('usr_123', $a->verifyToken($t)->sub);
});

test('a custom issuer drives discovery', function() {
    $iss = 'https://login.example.com';
    $web = fake_web([
        "$iss/.well-known/openid-configuration" => ['issuer' => $iss, 'jwks_uri' => "$iss/keys"],
        "$iss/keys" => jwks(),
    ]);
    assert_eq('usr_123', verify(rs256(claims(['iss' => $iss])), ['issuer' => $iss], $web)->sub);
});

test('the issuer must be https with no path, query or trailing slash', function() {
    foreach (['http://acme.authfi.io', 'https://acme.authfi.io/', 'https://acme.authfi.io/x', 'https://a.io?x=1', 'nonsense'] as $bad) {
        assert_throws(InvalidArgumentException::class, fn() => new AuthFI('acme', null, issuer: $bad));
    }
    new AuthFI('acme', null, issuer: 'http://localhost:8080');
});

test('the JWKS is cached between calls', function() {
    $a = client();
    $t = rs256(claims());
    for ($i = 0; $i < 3; $i++) $a->verifyToken($t);
    assert_eq(2, count($a->calls));
});

test('invented kids cause no refetch inside the window', function() {
    $a = client();
    $a->verifyToken(rs256(claims()));
    for ($i = 0; $i < 10; $i++) {
        refused(fn() => $a->verifyToken(rs256(claims(), null, "invented-$i")));
    }
    assert_eq(2, count($a->calls), 'invented kids must not refetch the JWKS');
});

test('an unknown kid refetches once after the window, picking up a rotated key', function() {
    global $ATTACKER_PEM, $ATTACKER_RSA;
    $routes = [
        ISSUER . '/.well-known/openid-configuration' => ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI],
        JWKS_URI => jwks(),
    ];
    $a = client([], function ($url) use (&$routes) {
        $r = $routes[$url] ?? null;
        return $r === null ? [404, ''] : [200, json_encode($r)];
    });
    $a->clock = time();
    $a->verifyToken(rs256(claims()));
    $routes[JWKS_URI] = jwks([rsa_jwk($ATTACKER_RSA, 'rs-2')]);
    $a->clock = time() + AuthFI::JWKS_MIN_REFETCH_SECONDS + 1;
    $t = rs256(claims(['exp' => time() + 7200]), $ATTACKER_PEM, 'rs-2');
    assert_eq('usr_123', $a->verifyToken($t)->sub);
});

/** Starts `php -S` with a router script for one test; returns [process, port, router path]. */
function serve(string $mode): array {
    $router = sys_get_temp_dir() . '/authfi-router-' . bin2hex(random_bytes(4)) . '.php';
    file_put_contents($router, <<<'PHP'
<?php
$base = 'http://127.0.0.1:' . $_SERVER['SERVER_PORT'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
file_put_contents(sys_get_temp_dir() . '/authfi-ua-' . $_SERVER['SERVER_PORT'], ($_SERVER['HTTP_USER_AGENT'] ?? '') . '|' . ($_SERVER['HTTP_ACCEPT'] ?? ''));
$mode = getenv('MODE');
header('Content-Type: application/json');
if ($mode === 'redirect' && $path === '/.well-known/openid-configuration') { header('Location: ' . $base . '/real-discovery', true, 302); exit; }
if ($path === '/real-discovery' || $path === '/.well-known/openid-configuration') {
    $doc = ['issuer' => $base, 'jwks_uri' => $base . '/jwks'];
    if ($mode === 'huge') { $doc['pad'] = str_repeat('x', 300000); }
    if ($mode === 'exact' || $mode === 'over') {
        $doc['pad'] = '';
        $doc['pad'] = str_repeat('x', 262144 - strlen(json_encode($doc)) + ($mode === 'over' ? 1 : 0));
    }
    echo json_encode($doc); exit;
}
if (str_ends_with($path, '/permissions/sync') && $mode === 'syncfail') { http_response_code(500); echo 'echo ' . getenv('ECHO'); exit; }
if ($path === '/jwks') { echo getenv('JWKS'); exit; }
http_response_code(404);
PHP);
    for ($try = 0; $try < 20; $try++) {
        $port = random_int(20000, 60000);
        $proc = proc_open(
            [PHP_BINARY, '-S', "127.0.0.1:$port", $router],
            [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes,
            null,
            ['MODE' => $mode, 'JWKS' => json_encode(jwks()), 'ECHO' => SECRET]
        );
        for ($i = 0; $i < 50; $i++) {
            $s = @fsockopen('127.0.0.1', $port, $en, $es, 0.1);
            if ($s) { fclose($s); return [$proc, $port, $router]; }
            usleep(50000);
        }
        proc_terminate($proc);
    }
    throw new RuntimeException('could not start a loopback server');
}

function stop(array $srv): void {
    proc_terminate($srv[0]);
    proc_close($srv[0]);
    @unlink($srv[2]);
}

test('real HTTP follows the discovery document', function() {
    $srv = serve('ok');
    try {
        $iss = "http://127.0.0.1:{$srv[1]}";
        $a = new AuthFI('acme', null, issuer: $iss, audience: AUDIENCE);
        assert_eq('usr_123', $a->verifyToken(rs256(claims(['iss' => $iss])))->sub);
        $ua = (string) @file_get_contents(sys_get_temp_dir() . "/authfi-ua-{$srv[1]}");
        assert_eq(1, preg_match('#^authfi-php/\d+\.\d+\.\d+ \(php [^|]+\|application/json$#', $ua), "user agent and accept were '$ua'");
    } finally { stop($srv); @unlink(sys_get_temp_dir() . "/authfi-ua-{$srv[1]}"); }
});

test('real HTTP does not follow redirects', function() {
    $srv = serve('redirect');
    try {
        $iss = "http://127.0.0.1:{$srv[1]}";
        $a = new AuthFI('acme', null, issuer: $iss, audience: AUDIENCE);
        refused(fn() => $a->verifyToken(rs256(claims(['iss' => $iss]))));
    } finally { stop($srv); }
});

test('real HTTP refuses an oversize document', function() {
    $srv = serve('huge');
    try {
        $iss = "http://127.0.0.1:{$srv[1]}";
        $a = new AuthFI('acme', null, issuer: $iss, audience: AUDIENCE);
        refused(fn() => $a->verifyToken(rs256(claims(['iss' => $iss]))));
    } finally { stop($srv); }
});

echo "\nAlgorithms:\n";
test('accepts an RS256 user token', function() {
    assert_eq(['admin', 'editor'], verify(rs256(claims()))->roles);
});

test('accepts an EdDSA agent token', function() {
    assert_eq('agt_1', verify(eddsa(claims(['sub' => 'agt_1', 'aud' => AUDIENCE])))->sub);
});

test('rejects EdDSA signed by another key', function() {
    global $ATTACKER_ED;
    refused(fn() => verify(eddsa(claims(), $ATTACKER_ED)));
});

test('rejects RS256 signed by another key', function() {
    global $ATTACKER_PEM;
    refused(fn() => verify(rs256(claims(), $ATTACKER_PEM)));
});

test('rejects a tampered payload', function() {
    [$h, , $s] = explode('.', rs256(claims(['permissions' => ['read:users']])));
    $forged = b64url(json_encode(claims(['permissions' => ['delete:users']])));
    refused(fn() => verify("$h.$forged.$s"));
});

test('rejects none, HS256, ES256 and PS256 before any key lookup', function() {
    foreach (['none', 'HS256', 'ES256', 'PS256'] as $alg) {
        $h = b64url(json_encode(['alg' => $alg, 'typ' => 'at+jwt', 'kid' => 'rs-1']));
        $t = "$h." . b64url(json_encode(claims())) . '.' . b64url('sig');
        $a = client();
        refused(fn() => $a->verifyToken($t), 'Unsupported token algorithm');
        assert_eq([], $a->calls, "$alg must be refused before fetching keys");
    }
});

test('an HS256 token signed with the public key as secret is refused', function() {
    global $RS_RSA;
    $secret = json_encode(rsa_jwk($RS_RSA, 'rs-1')) . str_repeat('x', 32);
    $t = hand(claims(), 'HS256', $secret, 'rs-1');
    refused(fn() => verify($t));
});

test('an RS256 header with an Ed25519 key is refused', function() {
    refused(fn() => verify(rs256(claims(), null, 'ed-1')));
});

test('an EdDSA header with an RSA key is refused', function() {
    refused(fn() => verify(eddsa(claims(), null, 'rs-1')));
});

test('a key whose declared alg disagrees is refused', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($RS_RSA, 'rs-1', ['alg' => 'PS256'])]])));
});

test('a key without alg is judged by its type', function() {
    global $RS_RSA;
    $jwk = rsa_jwk($RS_RSA, 'rs-1');
    unset($jwk['alg']);
    assert_eq('usr_123', verify(rs256(claims()), [], platform(['keys' => [$jwk]]))->sub);
});

test('keys carrying private members are ignored', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($RS_RSA, 'rs-1', ['d' => 'AQAB'])]])));
});

test('encryption keys are ignored', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($RS_RSA, 'rs-1', ['use' => 'enc'])]])));
});

test('RSA keys under 2048 bits are refused', function() {
    global $SMALL_RSA;
    // Signing with a sub-2048 key is itself refused by hardened OpenSSL builds, so the JWKS
    // advertises the small key under the kid and the refusal must be the size refusal.
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($SMALL_RSA, 'rs-1')]])), 'Signing key does not match token algorithm');
});

test('keys carrying p, q or k members are ignored', function() {
    global $RS_RSA;
    foreach (['p', 'q', 'dp', 'dq', 'qi', 'k'] as $m) {
        refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($RS_RSA, 'rs-1', [$m => 'AQAB'])]])), 'Unknown signing key');
    }
});

test('a non-200 answer is never used even when its body is valid', function() {
    $web = function (string $url) {
        return str_ends_with($url, 'openid-configuration')
            ? [200, json_encode(['issuer' => ISSUER, 'jwks_uri' => JWKS_URI])]
            : [500, json_encode(jwks())];
    };
    refused(fn() => verify(rs256(claims()), [], $web));
});

test('a plain-http jwks_uri is refused even when it answers', function() {
    $http = 'http://acme.authfi.io/oauth/jwks';
    $web = fake_web([
        ISSUER . '/.well-known/openid-configuration' => ['issuer' => ISSUER, 'jwks_uri' => $http],
        $http => jwks(),
    ]);
    refused(fn() => verify(rs256(claims()), [], $web), 'Discovery document has no valid jwks_uri');
});

test('a token over the size cap is refused even when validly signed', function() {
    refused(fn() => verify(rs256(claims(['pad' => str_repeat('x', AuthFI::MAX_TOKEN_BYTES + 1)]))));
    assert_eq('usr_123', verify(rs256(claims()))->sub);
});

test('a signature in the standard base64 alphabet is refused', function() {
    do {
        $t = rs256(claims());
        [$h, $p, $s] = explode('.', $t);
    } while (!preg_match('/[-_]/', $s));
    refused(fn() => verify("$h.$p." . strtr($s, '-_', '+/')));
});

test('a kid is required', function() {
    global $RS_PEM;
    $h = b64url(json_encode(['alg' => 'RS256', 'typ' => 'at+jwt']));
    $p = b64url(json_encode(claims()));
    openssl_sign("$h.$p", $sig, $RS_PEM, OPENSSL_ALGO_SHA256);
    refused(fn() => verify("$h.$p." . b64url($sig)));
});

test('an unknown critical header is refused', function() {
    global $RS_PEM;
    refused(fn() => verify(hand(claims(), 'RS256', $RS_PEM, 'rs-1', 'at+jwt', ['crit' => ['x'], 'x' => 1])));
});

test('rejects malformed tokens', function() {
    foreach (['not-a-jwt', 'a.b', 'a.b.c.d', '..', '', 'a..c', str_repeat('a', 20000) . '.b.c'] as $bad) {
        refused(fn() => client()->verifyToken($bad));
    }
});

echo "\nAccess tokens only:\n";
test('refuses an ID token offered as an access token', function() {
    $idToken = rs256(claims(['nonce' => 'n', 'at_hash' => 'h']), null, 'rs-1', 'JWT');
    refused(fn() => verify($idToken), 'Token is not an access token');
});

test('refuses a token with no typ', function() {
    refused(fn() => verify(rs256(claims(), null, 'rs-1', null)));
});

test('refuses other typed tokens', function() {
    foreach (['secevent+jwt', 'txn_token+jwt'] as $typ) {
        refused(fn() => verify(eddsa(claims(), null, 'ed-1', $typ)));
    }
});

test('accepts the application form and any case', function() {
    foreach (['application/at+jwt', 'AT+JWT', 'Application/At+Jwt'] as $typ) {
        assert_eq('usr_123', verify(rs256(claims(), null, 'rs-1', $typ))->sub);
    }
});

echo "\nClaims:\n";
test('rejects the wrong issuer', function() {
    refused(fn() => verify(rs256(claims(['iss' => 'https://evil.example.com']))), 'Invalid token issuer');
});

test('rejects a token with no issuer', function() {
    $c = claims();
    unset($c['iss']);
    refused(fn() => verify(rs256($c)));
});

test('rejects the wrong audience', function() {
    refused(fn() => verify(rs256(claims(['aud' => ['app_other']]))), 'Invalid token audience');
});

test('rejects a token with no audience', function() {
    $c = claims();
    unset($c['aud']);
    refused(fn() => verify(rs256($c)));
});

test('accepts aud as a string or an array when one matches', function() {
    verify(rs256(claims(['aud' => AUDIENCE])));
    verify(rs256(claims(['aud' => ['x', AUDIENCE]])));
});

test('several configured audiences', function() {
    verify(rs256(claims(['aud' => ['app_b']])), ['audience' => [AUDIENCE, 'app_b']]);
});

test('refuses every token when no audience is configured', function() {
    refused(fn() => verify(rs256(claims()), ['audience' => null]), 'Token audience not configured');
});

test("AuthFI's own audience is a configuration error", function() {
    foreach ([ISSUER, ISSUER . '/mcp', ISSUER . '/anything'] as $a) {
        assert_throws(InvalidArgumentException::class, fn() => new AuthFI('acme', null, audience: $a));
    }
});

test('rejects an expired token', function() {
    refused(fn() => verify(rs256(claims(['exp' => time() - 3600]))), 'Token expired');
});

test('rejects a token with no expiry', function() {
    $c = claims();
    unset($c['exp']);
    refused(fn() => verify(rs256($c)));
});

test('rejects a token whose expiry is not a number', function() {
    refused(fn() => verify(rs256(claims(['exp' => 'never']))));
});

test('leeway tolerates small clock skew only', function() {
    verify(rs256(claims(['exp' => time() - 10])));
    refused(fn() => verify(rs256(claims(['exp' => time() - 120]))));
    refused(fn() => verify(rs256(claims(['exp' => time() - 10])), ['leeway' => 0]));
});

test('rejects a not-yet-valid token', function() {
    refused(fn() => verify(rs256(claims(['nbf' => time() + 600]))));
    refused(fn() => verify(rs256(claims(['iat' => time() + 600]))));
});

test('verifying leaves the global leeway as it was', function() {
    JWT::$leeway = 7;
    verify(rs256(claims()));
    assert_eq(7, JWT::$leeway);
    JWT::$leeway = 0;
});

test('rejects a token with no subject', function() {
    $c = claims();
    unset($c['sub']);
    refused(fn() => verify(rs256($c)));
});

test('a JWKS failure never passes a token', function() {
    refused(fn() => verify(rs256(claims()), [], fn() => [500, 'boom']));
});

echo "\nNo secret in output:\n";
test('print_r, var_dump, var_export and json hide the api key', function() {
    $a = new AuthFI('acme', SECRET, audience: AUDIENCE);
    ob_start();
    var_dump($a);
    print_r($a);
    echo var_export($a, true), json_encode($a), json_encode((array) $a);
    $out = ob_get_clean();
    assert_not_contains(SECRET, $out);
});

test('cannot be serialized', function() {
    assert_throws(LogicException::class, fn() => serialize(new AuthFI('acme', SECRET)));
});

test('refusals never echo the token', function() {
    $t = rs256(claims(['aud' => ['app_other']]));
    $e = refused(fn() => verify($t));
    assert_not_contains($t, $e->getMessage());
    assert_not_contains(explode('.', $t)[1], $e->getMessage());
});

function trace_strings(Throwable $e): array {
    $out = [];
    foreach ($e->getTrace() as $frame) {
        // Only the SDK's own frames: a test helper that takes the token as an argument shows it.
        if (!in_array($frame['class'] ?? '', ['AuthFI', 'TestAuthFI'], true)) continue;
        foreach ($frame['args'] ?? [] as $arg) {
            if (is_string($arg)) $out[] = $arg;
        }
    }
    return $out;
}

test('a stack trace does not carry the token or the api key', function() {
    if (PHP_VERSION_ID < 80200) return; // #[SensitiveParameter] arrived in PHP 8.2
    ini_set('zend.exception_ignore_args', '0');
    $t = rs256(claims(['aud' => ['app_other']]));
    $e = refused(fn() => verify($t));
    assert_eq([], array_values(array_filter(trace_strings($e), fn($a) => str_starts_with($a, 'eyJ'))));
    try {
        new AuthFI('acme', SECRET, issuer: 'nonsense');
    } catch (InvalidArgumentException $ex) {
        assert_eq([], array_values(array_filter(trace_strings($ex), fn($a) => $a === SECRET)));
        return;
    }
    throw new RuntimeException('expected the constructor to throw');
});

test('a failed sync does not log the response body or the key', function() {
    $srv = serve('syncfail');
    $log = sys_get_temp_dir() . '/authfi-log-' . bin2hex(random_bytes(4));
    $prev = ini_set('error_log', $log);
    try {
        $a = new AuthFI('acme', SECRET, "http://127.0.0.1:{$srv[1]}", audience: AUDIENCE);
        $a->registerPermission('read:users');
        $a->sync();
        $logged = (string) @file_get_contents($log);
        assert_not_contains(SECRET, $logged);
        assert_eq(true, str_contains($logged, 'HTTP 500'), 'the failure is still reported');
    } finally {
        ini_set('error_log', $prev === false ? '' : $prev);
        @unlink($log);
        stop($srv);
    }
});

test('sync requires an api key', function() {
    $a = new AuthFI('acme');
    $a->registerPermission('read:users');
    assert_throws(AuthFIException::class, fn() => $a->sync());
});

echo "\nAuthentication:\n";
test('rejects a missing auth header', function() {
    unset($_SERVER['HTTP_AUTHORIZATION']);
    refused(fn() => client()->authenticate());
});

test('reads the bearer token from the request', function() {
    $_SERVER['HTTP_AUTHORIZATION'] = 'Bearer ' . rs256(claims());
    assert_eq('usr_123', client()->authenticate()->sub);
    unset($_SERVER['HTTP_AUTHORIZATION']);
});

echo "\nPermission checks:\n";
test('passes with matching permissions', function() {
    client()->requirePermissions((object)['permissions' => ['read:users', 'write:users']], ['read:users']);
});

test('raises on a missing permission', function() {
    $e = assert_throws(AuthFIException::class, fn() => client()->requirePermissions((object)['permissions' => ['read:users']], ['delete:users']));
    assert_eq(403, $e->status);
});

test('handles empty permissions', function() {
    assert_throws(AuthFIException::class, fn() => client()->requirePermissions((object)[], ['read:users']));
});

echo "\nRole checks:\n";
test('passes with a matching role', function() {
    client()->requireRole((object)['roles' => ['editor']], ['admin', 'editor']);
});

test('raises on a missing role', function() {
    $e = assert_throws(AuthFIException::class, fn() => client()->requireRole((object)['roles' => ['viewer']], ['admin']));
    assert_eq(403, $e->status);
});

test('handles empty roles', function() {
    assert_throws(AuthFIException::class, fn() => client()->requireRole((object)[], ['admin']));
});

echo "\nSync and exception:\n";
test('sync with nothing registered is a no-op', function() {
    (new AuthFI('acme', 'k'))->sync();
});

test('exception statuses', function() {
    assert_eq(401, (new AuthFIException('t'))->status);
    assert_eq(403, (new AuthFIException('t', 403))->status);
});

echo "\n" . str_repeat('=', 40) . "\n";
echo "\nReview r1 additions:\n";
test('r1: iss that merely starts with the issuer is refused', function() {
    refused(fn() => verify(rs256(claims(['iss' => ISSUER . '/x']))));
});
test('r1: iss true is refused (no loose comparison)', function() {
    refused(fn() => verify(rs256(claims(['iss' => true]))));
});
test('r1: a discovery issuer of true is refused', function() {
    refused(fn() => verify(rs256(claims()), [], platform(doc: ['issuer' => true, 'jwks_uri' => JWKS_URI])));
});
test('r1: empty and non-string sub are refused', function() {
    refused(fn() => verify(rs256(claims(['sub' => '']))));
    refused(fn() => verify(rs256(claims(['sub' => 123]))));
});
test('r1: an empty-string audience accepts nothing', function() {
    refused(fn() => verify(rs256(claims(['aud' => ['']])), ['audience' => '']));
});
test('r1: aud entries that are not strings never match', function() {
    refused(fn() => verify(rs256(claims(['aud' => [true]])), ['audience' => '1']));
});
test('r1: a float exp is accepted', function() {
    assert_eq('usr_123', verify(rs256(claims(['exp' => time() + 3600.5])))->sub);
});
test('r1: an issuer with a fragment or userinfo is a configuration error', function() {
    foreach (['https://acme.authfi.io#f', 'https://u@acme.authfi.io'] as $bad) {
        assert_throws(InvalidArgumentException::class, fn() => new AuthFI('acme', null, issuer: $bad));
    }
});
test('r1: a header that is JSON but not an object is an AuthFIException', function() {
    foreach (['"x"', 'null', '1', '[]', 'true'] as $raw) {
        refused(fn() => verify(b64url($raw) . '.' . b64url('{}') . '.' . b64url('s')));
    }
});
test('r1: a key with only a d member is refused', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [rsa_jwk($RS_RSA, 'rs-1', ['d' => 'AQAB'])]])));
});
test('r1: a key without use is accepted', function() {
    global $RS_RSA;
    $j = rsa_jwk($RS_RSA, 'rs-1');
    unset($j['use']);
    assert_eq('usr_123', verify(rs256(claims()), [], platform(['keys' => [$j]]))->sub);
});
test('r1: kid must match exactly, not by prefix or numeric-string equality', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims(), null, 'rs')));
    refused(fn() => verify(rs256(claims(), null, '10'), [], platform(['keys' => [rsa_jwk($RS_RSA, '1e1')]])));
});
test('r1: an empty kid never matches a key', function() {
    global $RS_RSA;
    refused(fn() => verify(rs256(claims(), null, ''), [], platform(['keys' => [rsa_jwk($RS_RSA, '')]])));
});
test('r1: the cache expires after jwksTtl (boundary included) and rediscovers', function() {
    $a = client();
    $a->clock = 1000000;
    $t = rs256(claims());
    $a->verifyToken($t);
    $a->clock += 299;
    $a->verifyToken($t);
    assert_eq(2, count($a->calls));
    $a->clock += 1;                       // exactly jwksTtl
    $a->verifyToken($t);
    assert_eq(4, count($a->calls));
});
test('r1: an unknown kid refetches the JWKS (not discovery) at exactly the window', function() {
    $a = client();
    $a->clock = 1000000;
    $a->verifyToken(rs256(claims()));
    $a->clock += 29;
    refused(fn() => $a->verifyToken(rs256(claims(), null, 'nope')));
    assert_eq(2, count($a->calls));
    $a->clock += 1;                       // exactly 30 s
    refused(fn() => $a->verifyToken(rs256(claims(), null, 'nope')));
    assert_eq([ISSUER . '/.well-known/openid-configuration', JWKS_URI, JWKS_URI], $a->calls);
});
test('r1: a malformed JWKS is not cached', function() {
    $good = false;
    $a = client([], fake_web([
        ISSUER . '/.well-known/openid-configuration' => ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI],
        JWKS_URI => function() use (&$good) { return $good ? jwks() : ['nokeys' => 1]; },
    ]));
    $t = rs256(claims());
    refused(fn() => $a->verifyToken($t));
    $good = true;
    assert_eq('usr_123', $a->verifyToken($t)->sub);
});
test('r1: a non-200 answer is never used even with a valid body', function() {
    $web = platform();
    $a = client([], function ($url) use ($web) {
        return str_contains($url, '/.well-known/') ? [302, json_encode(['issuer' => ISSUER, 'jwks_uri' => JWKS_URI])] : $web($url);
    });
    refused(fn() => $a->verifyToken(rs256(claims())));
});
test('real HTTP accepts a document of exactly the size limit and refuses one byte more', function() {
    foreach (['exact' => true, 'over' => false] as $mode => $accepted) {
        $srv = serve($mode);
        try {
            $iss = "http://127.0.0.1:{$srv[1]}";
            $a = new AuthFI('acme', null, issuer: $iss, audience: AUDIENCE);
            if ($accepted) {
                assert_eq('usr_123', $a->verifyToken(rs256(claims(['iss' => $iss])))->sub);
            } else {
                refused(fn() => $a->verifyToken(rs256(claims(['iss' => $iss]))));
            }
        } finally { stop($srv); }
    }
});

test('r1: a signature failure says so', function() {
    global $ATTACKER_PEM;
    refused(fn() => verify(rs256(claims(), $ATTACKER_PEM)), 'Invalid token signature');
});
test('r1: a valid token of exactly the size limit is accepted', function() {
    $t = null;
    for ($pad = 11000; $pad < 12400 && !$t; $pad++) {
        $c = rs256(claims(['pad' => str_repeat('x', $pad)]));
        if (strlen($c) === AuthFI::MAX_TOKEN_BYTES) $t = $c;
    }
    assert_eq(true, $t !== null, 'size reachable');
    assert_eq('usr_123', verify($t)->sub);
    refused(fn() => verify($t . 'A'));
});
test('r1: a token followed by a newline is refused', function() {
    refused(fn() => verify(rs256(claims()) . "\n"));
});
test('r1: an OKP key of another curve is refused', function() {
    global $ED_PUBLIC;
    refused(fn() => verify(eddsa(claims()), [], platform(['keys' => [ed_jwk($ED_PUBLIC, 'ed-1', ['crv' => 'X25519'])]])));
});

echo "\nReview r1 fixes:\n";
test('the api key is in no property, cast or dump of the instance', function() {
    $a = new AuthFI('acme', SECRET, audience: AUDIENCE);
    $seen = [];
    // What a debug dumper sees: every property, and what a closure has captured.
    $walk = function ($v) use (&$walk, &$seen) {
        if (is_string($v)) { $seen[] = $v; return; }
        if ($v instanceof Closure) { $walk((new ReflectionFunction($v))->getStaticVariables()); return; }
        if (is_array($v)) { foreach ($v as $x) $walk($x); return; }
        if (is_object($v)) {
            foreach ((new ReflectionObject($v))->getProperties() as $p) {
                $p->setAccessible(true);
                if (!$p->isStatic() && $p->isInitialized($v)) $walk($p->getValue($v));
            }
        }
    };
    $walk($a);
    ob_start();
    debug_zval_dump($a);
    $seen[] = ob_get_clean();
    $seen[] = var_export((array) $a, true);
    $seen[] = var_export(get_object_vars($a), true);
    assert_not_contains(SECRET, implode("\n", $seen));
});

test('the api key still reaches sync', function() {
    $srv = serve('syncfail');
    $log = sys_get_temp_dir() . '/authfi-log-' . bin2hex(random_bytes(4));
    $prev = ini_set('error_log', $log);
    try {
        $a = new AuthFI('acme', SECRET, "http://127.0.0.1:{$srv[1]}", audience: AUDIENCE);
        $a->registerPermission('read:users');
        $a->sync();
        assert_eq(true, str_contains((string) @file_get_contents($log), 'HTTP 500'), 'sync reached the server with a key');
    } finally {
        ini_set('error_log', $prev === false ? '' : $prev);
        @unlink($log);
        stop($srv);
    }
});

test('an RSA key of 2047 bits is refused', function() {
    $n = chr(0x7f) . random_bytes(255);   // 2047 bits
    $jwk = ['kty' => 'RSA', 'kid' => 'rs-1', 'use' => 'sig', 'alg' => 'RS256', 'n' => b64url($n), 'e' => 'AQAB'];
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [$jwk]])), 'Signing key does not match token algorithm');
});

test('a plain-http loopback jwks_uri is refused for a remote https issuer', function() {
    $local = 'http://127.0.0.1:9/jwks';
    $web = fake_web([
        ISSUER . '/.well-known/openid-configuration' => ['issuer' => ISSUER, 'jwks_uri' => $local],
        $local => jwks(),
    ]);
    refused(fn() => verify(rs256(claims()), [], $web), 'Discovery document has no valid jwks_uri');
});

test("AuthFI's own audience is recognised after case and default-port normalisation", function() {
    foreach (['https://ACME.authfi.io/mcp', 'https://acme.authfi.io:443/mcp', 'HTTPS://acme.authfi.io'] as $a) {
        assert_throws(InvalidArgumentException::class, fn() => new AuthFI('acme', null, audience: $a));
    }
    new AuthFI('acme', null, audience: 'https://acme.authfi.io.evil.example/mcp');
});

test('a discovery answer that is not an object falls back to the next document', function() {
    $web = fake_web([
        ISSUER . '/.well-known/openid-configuration' => [],
        ISSUER . '/.well-known/oauth-authorization-server' => ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI],
        JWKS_URI => jwks(),
    ]);
    assert_eq('usr_123', verify(rs256(claims()), [], $web)->sub);
});

test('a clone keeps the api key', function() {
    $srv = serve('syncfail');
    $log = sys_get_temp_dir() . '/authfi-log-' . bin2hex(random_bytes(4));
    $prev = ini_set('error_log', $log);
    try {
        $a = new AuthFI('acme', SECRET, "http://127.0.0.1:{$srv[1]}", audience: AUDIENCE);
        $b = clone $a;
        unset($a);
        $b->registerPermission('read:users');
        $b->sync();
        assert_eq(true, str_contains((string) @file_get_contents($log), 'HTTP 500'), 'the clone reached the server with a key');
    } finally {
        ini_set('error_log', $prev === false ? '' : $prev);
        @unlink($log);
        stop($srv);
    }
});

test('leading zero bytes of the modulus do not count toward the 2048-bit floor', function() {
    global $RS_RSA;
    $padded = rsa_jwk($RS_RSA, 'rs-1', ['n' => b64url("\0\0" . $RS_RSA['n'])]);
    assert_eq('usr_123', verify(rs256(claims()), [], platform(['keys' => [$padded]]))->sub);
    $short = ['kty' => 'RSA', 'kid' => 'rs-1', 'use' => 'sig', 'alg' => 'RS256', 'n' => b64url("\0\0" . chr(0xff) . random_bytes(254)), 'e' => 'AQAB'];
    refused(fn() => verify(rs256(claims()), [], platform(['keys' => [$short]])), 'Signing key does not match token algorithm');
});

test('a discovery answer that is a non-empty list falls back to the next document', function() {
    $web = fake_web([
        ISSUER . '/.well-known/openid-configuration' => [1],
        ISSUER . '/.well-known/oauth-authorization-server' => ['issuer' => ISSUER, 'jwks_uri' => JWKS_URI],
        JWKS_URI => jwks(),
    ]);
    assert_eq('usr_123', verify(rs256(claims()), [], $web)->sub);
});

test('a non-loopback http jwks_uri is refused even for a loopback issuer', function() {
    $iss = 'http://127.0.0.1:8080';
    $web = fake_web([
        "$iss/.well-known/openid-configuration" => ['issuer' => $iss, 'jwks_uri' => 'http://example.com/jwks'],
        'http://example.com/jwks' => jwks(),
    ]);
    refused(fn() => verify(rs256(claims(['iss' => $iss])), ['issuer' => $iss], $web), 'Discovery document has no valid jwks_uri');
});

test('a trailing-dot host is still AuthFI\'s own audience', function() {
    assert_throws(InvalidArgumentException::class, fn() => new AuthFI('acme', null, audience: 'https://acme.authfi.io./mcp'));
});

echo "Results: $passed passed, $failed failed\n";
exit($failed > 0 ? 1 : 0);
