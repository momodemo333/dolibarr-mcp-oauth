# dolibarr-mcp-oauth

Shared **OAuth 2.1 + HTTP-exposure layer** for MCP-enabled Dolibarr modules.

This library was extracted from the [emMCP](https://github.com/momodemo333/emmcp)
Dolibarr module (v1.0.1) so that any Dolibarr module bundling the
[`dolibarr-mcp-server`](https://github.com/momodemo333/dolibarr-mcp-server) package
can expose it over **Streamable HTTP with OAuth 2.1**, without re-implementing the
authorization server, token storage, or authentication glue from scratch.

Current consumers: **emMCP** and **Dalfred**.

## What it does

A Dolibarr module that bundles `dolibarr-mcp-server` normally only exposes it
locally (stdio, CLI). This library adds the pieces needed to expose that same
MCP server as a remote HTTP endpoint that external clients (claude.ai
connectors, or any MCP client speaking Streamable HTTP) can reach:

- **`HttpEndpoint`** — resolves the effective Dolibarr REST API key for an
  incoming MCP request, whether the caller presents a plain Dolibarr API key
  (`Authorization: Bearer <key>`, `DOLAPIKEY` header/param) or an OAuth access
  token issued by this library.
- **`OAuthServer`** — a minimal OAuth 2.1 authorization server: RFC 7591
  dynamic client registration, authorization code + PKCE (S256 only) exchange,
  refresh token rotation. Tokens are opaque random strings; only their sha256
  hash is ever persisted.
- **`OAuthRouter`** — the machine-facing routes on top of `OAuthServer`:
  discovery metadata (RFC 8414 / RFC 9728), `/register`, `/token`, and the
  *validation* half of `/authorize` (see [Consent screen](#consent-screen-stays-in-the-module) below).
- **`Support\UrlHelper`** / **`Support\PackageLocator`** — small seams: building
  a correct public HTTPS URL behind a TLS-terminating reverse proxy, and
  locating the embedded `dolibarr-mcp-server` autoloader.
- **`ExposureConfig`** — the single parameterization point so the same code
  serves multiple host modules (see below).

## `ExposureConfig`

Every class in this library takes an `ExposureConfig` instead of hard-coding a
module name, so the same code can be embedded in emMCP, Dalfred, or any future
module without touching a line of the shared code.

```php
new ExposureConfig(
    string $tablePrefix,   // 'emmcp'   -> llx_emmcp_oauth_client / llx_emmcp_oauth_token
    string $tokenPrefix,   // 'emcp_'   -> issued tokens look like emcp_a<hex>, emcp_r<hex>, emcp_c<hex>
    string $logPrefix,     // 'EMMCP'   -> dol_syslog lines prefixed '[EMMCP] ...'
);
```

- **`$tablePrefix`** — the module's two OAuth tables must be named
  `llx_<tablePrefix>_oauth_client` and `llx_<tablePrefix>_oauth_token` (created
  by the host module's own SQL migrations; this library never creates tables).
- **`$tokenPrefix`** — prepended to every issued token/code so the type and
  origin are identifiable at a glance in logs or DB rows (`a` = access token,
  `r` = refresh token, `c` = authorization code, e.g. `emcp_a5f3...`). Also
  used as the prefix on registered `client_id`s (`emcp_client_...`).
- **`$logPrefix`** — used verbatim in every `dol_syslog('[' . logPrefix . '] ...')`
  call so `grep '\[EMMCP\]' dolibarr.log` finds only this module's lines.

TTLs are fixed constants shared by every consumer (not configurable per
module): `ExposureConfig::ACCESS_TOKEN_TTL` (3600s), `REFRESH_TOKEN_TTL`
(2592000s / 30 days), `AUTH_CODE_TTL` (120s, one-shot). Accessors:
`accessTokenTtl()`, `refreshTokenTtl()`, `authCodeTtl()`.

## Wiring a host module

A host module ships two thin front controllers. Both instantiate
`ExposureConfig` once and delegate everything else to this library.

### `mcp.php` — the protected MCP endpoint

```php
require_once '../../main.inc.php'; // or the module's own bootstrap
require_once __DIR__.'/vendor/autoload.php'; // or wherever Composer deps live

use DolibarrMcpOAuth\ExposureConfig;
use DolibarrMcpOAuth\HttpEndpoint;
use DolibarrMcpOAuth\Support\UrlHelper;

$config = new ExposureConfig('emmcp', 'emcp_', 'EMMCP');
$endpoint = new HttpEndpoint($db, $config);

// $getPost wraps Dolibarr's GETPOST(); note the 2nd arg here is the
// *default value* returned when the param is absent, NOT GETPOST's own
// filter-type argument (Dolibarr's 2nd arg selects a sanitizer like
// 'alphanohtml' — we've already picked one and hard-coded it below).
$getPost = fn(string $name, $default) => GETPOST($name, 'alphanohtml') ?: $default;

$auth = $endpoint->resolveApiKey($_SERVER, $getPost);
if ($auth->apiKey === null) {
    $prm = UrlHelper::publicUrl('/emmcp/oauth.php').'/.well-known/oauth-protected-resource';
    header('WWW-Authenticate: '.$endpoint->wwwAuthenticateHeader($prm));
    http_response_code($auth->httpCode);
    header('Content-Type: application/json');
    echo json_encode(['error' => $auth->error]);
    exit;
}

// $auth->apiKey is now a valid Dolibarr REST API key: forward it to the
// bundled dolibarr-mcp-server package (Streamable HTTP transport), which
// acts through the Dolibarr REST API with that user's permissions.
```

### `oauth.php` — discovery, registration, token, and consent

```php
require_once '../../main.inc.php';
require_once __DIR__.'/vendor/autoload.php';

use DolibarrMcpOAuth\ExposureConfig;
use DolibarrMcpOAuth\OAuthServer;
use DolibarrMcpOAuth\OAuthRouter;
use DolibarrMcpOAuth\Support\UrlHelper;

$config = new ExposureConfig('emmcp', 'emcp_', 'EMMCP');
$server = new OAuthServer($db, $config);
$router = new OAuthRouter(
    $server,
    $config,
    UrlHelper::publicUrl('/emmcp/oauth.php'), // issuer URL
    UrlHelper::publicUrl('/emmcp/mcp.php'),   // protected resource URL
);

// Route on PATH_INFO (or a ?route= fallback), NOT on GETPOST('action'):
// the consent form below POSTs action=consent to this same /authorize URL,
// so using 'action' for outer routing would misroute that POST away from
// the '/authorize' case. 'action' is only read *inside* the '/authorize'
// case, to tell the initial GET apart from the consent POST.
$route = !empty($_SERVER['PATH_INFO'])
    ? rtrim($_SERVER['PATH_INFO'], '/')
    : '/'.ltrim((string) GETPOST('route', 'alpha'), '/');

switch (true) {
    case str_ends_with($route, '.well-known/oauth-authorization-server'):
    case str_ends_with($route, '.well-known/openid-configuration'):
        header('Content-Type: application/json');
        echo json_encode($router->metadataAuthorizationServer());
        break;

    case str_ends_with($route, '.well-known/oauth-protected-resource'):
        header('Content-Type: application/json');
        echo json_encode($router->metadataProtectedResource());
        break;

    case str_ends_with($route, '/register'):
        $body = json_decode(file_get_contents('php://input'), true) ?: [];
        $result = $router->handleRegister($body);
        http_response_code($result['httpCode']);
        header('Content-Type: application/json');
        echo json_encode($result['payload']);
        break;

    case str_ends_with($route, '/token'):
        $getPost = fn(string $name, $default) => GETPOST($name, 'alphanohtml') ?: $default;
        $result = $router->handleToken($getPost, $_SERVER);
        http_response_code($result['httpCode']);
        header('Content-Type: application/json');
        echo json_encode($result['payload']);
        break;

    case str_ends_with($route, '/authorize'):
        // GETPOST-sourced (GET+POST): the initial request is a GET, but on
        // the consent form submission these same fields arrive as POST
        // hidden fields, so a plain $_GET array would miss them there.
        $params = [
            'client_id' => GETPOST('client_id', 'alphanohtml'),
            'redirect_uri' => GETPOST('redirect_uri', 'alphanohtml'),
            'state' => GETPOST('state', 'alphanohtml'),
            'scope' => GETPOST('scope', 'alphanohtml'),
            'resource' => GETPOST('resource', 'alphanohtml'),
            'response_type' => GETPOST('response_type', 'alphanohtml'),
            'code_challenge' => GETPOST('code_challenge', 'alphanohtml'),
            'code_challenge_method' => GETPOST('code_challenge_method', 'alphanohtml'),
        ];
        // Re-validating client_id/redirect_uri/PKCE here on the consent POST
        // too (not just on the initial GET) is a deliberate security
        // property, not incidental duplication: it re-confirms the redirect
        // target is still one of the client's registered URIs immediately
        // before minting an authorization code for it.
        $decision = $router->validateAuthorizeRequest($params);

        if (!$decision->valid && $decision->redirectUri === null) {
            // Open-redirect protection: unknown client_id or unregistered
            // redirect_uri means there is no safe place to send the user.
            llxHeader();
            print '<div class="error">'.dol_escape_htmltag($decision->error).'</div>';
            llxFooter();
            break;
        }
        if (!$decision->valid) {
            // Validated redirect target, but response_type/PKCE are wrong:
            // bounce back to the client with the OAuth error. buildRedirect()
            // appends with '&' instead of '?' when the registered
            // redirect_uri already carries its own query string.
            $errorParams = ['error' => $decision->error, 'state' => $decision->state];
            if ($decision->errorDescription !== null) {
                $errorParams['error_description'] = $decision->errorDescription;
            }
            header('Location: '.UrlHelper::buildRedirect($decision->redirectUri, $errorParams), true, 302);
            break;
        }

        if (GETPOST('action', 'aZ09') === 'consent' && $_SERVER['REQUEST_METHOD'] === 'POST') {
            // CSRF is enforced by main.inc.php (token checked on POST).
            if (GETPOST('decision', 'aZ09') === 'accept') {
                $code = $server->createAuthorizationCode($decision->client, (int) $user->id, $decision->redirectUri, $decision->codeChallenge, $decision->scope, $decision->resource);
                if ($code === null) {
                    header('Location: '.UrlHelper::buildRedirect($decision->redirectUri, ['error' => 'server_error', 'state' => $decision->state]), true, 302);
                    break;
                }
                header('Location: '.UrlHelper::buildRedirect($decision->redirectUri, ['code' => $code, 'state' => $decision->state]), true, 302);
                break;
            }
            header('Location: '.UrlHelper::buildRedirect($decision->redirectUri, ['error' => 'access_denied', 'state' => $decision->state]), true, 302);
            break;
        }

        // GET (or POST without action=consent yet): render the consent
        // screen here (llxHeader(), newToken(), $user, $langs — this HTML
        // stays in the module, see below). Its <form> must post back
        // client_id/redirect_uri/state/scope/resource/response_type/
        // code_challenge/code_challenge_method as hidden fields plus
        // action=consent, so the block above sees them on submission.
        break;
}
```

### Consent screen stays in the module

The `/authorize` GET (render the "Allow this client to access your Dolibarr
data?" form) and POST (handle accept/deny) branches are **not** in this
library. They need `llxHeader()`/`llxFooter()`/`newToken()`/`$user`/`$langs`,
which only make sense inside a live Dolibarr request — so `OAuthRouter` only
exposes the pure, unit-testable *validation* step
(`validateAuthorizeRequest()`) described above, and the host module owns the
actual HTML and the call to `OAuthServer::createAuthorizationCode()` once the
user consents.

## Distribution: single source of truth, copied at build

This package has **one canonical git repository**:
[`momodemo333/dolibarr-mcp-oauth`](https://github.com/momodemo333/dolibarr-mcp-oauth).

Host modules (emMCP, Dalfred, …) do **not** depend on it via a live Composer
registry pull embedded at runtime, nor via a git submodule. Instead, each
module's release build (`make build-release`) copies this package's source
into the module's own vendor tree, the same way each module already embeds a
private copy of `dolibarr-mcp-server`.

Consequences:

- **Never edit the embedded copy** inside a host module's tree
  (`htdocs/custom/<module>/vendor/.../dolibarr-mcp-oauth/` or wherever the
  build places it). Any fix belongs in this repository; the module picks it up
  on its next build.
- **Version bumps happen here first.** Bump this package, tag/release it,
  then update the host module's build to pull the new version and rebuild.
- This mirrors the `dolibarr-mcp-server` distribution model documented in
  each host module's own `CLAUDE.md` — same reasoning: Dolistore ZIPs must be
  self-contained, so nothing can depend on a runtime package fetch.

## Security summary

Every consumer of this library inherits the same security posture:

- **OAuth 2.1** authorization code flow with **PKCE, S256 only** — no
  `plain` challenge method is ever accepted.
- **Tokens stored sha256-hashed only.** Access tokens, refresh tokens, and
  authorization codes are opaque random values; the database never holds the
  clear-text value, only `hash('sha256', $token)`.
- **Refresh token rotation** — every use of a refresh token revokes it and
  issues a new access+refresh pair; refresh tokens are not reusable.
- **One-shot, 120s authorization codes** — a code is revoked the instant it is
  redeemed (even if the exchange subsequently fails validation), and expires
  after 120 seconds if never used.
- **`redirect_uri` re-validated at every step** — checked against the
  client's registered URIs both at `/authorize` and again at token exchange,
  with a narrow loopback exception (RFC 8252 §7.3: same scheme/host/path,
  any port) for native/CLI clients.

## Requirements

- **PHP 8.1+**
- A **Dolibarr host** providing a live `DoliDB` connection and the usual
  Dolibarr globals/functions this library calls directly: `dol_syslog()`,
  `dol_now()`, `dol_buildpath()`, `dol_trunc()`, `dol_string_nounprintableascii()`,
  `dol_escape_htmltag()`, `showValueWithClipboardCPButton()`,
  `dolEncrypt()`/`dolDecrypt()` (optional — used only if the host defines
  them), and the `MAIN_DB_PREFIX` constant. It is not meant to run outside a
  Dolibarr request context (the test suite stubs these with a `FakeDoliDB`
  and shimmed globals — see `tests/Fakes/`).

## Testing

```bash
composer install
vendor/bin/phpunit
```
