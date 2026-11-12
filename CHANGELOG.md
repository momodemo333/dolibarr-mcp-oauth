# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-11-12

### Fixed
- **An OAuth client left idle for about a month was deleted, and the AI client
  could no longer sign in.** The purge of abandoned registrations kept a
  client only while it had token rows, but the token rows of an idle client
  are themselves purged a day after its refresh token expires (30 days). The
  AI client still held that client_id, so every new sign-in failed with
  "unknown client_id" until the user deleted and re-created the connector.
  Only registrations between one and seven days old are considered now: a
  client that obtained a token always has a token row during its first week.

### Added
- `OAuthServer::$errorDetail` and `OAuthRouter::lastFailure()`: why the last
  exchange failed, in words an administrator can act on (code or refresh token
  unknown, expired, already used; redirect_uri mismatch; PKCE mismatch;
  unknown client_id...). Token errors also carry it as `error_description`.
  `$error` is unchanged.

## [1.1.0] - 2026-10-06

Security and compatibility release. Every point below was found by reviewing
this library against what the same design got wrong in the Dolibarr core
implementation, and each is covered by a test, run against a real database
where the fake one cannot express it.

### Security
- **An authorization code or refresh token could be spent several times
  concurrently.** The revocation that claims it did not check whether it was
  the one that flipped the row, so parallel requests each got a token pair.
  The UPDATE now carries `revoked = 0` and the caller checks the rows touched:
  twelve parallel exchanges of one code now yield exactly one pair.
- **A replayed code or refresh token now revokes the whole grant** of that
  client for that user (OAuth 2.1 section 4.3.1, RFC 6749 section 4.1.2). A
  value that merely expired unused is not a replay and revokes nothing.
- **Removing a user's REST API key did not end their OAuth access.**
  `getUserApiKey()` generated a new key whenever the user had none, on every
  MCP request, so the natural way to cut someone's API access was silently
  undone by the next call. It is now read only; `ensureUserApiKey()` creates
  the key at consent. A request whose user has no key, or is disabled, gets a
  401 so the client goes back through sign-in.
- `/register` is capped at 50 registrations per hour (429 beyond), and
  clients that never obtained a token are purged after a day.
- The PKCE challenge must be a real S256 value (43 base64url characters).

### Added
- `listGrants()` / `revokeGrant()` — the accesses currently granted, one line
  per client and user, and the call that ends one, for an admin screen.
- `HttpEndpoint::seesAuthorizationHeader()` — for a self-test telling an
  administrator whether the Authorization header reaches PHP at all.
- `OAuthRouter::metadataOpenIdConfiguration()` and `jwks()`.
- `OAuthRouter::issuer()`, and `authorization_response_iss_parameter_supported`
  in the metadata: modules add `iss` to every authorization response (RFC 9207).

### Fixed
- **Claude Desktop could not connect.** Clients built on the official MCP
  TypeScript SDK (mcp-remote) reach `.well-known/openid-configuration` for an
  issuer with a path and validate it as OpenID Connect; the RFC 8414 document
  served there has no `jwks_uri` and was rejected (ZodError). That route now
  gets its own document with the three OpenID fields and an empty key set; the
  RFC 8414 document stays free of them, as claude.ai and ChatGPT require.
- `client_secret_basic` works under PHP-FPM/CGI, where `PHP_AUTH_*` is never
  filled: the credentials are read from the Authorization header.

## [1.0.0] - 2026-07-16

Extracted from emMCP 1.0.1; parameterized via `ExposureConfig`.

### Added

- `ExposureConfig` — value object parameterizing every shared component per
  host module: table prefix, token prefix, log prefix, module slug, and the
  shared access/refresh/auth-code TTL constants.
- `OAuthServer` — minimal OAuth 2.1 authorization server: RFC 7591 dynamic
  client registration, authorization code issuance/exchange with mandatory
  PKCE (S256), refresh token rotation, Bearer access token validation,
  Dolibarr user REST API key resolution. Tokens are stored sha256-hashed
  only.
- `HttpEndpoint` (+ `AuthResult`) — authentication decision logic for the MCP
  Streamable HTTP endpoint: resolves a Dolibarr REST API key from a Bearer
  API key, a `DOLAPIKEY` header/param, or an OAuth access token; builds the
  `WWW-Authenticate` header for 401 responses.
- `OAuthRouter` (+ `AuthorizeDecision`) — machine-facing OAuth routes:
  authorization server / protected resource discovery metadata (RFC 8414,
  RFC 9728), dynamic client registration handling, the token endpoint
  (authorization_code and refresh_token grants), and the pure validation
  step of the `/authorize` request (the consent screen HTML itself stays in
  each host module).
- `Support\UrlHelper` — public HTTPS URL resolution behind a
  TLS-terminating reverse proxy, and a clipboard-friendly code block
  renderer.
- `Support\PackageLocator` — resolves the embedded `dolibarr-mcp-server`
  package's autoloader from a list of candidate paths.
- Test suite (PHPUnit 10) covering `ExposureConfig`, `OAuthServer`,
  `HttpEndpoint`, `OAuthRouter`, and the `Support` helpers, with a
  `FakeDoliDB` and shimmed Dolibarr globals so the library is testable
  outside a live Dolibarr instance.

### Known divergences from the emMCP source

Three intentionally accepted differences from `htdocs/custom/emmcp/oauth.php`
/ `mcp.php`, each unreachable in practice with a real registered client:

- `OAuthRouter::handleToken()` checks `grant_type` before looking up the
  client, so a request that is *both* an unknown/bad client *and* an
  unsupported `grant_type` gets a 400 `unsupported_grant_type` instead of the
  401 `invalid_client` the source would return in that order. A real
  registered client always sends a supported `grant_type`, so this ordering
  difference is not reachable by any legitimate caller.
- The no-safe-redirect `/authorize` error path returns `httpCode: 400` in
  `AuthorizeDecision`, whereas the source's inline HTML error page implicitly
  responds with the default 200 status. Both stop the flow the same way; only
  the machine-readable status code differs, and no client parses it (the page
  is meant for a human).
- `HttpEndpoint::resolveApiKey()` uses `=== ''` where the source uses
  `empty()` for the credential fallback chain. The two differ only for the
  literal string `"0"`, which is never a valid key in either implementation
  (issued keys are 40 hex characters), so no real request can hit this edge.
