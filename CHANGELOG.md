# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
