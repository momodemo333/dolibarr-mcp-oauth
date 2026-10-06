<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth;

/* Copyright (C) 2026 E-dem
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

/**
 * \file    src/OAuthRouter.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Machine-facing OAuth 2.1 routing: discovery metadata, dynamic
 *          client registration, token grants, and authorize-request
 *          validation, extracted from emMCP's oauth.php.
 *
 * The /authorize consent HTML (GET: render form, POST: handle the user's
 * accept/deny decision) stays in each host module's thin oauth.php front
 * controller, since it needs llxHeader()/llxFooter()/newToken()/$user/$langs.
 * This class only exposes the pure *validation* step of that route
 * (validateAuthorizeRequest()) so it is unit-testable without Dolibarr.
 *
 * Every other route here is machine-to-machine (no session, no CSRF token)
 * and fully delegated: metadata documents, dynamic client registration
 * (RFC 7591), and the token endpoint (authorization_code + refresh_token
 * grants, PKCE S256, client_secret_basic/post/none authentication).
 */
final class OAuthRouter
{
    /**
     * @param OAuthServer    $server     Authorization server (client/token storage + grants)
     * @param ExposureConfig $config     Exposure configuration (prefixes, TTLs)
     * @param string         $issuerUrl  Absolute URL of the module's oauth.php (no trailing slash)
     * @param string         $resourceUrl Absolute URL of the module's mcp.php (protected resource)
     */
    public function __construct(
        private OAuthServer $server,
        private ExposureConfig $config,
        private string $issuerUrl,
        private string $resourceUrl,
    ) {
    }

    // --- Discovery (RFC 8414 / OIDC discovery, RFC 9728) -----------------------

    /**
     * The issuer, as clients must see it in metadata and in the iss
     * parameter of every authorization response (RFC 9207).
     *
     * @return string
     */
    public function issuer(): string
    {
        return $this->issuerUrl;
    }

    /**
     * Authorization Server Metadata (RFC 8414).
     *
     * This document must stay free of OpenID fields: carrying them is a claim
     * to be an OpenID provider, and the claude.ai and ChatGPT connectors
     * refuse it. The OpenID route has its own document,
     * metadataOpenIdConfiguration().
     *
     * @return array
     */
    public function metadataAuthorizationServer(): array
    {
        return array(
            'issuer' => $this->issuerUrl,
            'authorization_endpoint' => $this->issuerUrl.'/authorize',
            'token_endpoint' => $this->issuerUrl.'/token',
            'registration_endpoint' => $this->issuerUrl.'/register',
            'response_types_supported' => array('code'),
            'grant_types_supported' => array('authorization_code', 'refresh_token'),
            'code_challenge_methods_supported' => array('S256'),
            'token_endpoint_auth_methods_supported' => array('none', 'client_secret_basic', 'client_secret_post'),
            'scopes_supported' => array('dolibarr'),
            // RFC 9207: the authorization response names its issuer, so a
            // client talking to several servers cannot be made to mix them up.
            'authorization_response_iss_parameter_supported' => true,
            'service_documentation' => 'https://github.com/momodemo333/dolibarr-mcp-server',
        );
    }

    /**
     * The document served on .well-known/openid-configuration.
     *
     * A client that fetches this route validates the answer as OpenID
     * Connect discovery, which requires jwks_uri,
     * subject_types_supported and id_token_signing_alg_values_supported.
     * Clients built on the official MCP TypeScript SDK (mcp-remote, hence
     * Claude Desktop) reach this route for an issuer with a path and refuse
     * the RFC 8414 document there. The values are honest: the key set is
     * empty, since no id_token is ever issued and the openid scope is not
     * offered.
     *
     * @return array
     */
    public function metadataOpenIdConfiguration(): array
    {
        return array_merge($this->metadataAuthorizationServer(), array(
            'jwks_uri' => $this->issuerUrl.'/jwks',
            'subject_types_supported' => array('public'),
            'id_token_signing_alg_values_supported' => array('RS256'),
        ));
    }

    /**
     * The key set announced by metadataOpenIdConfiguration(): empty, since
     * nothing here is signed.
     *
     * @return array
     */
    public function jwks(): array
    {
        return array('keys' => array());
    }

    /**
     * Protected Resource Metadata (RFC 9728).
     *
     * @return array
     */
    public function metadataProtectedResource(): array
    {
        return array(
            'resource' => $this->resourceUrl,
            'authorization_servers' => array($this->issuerUrl),
            'scopes_supported' => array('dolibarr'),
            'bearer_methods_supported' => array('header'),
            'resource_name' => 'Dolibarr MCP Server',
        );
    }

    // --- Dynamic Client Registration (RFC 7591) ---------------------------------

    /**
     * Handle a POST /register request. The caller (module oauth.php) is
     * responsible for enforcing the HTTP method and decoding the JSON body
     * (returning the same invalid_client_metadata/400 shape itself when the
     * body isn't valid JSON, before this is even reached).
     *
     * @param array $body Parsed JSON registration request
     * @return array{payload: array, httpCode: int}
     */
    public function handleRegister(array $body): array
    {
        $response = $this->server->registerClient($body);
        if ($response === null && $this->server->error === 'too_many_registrations') {
            return array(
                'payload' => array('error' => 'too_many_requests', 'error_description' => 'Too many client registrations, try again later'),
                'httpCode' => 429,
            );
        }
        if ($response === null) {
            return array(
                'payload' => array('error' => 'invalid_client_metadata', 'error_description' => $this->server->error),
                'httpCode' => 400,
            );
        }

        return array('payload' => $response, 'httpCode' => 201);
    }

    // --- Token endpoint ----------------------------------------------------------

    /**
     * Handle a POST /token request: authorization_code exchange (PKCE S256)
     * or refresh_token rotation, with client_secret_basic/post/none auth.
     *
     * @param callable $getPost Request param reader: fn(string $name, $default)
     * @param array    $server  $_SERVER-like array (PHP_AUTH_USER/PHP_AUTH_PW for client_secret_basic)
     * @return array{payload: array, httpCode: int}
     */
    public function handleToken(callable $getPost, array $server): array
    {
        $grantType = (string) $getPost('grant_type', '');
        $clientId = (string) $getPost('client_id', '');
        $clientSecret = (string) $getPost('client_secret', '');

        // client_secret_basic. PHP_AUTH_* is only filled by mod_php; under
        // PHP-FPM or CGI the credentials arrive in the Authorization header,
        // when the web server passes it on at all.
        if (empty($clientId)) {
            if (!empty($server['PHP_AUTH_USER'])) {
                $clientId = urldecode((string) $server['PHP_AUTH_USER']);
                $clientSecret = urldecode((string) ($server['PHP_AUTH_PW'] ?? ''));
            } else {
                $basic = (string) ($server['HTTP_AUTHORIZATION'] ?? ($server['REDIRECT_HTTP_AUTHORIZATION'] ?? ''));
                if (stripos($basic, 'Basic ') === 0) {
                    $pair = base64_decode(substr($basic, 6), true);
                    if (is_string($pair) && strpos($pair, ':') !== false) {
                        list($user, $pass) = explode(':', $pair, 2);
                        $clientId = urldecode($user);
                        $clientSecret = urldecode($pass);
                    }
                }
            }
        }

        // Fail fast on an unrecognized grant_type, before touching client storage.
        if ($grantType !== 'authorization_code' && $grantType !== 'refresh_token') {
            return array('payload' => array('error' => 'unsupported_grant_type'), 'httpCode' => 400);
        }

        $client = $this->server->getClient($clientId);
        if (!$client) {
            return array('payload' => array('error' => 'invalid_client'), 'httpCode' => 401);
        }
        if (!$this->server->authenticateClient($client, $clientSecret)) {
            return array('payload' => array('error' => 'invalid_client'), 'httpCode' => 401);
        }

        $this->server->purgeExpired();

        if ($grantType === 'authorization_code') {
            $tokens = $this->server->exchangeAuthorizationCode(
                $client,
                (string) $getPost('code', ''),
                (string) $getPost('redirect_uri', ''),
                (string) $getPost('code_verifier', '')
            );
        } else {
            $tokens = $this->server->refreshTokens($client, (string) $getPost('refresh_token', ''));
        }

        if ($tokens === null) {
            return array('payload' => array('error' => $this->server->error ?: 'invalid_grant'), 'httpCode' => 400);
        }

        dol_syslog('['.$this->config->logPrefix.'] OAuth tokens issued to client '.$client->client_id.' (grant: '.$grantType.')', LOG_INFO);

        return array('payload' => $tokens, 'httpCode' => 200);
    }

    // --- Authorization endpoint: request validation only -------------------------

    /**
     * Validate a GET/POST /authorize request up to (but not including)
     * rendering the consent screen or creating the authorization code.
     *
     * @param array $params Sanitized request params: client_id, redirect_uri,
     *                   state, scope, resource, response_type, code_challenge,
     *                   code_challenge_method (same names as the source's
     *                   GETPOST() calls). Must be sourced from BOTH GET and
     *                   POST (Dolibarr's GETPOST() reads both): the initial
     *                   request arrives as a GET, but on the consent form
     *                   submission these same fields arrive as POST hidden
     *                   fields.
     * @return AuthorizeDecision
     */
    public function validateAuthorizeRequest(array $params): AuthorizeDecision
    {
        $clientId = (string) ($params['client_id'] ?? '');
        $redirectUri = (string) ($params['redirect_uri'] ?? '');
        $state = (string) ($params['state'] ?? '');
        $scope = (string) ($params['scope'] ?? '');
        $resource = (string) ($params['resource'] ?? '');
        $responseType = (string) ($params['response_type'] ?? '');
        $codeChallenge = (string) ($params['code_challenge'] ?? '');
        $codeChallengeMethod = (string) ($params['code_challenge_method'] ?? '');

        $client = $this->server->getClient($clientId);

        // Never redirect to an unvalidated URI (open redirect protection):
        // this is the one failure that cannot be reported via redirect.
        if (!$client || !$this->server->isRegisteredRedirectUri($client, $redirectUri)) {
            return new AuthorizeDecision(
                valid: false,
                client: null,
                redirectUri: null,
                codeChallenge: null,
                scope: null,
                state: $state,
                error: 'Invalid OAuth request: unknown client_id or unregistered redirect_uri.',
                httpCode: 400,
                errorDescription: null,
                resource: $resource,
            );
        }

        if ($responseType !== 'code') {
            return new AuthorizeDecision(
                valid: false,
                client: $client,
                redirectUri: $redirectUri,
                codeChallenge: null,
                scope: $scope,
                state: $state,
                error: 'unsupported_response_type',
                httpCode: null,
                errorDescription: null,
                resource: $resource,
            );
        }

        // An S256 challenge is the base64url of a SHA-256: 43 characters.
        // Anything else is not one, and would only be stored to fail later.
        if (strtoupper($codeChallengeMethod) !== 'S256' || !preg_match('/^[A-Za-z0-9_-]{43}$/', $codeChallenge)) {
            return new AuthorizeDecision(
                valid: false,
                client: $client,
                redirectUri: $redirectUri,
                codeChallenge: null,
                scope: $scope,
                state: $state,
                error: 'invalid_request',
                httpCode: null,
                errorDescription: 'PKCE S256 required',
                resource: $resource,
            );
        }

        return new AuthorizeDecision(
            valid: true,
            client: $client,
            redirectUri: $redirectUri,
            codeChallenge: $codeChallenge,
            scope: $scope,
            state: $state,
            error: null,
            httpCode: null,
            errorDescription: null,
            resource: $resource,
        );
    }
}
