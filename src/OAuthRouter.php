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
     * Authorization Server Metadata (RFC 8414), also served for the
     * OIDC-flavored .well-known/openid-configuration route (same document).
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
            'service_documentation' => 'https://github.com/momodemo333/dolibarr-mcp-server',
        );
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

        // client_secret_basic support
        if (empty($clientId) && !empty($server['PHP_AUTH_USER'])) {
            $clientId = urldecode((string) $server['PHP_AUTH_USER']);
            $clientSecret = urldecode((string) ($server['PHP_AUTH_PW'] ?? ''));
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
     * @param array $get Sanitized request params: client_id, redirect_uri,
     *                   state, scope, response_type, code_challenge,
     *                   code_challenge_method (same names as the source's
     *                   GETPOST() calls)
     * @return AuthorizeDecision
     */
    public function validateAuthorizeRequest(array $get): AuthorizeDecision
    {
        $clientId = (string) ($get['client_id'] ?? '');
        $redirectUri = (string) ($get['redirect_uri'] ?? '');
        $state = (string) ($get['state'] ?? '');
        $scope = (string) ($get['scope'] ?? '');
        $responseType = (string) ($get['response_type'] ?? '');
        $codeChallenge = (string) ($get['code_challenge'] ?? '');
        $codeChallengeMethod = (string) ($get['code_challenge_method'] ?? '');

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
            );
        }

        if ($codeChallenge === '' || strtoupper($codeChallengeMethod) !== 'S256') {
            return new AuthorizeDecision(
                valid: false,
                client: $client,
                redirectUri: $redirectUri,
                codeChallenge: null,
                scope: $scope,
                state: $state,
                error: 'invalid_request',
                httpCode: null,
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
        );
    }
}
