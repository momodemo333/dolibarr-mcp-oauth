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
 * \file    src/HttpEndpoint.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Authentication decision logic for the MCP Streamable HTTP endpoint.
 *
 * Isolates the *auth decision* (testable, no SAPI/global state) from the
 * `mcp.php` glue (headers, HTTP status emission, MCP package dispatch),
 * which stays thin in each host module.
 *
 * Authentication: the caller provides a Dolibarr user API key via
 *   - "Authorization: Bearer <key>"  (standard for MCP clients), or
 *   - "DOLAPIKEY: <key>" header      (Dolibarr REST API convention), or
 *   - "?DOLAPIKEY=<key>" query param (fallback for clients without headers), or
 *   - an OAuth access token (opaque, prefixed "{tokenPrefix}a"), resolved to
 *     the granting user's REST API key.
 * The effective key is validated against llx_user, then returned so the
 * caller can forward it to the MCP tools acting through the Dolibarr REST
 * API with that user's permissions.
 */

final class HttpEndpoint
{
    private OAuthServer $oauthServer;

    /**
     * @param \DoliDB       $db     Database handler (left untyped: real \DoliDB in
     *                              production, FakeDoliDB in tests)
     * @param ExposureConfig $config Exposure configuration (prefixes, TTLs)
     */
    public function __construct(
        private $db,
        private ExposureConfig $config,
    ) {
        $this->oauthServer = new OAuthServer($db, $config);
    }

    /**
     * Resolve the effective Dolibarr REST API key for an incoming MCP request.
     *
     * @param array    $server  $_SERVER-like array (HTTP_AUTHORIZATION,
     *                          REDIRECT_HTTP_AUTHORIZATION, HTTP_DOLAPIKEY, ...)
     * @param callable $getPost Query/body param reader: fn(string $name, $default)
     * @return AuthResult Effective API key on success, or an error + HTTP status code
     */
    public function resolveApiKey(array $server, callable $getPost): AuthResult
    {
        // The Authorization header may be stripped by Apache/FPM: check the
        // usual fallbacks (REDIRECT_ prefix, getallheaders) before giving up.
        $authHeader = '';
        if (!empty($server['HTTP_AUTHORIZATION'])) {
            $authHeader = $server['HTTP_AUTHORIZATION'];
        } elseif (!empty($server['REDIRECT_HTTP_AUTHORIZATION'])) {
            $authHeader = $server['REDIRECT_HTTP_AUTHORIZATION'];
        } elseif (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strcasecmp($name, 'Authorization') === 0) {
                    $authHeader = $value;
                    break;
                }
            }
        }

        $apiKey = '';
        if ($authHeader && preg_match('/^Bearer\s+(\S+)$/i', $authHeader, $m)) {
            $apiKey = $m[1];
        }
        if ($apiKey === '' && !empty($server['HTTP_DOLAPIKEY'])) {
            $apiKey = $server['HTTP_DOLAPIKEY'];
        }
        if ($apiKey === '') {
            $apiKey = (string) $getPost('DOLAPIKEY', '');
        }
        $apiKey = dol_string_nounprintableascii($apiKey);

        if ($apiKey === '' || preg_match('/^dolcrypt:/i', $apiKey)) {
            return new AuthResult(null, 401, 'Missing or invalid credentials. Provide a Dolibarr API key ("Authorization: Bearer <key>" or "DOLAPIKEY" header), or authenticate through OAuth.');
        }

        // --- OAuth access token path -----------------------------------------
        // Tokens issued by the OAuth server are opaque values prefixed
        // "{tokenPrefix}a". They map to the Dolibarr user who granted consent;
        // the request then proceeds with that user's REST API key.
        if (str_starts_with($apiKey, $this->config->tokenPrefix.'a')) {
            $tokenRow = $this->oauthServer->validateAccessToken($apiKey);
            if (!$tokenRow) {
                dol_syslog('['.$this->config->logPrefix.'] OAuth access token rejected (unknown, expired or revoked)', LOG_NOTICE);
                return new AuthResult(null, 401, 'Invalid or expired access token');
            }

            $userApiKey = $this->oauthServer->getUserApiKey((int) $tokenRow->fk_user);
            if ($userApiKey === null) {
                // The user was disabled or their API key removed: the access
                // is over. 401 rather than 403, so the client goes back
                // through sign-in and consent instead of retrying.
                dol_syslog('['.$this->config->logPrefix.'] OAuth token refused, linked user no longer usable: '.$this->oauthServer->error, LOG_NOTICE);
                return new AuthResult(null, 401, 'Access revoked for the linked Dolibarr user');
            }

            $apiKey = $userApiKey; // downstream flow is identical to direct API key auth
        }

        // Validate against llx_user, same lookup as the native REST API
        // (api_key may be stored plain or encrypted with dolEncrypt)
        $db = $this->db;
        $sql = "SELECT u.rowid, u.login, u.statut as status";
        $sql .= " FROM ".MAIN_DB_PREFIX."user as u";
        $sql .= " WHERE u.api_key = '".$db->escape($apiKey)."'";
        $sql .= " OR u.api_key = '".$db->escape(dolEncrypt($apiKey, '', '', 'dolibarr'))."'";

        $resql = $db->query($sql);
        if (!$resql || $db->num_rows($resql) != 1) {
            dol_syslog('['.$this->config->logPrefix.'] Authentication KO: no unique user for provided api key', LOG_NOTICE);
            sleep(1); // Anti brute force, same delay as the native REST API
            return new AuthResult(null, 401, 'Error user not valid (not found with api key or bad status)');
        }
        $obj = $db->fetch_object($resql);
        if (empty($obj->status)) {
            dol_syslog('['.$this->config->logPrefix.'] Authentication KO: user '.$obj->login.' is disabled', LOG_NOTICE);
            sleep(1);
            return new AuthResult(null, 401, 'Error user not valid (not found with api key or bad status)');
        }

        dol_syslog('['.$this->config->logPrefix.'] MCP request authenticated for user '.$obj->login, LOG_DEBUG);

        return new AuthResult($apiKey, null, null);
    }

    /**
     * Tell whether an Authorization header reached PHP, through any of the
     * sources authentication reads.
     *
     * Used by the self-test of the module's admin page: Apache running PHP
     * as CGI or FastCGI drops the header unless configured otherwise, a
     * .htaccess is ignored by many hosts, and the only symptom is a 401
     * right after a successful sign-in.
     *
     * @param array $server $_SERVER-like array
     * @return bool
     */
    public static function seesAuthorizationHeader(array $server): bool
    {
        if (!empty($server['HTTP_AUTHORIZATION']) || !empty($server['REDIRECT_HTTP_AUTHORIZATION'])) {
            return true;
        }
        if (function_exists('getallheaders')) {
            foreach (getallheaders() as $name => $value) {
                if (strtolower((string) $name) === 'authorization' && $value !== '') {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * WWW-Authenticate header value advertised on 401s, so OAuth-capable MCP
     * clients (claude.ai connectors...) can run the discovery + authorization
     * flow (RFC 9728 §5.1).
     *
     * @param string $oauthProtectedResourceUrl Absolute URL of the module's
     *               oauth.php Protected Resource Metadata document (the
     *               caller builds this via UrlHelper::publicUrl(...))
     * @return string Header value (without the "WWW-Authenticate:" name)
     */
    public function wwwAuthenticateHeader(string $oauthProtectedResourceUrl): string
    {
        return 'Bearer resource_metadata="'.$oauthProtectedResourceUrl.'", scope="dolibarr"';
    }
}
