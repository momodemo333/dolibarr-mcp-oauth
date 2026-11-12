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
 * \file    src/OAuthServer.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Minimal OAuth 2.1 authorization server for the MCP endpoint.
 *
 * Implements the subset required by the MCP authorization spec:
 * authorization code + PKCE (S256 only), refresh token rotation,
 * RFC 7591 dynamic client registration. Tokens are opaque random
 * strings; only their sha256 hash is stored.
 */

class OAuthServer
{
	/** @var DoliDB */
	public $db;

	/** @var ExposureConfig */
	private $config;

	/** @var string Last error message */
	public $error = '';

	/**
	 * Why the last operation failed, in words an administrator can act on
	 * ("authorization code already used", "redirect_uri differs from the one
	 * of the authorization request"...). $error keeps the OAuth error code
	 * the client receives; this is for logs and diagnostic screens, where
	 * "invalid_grant" alone says nothing.
	 *
	 * @var string|null
	 */
	public $errorDetail = null;

	/**
	 * @param DoliDB        $db     Database handler
	 * @param ExposureConfig $config Exposure configuration (prefixes, TTLs)
	 */
	public function __construct($db, ExposureConfig $config)
	{
		$this->db = $db;
		$this->config = $config;
	}

	// --- Clients (RFC 7591) -------------------------------------------------

	/**
	 * Register a new OAuth client (Dynamic Client Registration).
	 *
	 * @param array $metadata Parsed JSON registration request
	 * @return array|null Registration response (RFC 7591), or null on error ($this->error set)
	 */
	public function registerClient(array $metadata)
	{
		global $conf;

		$redirectUris = $metadata['redirect_uris'] ?? array();
		if (!is_array($redirectUris) || empty($redirectUris)) {
			$this->error = 'redirect_uris is required';
			return null;
		}
		foreach ($redirectUris as $uri) {
			if (!is_string($uri) || !$this->isAcceptableRedirectUri($uri)) {
				$this->error = 'Invalid redirect_uri: must be https or a localhost loopback URL';
				return null;
			}
		}

		$authMethod = $metadata['token_endpoint_auth_method'] ?? 'none';
		if (!in_array($authMethod, array('none', 'client_secret_post', 'client_secret_basic'), true)) {
			$this->error = 'Unsupported token_endpoint_auth_method';
			return null;
		}

		// /register takes no credential, so it is the one route anybody can use
		// to write into the database. A ceiling per hour keeps a loop or a
		// scanner from filling the client table; unused clients are purged by
		// purgeExpired().
		if ($this->countRecentRegistrations() >= $this->config->registrationsPerHour()) {
			$this->error = 'too_many_registrations';
			return null;
		}

		$clientId = $this->config->tokenPrefix.'client_'.bin2hex(random_bytes(16));
		$clientSecret = null;
		$secretHash = null;
		if ($authMethod !== 'none') {
			$clientSecret = bin2hex(random_bytes(32));
			$secretHash = password_hash($clientSecret, PASSWORD_DEFAULT);
		}

		$clientName = dol_trunc((string) ($metadata['client_name'] ?? ''), 250);

		$sql = "INSERT INTO ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_client";
		$sql .= " (client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method, entity, datec)";
		$sql .= " VALUES ('".$this->db->escape($clientId)."',";
		$sql .= " ".($secretHash ? "'".$this->db->escape($secretHash)."'" : "NULL").",";
		$sql .= " '".$this->db->escape($clientName)."',";
		$sql .= " '".$this->db->escape(json_encode(array_values($redirectUris)))."',";
		$sql .= " '".$this->db->escape($authMethod)."',";
		$sql .= " ".((int) $conf->entity).",";
		$sql .= " '".$this->db->idate(dol_now())."')";

		if (!$this->db->query($sql)) {
			$this->error = 'DB error: '.$this->db->lasterror();
			return null;
		}

		dol_syslog('['.$this->config->logPrefix.'] OAuth client registered: '.$clientId.' ('.$clientName.')', LOG_INFO);

		$response = array(
			'client_id' => $clientId,
			'client_id_issued_at' => dol_now(),
			'client_name' => $clientName,
			'redirect_uris' => array_values($redirectUris),
			'grant_types' => array('authorization_code', 'refresh_token'),
			'response_types' => array('code'),
			'token_endpoint_auth_method' => $authMethod,
		);
		if ($clientSecret !== null) {
			$response['client_secret'] = $clientSecret; // returned once, only the hash is stored
		}

		return $response;
	}

	/**
	 * Fetch a registered client by its client_id.
	 *
	 * @param string $clientId Client identifier
	 * @return object|null Row object or null
	 */
	public function getClient($clientId)
	{
		$sql = "SELECT rowid, client_id, client_secret_hash, client_name, redirect_uris, token_endpoint_auth_method";
		$sql .= " FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_client";
		$sql .= " WHERE client_id = '".$this->db->escape($clientId)."'";

		$resql = $this->db->query($sql);
		if ($resql && $this->db->num_rows($resql) === 1) {
			return $this->db->fetch_object($resql);
		}
		return null;
	}

	/**
	 * Authenticate a client on the token endpoint according to its
	 * registered token_endpoint_auth_method.
	 *
	 * @param object      $client Client row
	 * @param string|null $secret Secret provided in the request (body or Basic auth), if any
	 * @return bool
	 */
	public function authenticateClient($client, $secret)
	{
		if ($client->token_endpoint_auth_method === 'none') {
			return true; // public client, PKCE is the protection
		}
		return !empty($secret) && !empty($client->client_secret_hash)
			&& password_verify($secret, $client->client_secret_hash);
	}

	/**
	 * Validate a redirect_uri against the client's registered URIs.
	 * Exact match, except for loopback hosts where the port is ignored
	 * (RFC 8252 §7.3 — native clients bind a random localhost port).
	 *
	 * @param object $client Client row
	 * @param string $uri    redirect_uri from the request
	 * @return bool
	 */
	public function isRegisteredRedirectUri($client, $uri)
	{
		$registered = json_decode((string) $client->redirect_uris, true);
		if (!is_array($registered)) {
			return false;
		}

		if (in_array($uri, $registered, true)) {
			return true;
		}

		$p = parse_url($uri);
		if (!$p || !in_array($p['host'] ?? '', array('127.0.0.1', 'localhost', '[::1]'), true)) {
			return false;
		}
		foreach ($registered as $reg) {
			$r = parse_url($reg);
			if ($r && in_array($r['host'] ?? '', array('127.0.0.1', 'localhost', '[::1]'), true)
				&& ($r['scheme'] ?? '') === ($p['scheme'] ?? '')
				&& ($r['path'] ?? '/') === ($p['path'] ?? '/')) {
				return true; // same loopback URI, any port
			}
		}
		return false;
	}

	/**
	 * A redirect URI is acceptable if https, or http on a loopback host.
	 *
	 * @param string $uri Redirect URI
	 * @return bool
	 */
	private function isAcceptableRedirectUri($uri)
	{
		$p = parse_url($uri);
		if (!$p || empty($p['scheme']) || empty($p['host'])) {
			return false;
		}
		if ($p['scheme'] === 'https') {
			return true;
		}
		return $p['scheme'] === 'http' && in_array($p['host'], array('127.0.0.1', 'localhost', '[::1]'), true);
	}

	// --- Grants ---------------------------------------------------------------

	/**
	 * Issue an authorization code after user consent.
	 *
	 * @param object $client        Client row
	 * @param int    $userId        Dolibarr user granting access
	 * @param string $redirectUri   Redirect URI of the request (re-checked at exchange)
	 * @param string $codeChallenge PKCE S256 challenge
	 * @param string $scope         Requested scope
	 * @param string $resource      RFC 8707 resource indicator
	 * @return string|null The code, or null on error
	 */
	public function createAuthorizationCode($client, $userId, $redirectUri, $codeChallenge, $scope, $resource)
	{
		$code = $this->config->tokenPrefix.'c'.bin2hex(random_bytes(32));

		if (!$this->insertToken('code', $code, (int) $client->rowid, $userId, $scope, $resource, $codeChallenge, $redirectUri, $this->config->authCodeTtl())) {
			return null;
		}

		return $code;
	}

	/**
	 * Exchange an authorization code for tokens (with PKCE verification).
	 *
	 * @param object $client       Authenticated client row
	 * @param string $code         Authorization code
	 * @param string $redirectUri  redirect_uri from the token request
	 * @param string $codeVerifier PKCE verifier
	 * @return array|null Token response, or null ($this->error set to an OAuth error code)
	 */
	public function exchangeAuthorizationCode($client, $code, $redirectUri, $codeVerifier)
	{
		$this->errorDetail = null;
		$row = $this->getValidToken('code', $code);
		if (!$row) {
			$this->errorDetail = $this->diagnoseInvalidToken('code', $code, (int) $client->rowid);
			$this->revokeReplayedFamily('code', $code, (int) $client->rowid);
			$this->error = 'invalid_grant';
			return null;
		}
		if ((int) $row->fk_client !== (int) $client->rowid) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'authorization code was issued to another client';
			return null;
		}

		// One-shot, and the revocation is what claims it: of two concurrent
		// exchanges of the same code, only the one whose UPDATE actually
		// flipped the row gets tokens. Revoked before anything else is
		// checked, since a code that survives a failed exchange can be
		// replayed.
		if (!$this->revokeToken($row->rowid)) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'authorization code already used (concurrent exchange)';
			return null;
		}

		if (!empty($row->redirect_uri) && $row->redirect_uri !== $redirectUri) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'redirect_uri differs from the one of the authorization request';
			return null;
		}

		// PKCE S256 (mandatory, only supported method)
		if (empty($row->code_challenge) || empty($codeVerifier)) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'PKCE code_verifier missing';
			return null;
		}
		$computed = rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '=');
		if (!hash_equals($row->code_challenge, $computed)) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'PKCE code_verifier does not match the code_challenge';
			return null;
		}

		return $this->issueTokenPair((int) $client->rowid, (int) $row->fk_user, (string) $row->scope, (string) $row->resource);
	}

	/**
	 * Rotate a refresh token: revoke it and issue a new access+refresh pair.
	 *
	 * @param object $client       Authenticated client row
	 * @param string $refreshToken Current refresh token
	 * @return array|null Token response, or null ($this->error set)
	 */
	public function refreshTokens($client, $refreshToken)
	{
		$this->errorDetail = null;
		$row = $this->getValidToken('refresh', $refreshToken);
		if (!$row) {
			$this->errorDetail = $this->diagnoseInvalidToken('refresh', $refreshToken, (int) $client->rowid);
			$this->revokeReplayedFamily('refresh', $refreshToken, (int) $client->rowid);
			$this->error = 'invalid_grant';
			return null;
		}
		if ((int) $row->fk_client !== (int) $client->rowid) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'refresh token was issued to another client';
			return null;
		}

		// Same claim as for codes: rotation means a refresh token works once.
		if (!$this->revokeToken($row->rowid)) {
			$this->error = 'invalid_grant';
			$this->errorDetail = 'refresh token already used (concurrent refresh)';
			return null;
		}

		return $this->issueTokenPair((int) $client->rowid, (int) $row->fk_user, (string) $row->scope, (string) $row->resource);
	}

	/**
	 * Validate a Bearer access token.
	 *
	 * @param string $token Access token presented by the MCP client
	 * @return object|null Token row (with fk_user) or null
	 */
	public function validateAccessToken($token)
	{
		return $this->getValidToken('access', $token);
	}

	/**
	 * Resolve the Dolibarr REST API key of a user, so the MCP tools can act
	 * through the REST API on the user's behalf.
	 *
	 * Read only. Up to 1.0.x this generated a key when the user had none, on
	 * every request: removing a user's API key — the natural way for an
	 * administrator to cut someone's API access — was silently undone by
	 * the next MCP call, and the access could not be revoked. A key is now
	 * created only at consent (ensureUserApiKey()), so removing it ends every
	 * OAuth access of that user until they consent again.
	 *
	 * @param int $userId User rowid
	 * @return string|null Clear-text API key, or null ($this->error set)
	 */
	public function getUserApiKey($userId)
	{
		return $this->readUserApiKey($userId, false);
	}

	/**
	 * Make sure a user has a REST API key, creating one if needed. Called at
	 * consent, the moment the user explicitly grants access.
	 *
	 * @param int $userId User rowid
	 * @return string|null Clear-text API key, or null ($this->error set)
	 */
	public function ensureUserApiKey($userId)
	{
		return $this->readUserApiKey($userId, true);
	}

	/**
	 * @param int  $userId User rowid
	 * @param bool $create Create a key when the user has none
	 * @return string|null
	 */
	private function readUserApiKey($userId, $create)
	{
		$sql = "SELECT api_key FROM ".MAIN_DB_PREFIX."user";
		$sql .= " WHERE rowid = ".((int) $userId)." AND statut = 1";

		$resql = $this->db->query($sql);
		if (!$resql || $this->db->num_rows($resql) !== 1) {
			$this->error = 'User not found or disabled';
			return null;
		}
		$obj = $this->db->fetch_object($resql);

		if (!empty($obj->api_key)) {
			$key = function_exists('dolDecrypt') ? dolDecrypt($obj->api_key) : $obj->api_key;
			if (!empty($key) && !preg_match('/^dolcrypt:/i', $key)) {
				return $key;
			}
		}

		if (!$create) {
			$this->error = 'The user has no REST API key (access revoked)';
			return null;
		}

		// No usable key: generate one (same storage convention as the user card)
		$key = bin2hex(random_bytes(20));
		$stored = function_exists('dolEncrypt') ? dolEncrypt($key, '', '', 'dolibarr') : $key;
		$sql = "UPDATE ".MAIN_DB_PREFIX."user SET api_key = '".$this->db->escape($stored)."'";
		$sql .= " WHERE rowid = ".((int) $userId);
		if (!$this->db->query($sql)) {
			$this->error = 'Failed to generate API key: '.$this->db->lasterror();
			return null;
		}
		dol_syslog('['.$this->config->logPrefix.'] Generated REST API key for user '.$userId.' (OAuth consent)', LOG_INFO);

		return $key;
	}

	/**
	 * Opportunistic cleanup of expired/revoked grants (called from the token endpoint).
	 *
	 * @return void
	 */
	public function purgeExpired()
	{
		$sql = "DELETE FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token";
		$sql .= " WHERE expires_at < '".$this->db->idate(dol_now() - 86400)."'";
		$this->db->query($sql);

		// A registration that never led to a token is a row nobody asked
		// for: /register takes no credential, so without this the client
		// table only grows, one row per connection attempt.
		//
		// Only registrations between one and seven days old are considered.
		// "Has no token row" cannot tell an abandoned registration from a
		// client that was used and then left idle: the token rows of an idle
		// client are themselves purged a day after its refresh token expires
		// (30 days), and in 1.1.0 the client went with them. The AI client
		// still holds that client_id, so the next sign-in failed with
		// "unknown client_id" until the user deleted and re-created the
		// connector. A client that obtains a token always has a token row
		// during its first week (the code row alone outlives the first day),
		// so the window catches every abandoned registration and no used one.
		$sql = "DELETE FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_client";
		$sql .= " WHERE datec < '".$this->db->idate(dol_now() - 86400)."'";
		$sql .= " AND datec > '".$this->db->idate(dol_now() - 7 * 86400)."'";
		$sql .= " AND rowid NOT IN (SELECT fk_client FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token WHERE fk_client IS NOT NULL)";
		$this->db->query($sql);
	}

	// --- Grants, for the administrator ------------------------------------------

	/**
	 * List the accesses currently granted: one line per client and user that
	 * still holds a usable refresh token.
	 *
	 * @return array<int, object> Rows with fk_client, client_name, client_id,
	 *                            fk_user, login, granted (first token), last_used
	 *                            (latest token), expires (latest expiry)
	 */
	public function listGrants()
	{
		global $conf;

		$t = MAIN_DB_PREFIX.$this->config->tablePrefix;
		$sql = "SELECT t.fk_client, t.fk_user, c.client_name, c.client_id, u.login,";
		$sql .= " MIN(t.datec) as granted, MAX(t.datec) as last_used, MAX(t.expires_at) as expires";
		$sql .= " FROM ".$t."_oauth_token as t";
		$sql .= " INNER JOIN ".$t."_oauth_client as c ON c.rowid = t.fk_client";
		$sql .= " LEFT JOIN ".MAIN_DB_PREFIX."user as u ON u.rowid = t.fk_user";
		$sql .= " WHERE t.token_type = 'refresh' AND t.revoked = 0";
		$sql .= " AND t.expires_at > '".$this->db->idate(dol_now())."'";
		$sql .= " AND t.entity = ".((int) $conf->entity);
		$sql .= " GROUP BY t.fk_client, t.fk_user, c.client_name, c.client_id, u.login";
		$sql .= " ORDER BY last_used DESC";

		$rows = array();
		$resql = $this->db->query($sql);
		if ($resql) {
			while ($obj = $this->db->fetch_object($resql)) {
				$rows[] = $obj;
			}
		}

		return $rows;
	}

	/**
	 * Revoke everything issued to one client for one user: codes, access and
	 * refresh tokens. The client must consent again to get back in.
	 *
	 * @param int $clientRowid Client rowid
	 * @param int $userId      User rowid
	 * @return int Number of tokens revoked, -1 on error
	 */
	public function revokeGrant($clientRowid, $userId)
	{
		$sql = "UPDATE ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token SET revoked = 1";
		$sql .= " WHERE fk_client = ".((int) $clientRowid);
		$sql .= " AND fk_user = ".((int) $userId);
		$sql .= " AND revoked = 0";

		$resql = $this->db->query($sql);
		if (!$resql) {
			$this->error = $this->db->lasterror();
			return -1;
		}

		return (int) $this->db->affected_rows($resql);
	}

	/**
	 * Number of clients registered over the last hour.
	 *
	 * @return int
	 */
	public function countRecentRegistrations()
	{
		$sql = "SELECT COUNT(*) as nb FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_client";
		$sql .= " WHERE datec > '".$this->db->idate(dol_now() - 3600)."'";

		$resql = $this->db->query($sql);
		if ($resql && ($obj = $this->db->fetch_object($resql))) {
			return (int) $obj->nb;
		}

		return 0;
	}

	// --- Internals --------------------------------------------------------------

	/**
	 * Issue an access token + refresh token pair.
	 *
	 * @param int    $clientRowid Client rowid
	 * @param int    $userId      User rowid
	 * @param string $scope       Scope
	 * @param string $resource    Resource indicator
	 * @return array|null OAuth token response
	 */
	private function issueTokenPair($clientRowid, $userId, $scope, $resource)
	{
		$access = $this->config->tokenPrefix.'a'.bin2hex(random_bytes(32));
		$refresh = $this->config->tokenPrefix.'r'.bin2hex(random_bytes(32));

		if (!$this->insertToken('access', $access, $clientRowid, $userId, $scope, $resource, null, null, $this->config->accessTokenTtl())
			|| !$this->insertToken('refresh', $refresh, $clientRowid, $userId, $scope, $resource, null, null, $this->config->refreshTokenTtl())) {
			$this->error = 'server_error';
			return null;
		}

		$response = array(
			'access_token' => $access,
			'token_type' => 'Bearer',
			'expires_in' => $this->config->accessTokenTtl(),
			'refresh_token' => $refresh,
		);
		if (!empty($scope)) {
			$response['scope'] = $scope;
		}

		return $response;
	}

	/**
	 * Insert a token row (only the sha256 hash of the token is stored).
	 *
	 * @param string      $type          'code' | 'access' | 'refresh'
	 * @param string      $token         Clear token value
	 * @param int         $clientRowid   Client rowid
	 * @param int         $userId        User rowid
	 * @param string      $scope         Scope
	 * @param string      $resource      Resource indicator
	 * @param string|null $codeChallenge PKCE challenge (codes only)
	 * @param string|null $redirectUri   Redirect URI (codes only)
	 * @param int         $ttl           Lifetime in seconds
	 * @return bool
	 */
	private function insertToken($type, $token, $clientRowid, $userId, $scope, $resource, $codeChallenge, $redirectUri, $ttl)
	{
		global $conf;

		$sql = "INSERT INTO ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token";
		$sql .= " (token_type, token_hash, fk_client, fk_user, scope, resource, code_challenge, redirect_uri, expires_at, revoked, entity, datec)";
		$sql .= " VALUES ('".$this->db->escape($type)."',";
		$sql .= " '".$this->db->escape(hash('sha256', $token))."',";
		$sql .= " ".((int) $clientRowid).",";
		$sql .= " ".((int) $userId).",";
		$sql .= " ".($scope !== '' && $scope !== null ? "'".$this->db->escape($scope)."'" : "NULL").",";
		$sql .= " ".($resource !== '' && $resource !== null ? "'".$this->db->escape($resource)."'" : "NULL").",";
		$sql .= " ".($codeChallenge ? "'".$this->db->escape($codeChallenge)."'" : "NULL").",";
		$sql .= " ".($redirectUri ? "'".$this->db->escape($redirectUri)."'" : "NULL").",";
		$sql .= " '".$this->db->idate(dol_now() + $ttl)."',";
		$sql .= " 0,";
		$sql .= " ".((int) $conf->entity).",";
		$sql .= " '".$this->db->idate(dol_now())."')";

		if (!$this->db->query($sql)) {
			dol_syslog('['.$this->config->logPrefix.'] ERROR insertToken: '.$this->db->lasterror(), LOG_ERR);
			return false;
		}
		return true;
	}

	/**
	 * Fetch a non-revoked, non-expired token row by type + clear value.
	 *
	 * @param string $type  Token type
	 * @param string $token Clear token value
	 * @return object|null
	 */
	private function getValidToken($type, $token)
	{
		if (empty($token)) {
			return null;
		}

		$sql = "SELECT rowid, token_type, fk_client, fk_user, scope, resource, code_challenge, redirect_uri, expires_at, revoked";
		$sql .= " FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token";
		$sql .= " WHERE token_type = '".$this->db->escape($type)."'";
		$sql .= " AND token_hash = '".$this->db->escape(hash('sha256', $token))."'";
		$sql .= " AND revoked = 0";
		$sql .= " AND expires_at > '".$this->db->idate(dol_now())."'";

		$resql = $this->db->query($sql);
		if ($resql && $this->db->num_rows($resql) === 1) {
			return $this->db->fetch_object($resql);
		}
		return null;
	}

	/**
	 * Mark a token row as revoked, and say whether this call is the one that
	 * did it.
	 *
	 * The WHERE carries "revoked = 0" and the caller checks the rows touched,
	 * so the database decides which of two concurrent requests spends a code
	 * or a refresh token. Reading then writing let both through: measured on
	 * the same design, twelve parallel exchanges of one code produced five
	 * token pairs.
	 *
	 * @param int $rowid Token rowid
	 * @return bool True when this call revoked the row
	 */
	private function revokeToken($rowid)
	{
		$sql = "UPDATE ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token SET revoked = 1";
		$sql .= " WHERE rowid = ".((int) $rowid)." AND revoked = 0";

		$resql = $this->db->query($sql);
		if (!$resql) {
			return false;
		}

		return (int) $this->db->affected_rows($resql) === 1;
	}

	/**
	 * Say why a code or refresh token was not accepted, for logs only.
	 *
	 * @param string $type        'code' | 'refresh'
	 * @param string $value       Value presented
	 * @param int    $clientRowid Client that presented it
	 * @return string
	 */
	private function diagnoseInvalidToken($type, $value, $clientRowid)
	{
		$what = $type === 'code' ? 'authorization code' : 'refresh token';
		if (empty($value)) {
			return $what.' missing from the request';
		}

		$sql = "SELECT fk_client, expires_at, revoked FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token";
		$sql .= " WHERE token_type = '".$this->db->escape($type)."'";
		$sql .= " AND token_hash = '".$this->db->escape(hash('sha256', $value))."'";

		$resql = $this->db->query($sql);
		if (!$resql || $this->db->num_rows($resql) !== 1) {
			return $what.' unknown (never issued by this server, or purged since it expired)';
		}
		$obj = $this->db->fetch_object($resql);
		if ((int) $obj->fk_client !== (int) $clientRowid) {
			return $what.' was issued to another client';
		}
		if (!empty($obj->revoked)) {
			return $what.' already used or revoked; presenting it again revokes the whole grant';
		}

		return $what.' expired';
	}

	/**
	 * Revoke everything issued to a client for a user whose code or refresh
	 * token was presented a second time.
	 *
	 * A spent value coming back means someone else holds a copy, so the
	 * grant it belonged to is compromised and nothing issued under it may
	 * survive (OAuth 2.1 section 4.3.1, RFC 6749 section 4.1.2). A value that
	 * merely expired unused is not a replay and revokes nothing.
	 *
	 * @param string $type        'code' | 'refresh'
	 * @param string $value       Value presented
	 * @param int    $clientRowid Client that presented it
	 * @return void
	 */
	private function revokeReplayedFamily($type, $value, $clientRowid)
	{
		if (empty($value)) {
			return;
		}

		$sql = "SELECT fk_user FROM ".MAIN_DB_PREFIX.$this->config->tablePrefix."_oauth_token";
		$sql .= " WHERE token_type = '".$this->db->escape($type)."'";
		$sql .= " AND token_hash = '".$this->db->escape(hash('sha256', $value))."'";
		$sql .= " AND fk_client = ".((int) $clientRowid);
		$sql .= " AND revoked = 1";

		$resql = $this->db->query($sql);
		if (!$resql || $this->db->num_rows($resql) !== 1) {
			return;
		}
		$obj = $this->db->fetch_object($resql);

		$revoked = $this->revokeGrant($clientRowid, (int) $obj->fk_user);
		if ($revoked > 0) {
			dol_syslog('['.$this->config->logPrefix.'] Replayed '.$type.': revoked '.$revoked.' token(s) of client '.$clientRowid.' for user '.$obj->fk_user, LOG_WARNING);
		}
	}
}
