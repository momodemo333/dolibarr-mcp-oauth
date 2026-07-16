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
 * \file    src/AuthorizeDecision.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Outcome of OAuthRouter::validateAuthorizeRequest().
 *
 * Two distinct failure shapes mirror the source emMCP oauth.php /authorize
 * branch:
 *   - client/redirect_uri could not be validated: there is no safe redirect
 *     target (open redirect protection), so $redirectUri is null and the
 *     module must render an inline error page (optionally using $httpCode).
 *   - client/redirect_uri are valid but response_type or PKCE are wrong:
 *     $redirectUri is set (validated) and the module must 302-redirect back
 *     to the client with {error, state} as query parameters.
 * When $valid is true, $client/$redirectUri/$codeChallenge/$scope/$state
 * carry everything the module needs to render the consent screen.
 */
final class AuthorizeDecision
{
    /**
     * @param bool        $valid        Whether the request may proceed to consent
     * @param object|null $client       Resolved client row (null only on the no-redirect error)
     * @param string|null $redirectUri  Validated redirect_uri (null only on the no-redirect error)
     * @param string|null $codeChallenge PKCE S256 challenge (set only when $valid)
     * @param string|null $scope        Requested scope
     * @param string|null $state        Opaque state to echo back
     * @param string|null $error        Error identifier/message, when $valid is false
     * @param int|null    $httpCode     HTTP status to use for a non-redirect error response
     * @param string|null $errorDescription Human-readable detail to accompany $error (mirrors
     *                                  the source's error_description query parameter), when set
     * @param string|null $resource     RFC 8707 resource indicator from the request, carried
     *                                  through so the consent glue doesn't have to re-read it
     */
    public function __construct(
        public readonly bool $valid,
        public readonly ?object $client = null,
        public readonly ?string $redirectUri = null,
        public readonly ?string $codeChallenge = null,
        public readonly ?string $scope = null,
        public readonly ?string $state = null,
        public readonly ?string $error = null,
        public readonly ?int $httpCode = null,
        public readonly ?string $errorDescription = null,
        public readonly ?string $resource = null,
    ) {
    }
}
