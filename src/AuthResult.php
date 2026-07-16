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
 * \file    src/AuthResult.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Outcome of HttpEndpoint::resolveApiKey().
 */

final class AuthResult
{
    /**
     * @param string|null $apiKey   Effective Dolibarr REST API key, when authentication succeeded
     * @param int|null    $httpCode HTTP status code to emit, when authentication failed (e.g. 401)
     * @param string|null $error    Human-readable error message, when authentication failed
     */
    public function __construct(
        public readonly ?string $apiKey = null,
        public readonly ?int $httpCode = null,
        public readonly ?string $error = null,
    ) {
    }
}
