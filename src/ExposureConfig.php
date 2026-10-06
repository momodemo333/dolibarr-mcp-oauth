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
 * \file    src/ExposureConfig.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Per-host-module parameterization: table/token/log prefixes and
 *          the shared access/refresh/auth-code TTL constants.
 */
final class ExposureConfig
{
    public const ACCESS_TOKEN_TTL = 3600;
    public const REFRESH_TOKEN_TTL = 2592000;
    public const AUTH_CODE_TTL = 120;
    public const REGISTRATIONS_PER_HOUR = 50;

    public function __construct(
        public readonly string $tablePrefix,
        public readonly string $tokenPrefix,
        public readonly string $logPrefix,
    ) {
    }

    public function accessTokenTtl(): int { return self::ACCESS_TOKEN_TTL; }
    public function refreshTokenTtl(): int { return self::REFRESH_TOKEN_TTL; }
    public function authCodeTtl(): int { return self::AUTH_CODE_TTL; }
    public function registrationsPerHour(): int { return self::REGISTRATIONS_PER_HOUR; }
}
