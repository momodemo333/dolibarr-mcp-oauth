<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Support;

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
 * \file    src/Support/PackageLocator.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   Locate the embedded Dolibarr MCP server package's autoloader.
 */

final class PackageLocator
{
    /**
     * Resolve the autoloader of the embedded Dolibarr MCP server package.
     *
     * @param array $candidates Absolute candidate paths to autoload.php, in
     *                          preference order (the host module knows its
     *                          own paths, e.g. via dol_buildpath()).
     * @return string|null Absolute path to autoload.php, or null if not found
     */
    public static function findAutoloader(array $candidates): ?string
    {
        foreach ($candidates as $candidate) {
            if ($candidate && file_exists($candidate)) {
                return $candidate;
            }
        }
        return null;
    }
}
