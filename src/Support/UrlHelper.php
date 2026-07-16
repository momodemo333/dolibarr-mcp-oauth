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
 * \file    src/Support/UrlHelper.php
 * \ingroup dolibarr-mcp-oauth
 * \brief   URL and HTML helpers shared by MCP-enabled Dolibarr modules.
 */

final class UrlHelper
{
    /**
     * Build a public absolute URL for a module file, forcing https when the
     * current request reached us over TLS.
     *
     * dol_buildpath(..., 2) derives the scheme from DOL_MAIN_URL_ROOT, which is
     * often http when Dolibarr sits behind a TLS-terminating reverse proxy
     * (Traefik, nginx). OAuth 2.1 / the MCP authorization spec require https for
     * every endpoint and redirect URI (localhost excepted), so we upgrade the
     * scheme based on the real request when it was encrypted.
     *
     * @param string $relpath Module-relative path, e.g. '/emmcp/oauth.php'
     * @return string Absolute URL
     */
    public static function publicUrl(string $relpath): string
    {
        return self::upgradeScheme(dol_buildpath($relpath, 2), $_SERVER);
    }

    /**
     * Pure scheme-upgrade seam, testable without Dolibarr or a real request.
     *
     * @param string $url    URL to inspect/rewrite
     * @param array  $server $_SERVER-like array (HTTPS, HTTP_X_FORWARDED_PROTO, SERVER_PORT)
     * @return string $url, upgraded from http:// to https:// when $server indicates TLS
     */
    public static function upgradeScheme(string $url, array $server): string
    {
        $isHttps = (!empty($server['HTTPS']) && $server['HTTPS'] !== 'off')
            || (($server['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https')
            || ((int) ($server['SERVER_PORT'] ?? 0) === 443);

        if ($isHttps && str_starts_with($url, 'http://')) {
            $url = 'https://'.substr($url, 7);
        }

        return $url;
    }

    /**
     * Build a redirect URL by appending query parameters, the same way the
     * source emMCP oauth.php's local emmcp_oauth_redirect() helper does:
     * '?' when $uri has no query string yet, '&' when it already has one
     * (a registered redirect_uri may already carry its own query params).
     *
     * @param string $uri    Validated redirect URI
     * @param array  $params Query parameters to append
     * @return string $uri with $params appended to its query string
     */
    public static function buildRedirect(string $uri, array $params): string
    {
        return $uri.(strpos($uri, '?') === false ? '?' : '&').http_build_query($params);
    }

    /**
     * Render a read-only code block with a native "copy to clipboard" button.
     *
     * Uses htmlspecialchars (not dol_escape_htmltag) so real newlines in the
     * snippet are preserved inside the <pre>, and Dolibarr's
     * showValueWithClipboardCPButton() for the copy button (value carried with
     * newlines intact via its $keepn handling).
     *
     * @param string $code  The snippet to display and copy (may be multi-line)
     * @param string $label Optional heading shown above the block
     * @return string HTML
     */
    public static function codeBlock(string $code, string $label = ''): string
    {
        $html = '';
        if ($label !== '') {
            $html .= '<div class="paddingtop"><strong>'.dol_escape_htmltag($label).'</strong> ';
            // texttoshow='none' → render only the copy button (value hidden)
            $html .= showValueWithClipboardCPButton($code, 0, 'none');
            $html .= '</div>';
        }
        $html .= '<pre class="mcp-code">'.htmlspecialchars($code, ENT_QUOTES, 'UTF-8').'</pre>';

        return $html;
    }
}
