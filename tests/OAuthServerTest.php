<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Tests;

use DolibarrMcpOAuth\{OAuthServer, ExposureConfig};
use DolibarrMcpOAuth\Tests\Fakes\FakeDoliDB;
use PHPUnit\Framework\TestCase;

final class OAuthServerTest extends TestCase
{
    private function server(FakeDoliDB $db): OAuthServer
    {
        return new OAuthServer($db, new ExposureConfig('emmcp', 'emcp_', 'EMMCP'));
    }

    public function testRegisterClientRejectsMissingRedirectUris(): void
    {
        $db = new FakeDoliDB();
        $out = $this->server($db)->registerClient([]);
        $this->assertNull($out);
    }

    public function testRegisterPublicClientReturnsClientIdWithConfiguredPrefix(): void
    {
        $db = new FakeDoliDB();
        $out = $this->server($db)->registerClient(['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']]);
        $this->assertStringStartsWith('emcp_client_', $out['client_id']);
        $this->assertSame('none', $out['token_endpoint_auth_method']);
    }

    public function testExchangeAuthorizationCodeValidatesPkceS256(): void
    {
        // verifier/challenge computed the RFC 7636 way; wrong verifier must fail
        $verifier = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdef123';
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $db = new FakeDoliDB();
        $srv = $this->server($db);
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $code = $srv->createAuthorizationCode($client, 7, 'https://claude.ai/api/mcp/auth_callback', $challenge, 'dolibarr', 'https://x/mcp.php');
        $this->assertNull($srv->exchangeAuthorizationCode($client, $code, 'https://claude.ai/api/mcp/auth_callback', 'WRONG-verifier'));
        $tokens = $srv->exchangeAuthorizationCode($client, $srv->createAuthorizationCode($client, 7, 'https://claude.ai/api/mcp/auth_callback', $challenge, 'dolibarr', 'https://x/mcp.php'), 'https://claude.ai/api/mcp/auth_callback', $verifier);
        $this->assertStringStartsWith('emcp_a', $tokens['access_token']);
        $this->assertStringStartsWith('emcp_r', $tokens['refresh_token']);
    }

    public function testTableNameUsesConfiguredPrefix(): void
    {
        $db = new FakeDoliDB();
        (new OAuthServer($db, new ExposureConfig('dalfred', 'dcp_', 'DALFRED')))
            ->registerClient(['redirect_uris' => ['https://claude.ai/api/mcp/auth_callback']]);
        $this->assertStringContainsString('llx_dalfred_oauth_client', $db->lastInsertTable());
    }

    public function testAuthorizationCodeIsOneShotAndCannotBeReplayed(): void
    {
        // A code is revoked the instant it is redeemed (source emMCP
        // comment: "One-shot: revoke immediately, whatever happens next"),
        // so a second exchange of the very same code must fail even though
        // the first exchange succeeded.
        $verifier = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdef123';
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $db = new FakeDoliDB();
        $srv = $this->server($db);
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $code = $srv->createAuthorizationCode($client, 7, 'https://claude.ai/api/mcp/auth_callback', $challenge, 'dolibarr', 'https://x/mcp.php');

        $first = $srv->exchangeAuthorizationCode($client, $code, 'https://claude.ai/api/mcp/auth_callback', $verifier);
        $this->assertNotNull($first, 'sanity: first exchange of a fresh code must succeed');

        $second = $srv->exchangeAuthorizationCode($client, $code, 'https://claude.ai/api/mcp/auth_callback', $verifier);
        $this->assertNull($second, 'replaying the same authorization code must fail (invalid_grant)');
        $this->assertSame('invalid_grant', $srv->error);
    }

    private function grant(OAuthServer $srv, object $client, int $user = 7): array
    {
        $verifier = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdef123';
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $code = $srv->createAuthorizationCode($client, $user, 'https://claude.ai/api/mcp/auth_callback', $challenge, 'dolibarr', 'https://x/mcp.php');
        $tokens = $srv->exchangeAuthorizationCode($client, $code, 'https://claude.ai/api/mcp/auth_callback', $verifier);

        return array('code' => $code, 'tokens' => $tokens, 'verifier' => $verifier);
    }

    public function testReplayedCodeRevokesTheTokensItIssued(): void
    {
        $db = new FakeDoliDB();
        $srv = $this->server($db);
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $g = $this->grant($srv, $client);
        $this->assertNotNull($srv->validateAccessToken($g['tokens']['access_token']));

        $this->assertNull($srv->exchangeAuthorizationCode($client, $g['code'], 'https://claude.ai/api/mcp/auth_callback', $g['verifier']));
        $this->assertNull($srv->validateAccessToken($g['tokens']['access_token']), 'tokens issued from a replayed code must be revoked');
    }

    public function testReplayedRefreshTokenRevokesTheFamily(): void
    {
        $db = new FakeDoliDB();
        $srv = $this->server($db);
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $g = $this->grant($srv, $client);

        $rotated = $srv->refreshTokens($client, $g['tokens']['refresh_token']);
        $this->assertNotNull($rotated);
        $this->assertNull($srv->refreshTokens($client, $g['tokens']['refresh_token']), 'a refresh token works once');
        $this->assertNull($srv->validateAccessToken($rotated['access_token']), 'the replay revokes what the rotation issued');
        $this->assertNull($srv->refreshTokens($client, $rotated['refresh_token']));
    }

    public function testRevokeGrantEndsTheAccess(): void
    {
        $db = new FakeDoliDB();
        $srv = $this->server($db);
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $g = $this->grant($srv, $client);

        $this->assertGreaterThan(0, $srv->revokeGrant(1, 7));
        $this->assertNull($srv->validateAccessToken($g['tokens']['access_token']));
        $this->assertNull($srv->refreshTokens($client, $g['tokens']['refresh_token']));
    }
}
