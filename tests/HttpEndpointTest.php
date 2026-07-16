<?php
namespace DolibarrMcpOAuth\Tests;
use DolibarrMcpOAuth\{HttpEndpoint, ExposureConfig, OAuthServer};
use DolibarrMcpOAuth\Tests\Fakes\FakeDoliDB;
use PHPUnit\Framework\TestCase;

final class HttpEndpointTest extends TestCase
{
    private function config(): ExposureConfig
    {
        return new ExposureConfig('emmcp', 'emcp_', 'EMMCP', 'emmcp');
    }

    private function ep(FakeDoliDB $db): HttpEndpoint
    {
        return new HttpEndpoint($db, $this->config());
    }
    public function testMissingCredentialsReturns401(): void
    {
        $r = $this->ep(new FakeDoliDB())->resolveApiKey([], fn($n,$d) => '');
        $this->assertSame(401, $r->httpCode);
        $this->assertNull($r->apiKey);
    }
    public function testBearerFromRedirectHeaderIsRead(): void
    {
        // apache/FPM fallback: token arrives as REDIRECT_HTTP_AUTHORIZATION
        $db = new FakeDoliDB(); $db->seedUserApiKey('KEY123');
        $r = $this->ep($db)->resolveApiKey(['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer KEY123'], fn($n,$d) => '');
        $this->assertSame('KEY123', $r->apiKey);
    }
    public function testUnknownOauthTokenReturns401(): void
    {
        $r = $this->ep(new FakeDoliDB())->resolveApiKey(['HTTP_AUTHORIZATION' => 'Bearer emcp_a000'], fn($n,$d) => '');
        $this->assertSame(401, $r->httpCode);
    }

    public function testOauthTokenValidButLinkedUserUnavailableReturns403(): void
    {
        // A genuinely valid access token (issued through the real
        // authorization-code + PKCE exchange, same as OAuthServerTest) whose
        // fk_user has no corresponding row in llx_user: validateAccessToken()
        // succeeds but getUserApiKey() fails to resolve a REST API key.
        // Per the emMCP source (htdocs/custom/emmcp/mcp.php ~L163), this must
        // be a 403, distinct from the 401 used for an invalid/expired token.
        $db = new FakeDoliDB();
        $oauth = new OAuthServer($db, $this->config());

        $verifier = 'abcdefabcdefabcdefabcdefabcdefabcdefabcdef123';
        $challenge = rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
        $client = (object) ['rowid' => 1, 'token_endpoint_auth_method' => 'none'];
        $code = $oauth->createAuthorizationCode($client, 999, 'https://claude.ai/api/mcp/auth_callback', $challenge, 'dolibarr', 'https://x/mcp.php');
        $tokens = $oauth->exchangeAuthorizationCode($client, $code, 'https://claude.ai/api/mcp/auth_callback', $verifier);
        $this->assertNotNull($tokens, 'sanity: token exchange must succeed for this test to be meaningful');

        // No llx_user row seeded for user 999: getUserApiKey() will fail.
        $r = $this->ep($db)->resolveApiKey(['HTTP_AUTHORIZATION' => 'Bearer '.$tokens['access_token']], fn($n,$d) => '');
        $this->assertSame(403, $r->httpCode);
        $this->assertSame('Access token valid but the linked Dolibarr user is unavailable', $r->error);
        $this->assertNull($r->apiKey);
    }
}
