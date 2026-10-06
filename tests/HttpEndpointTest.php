<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Tests;
use DolibarrMcpOAuth\{HttpEndpoint, ExposureConfig, OAuthServer};
use DolibarrMcpOAuth\Tests\Fakes\FakeDoliDB;
use PHPUnit\Framework\TestCase;

final class HttpEndpointTest extends TestCase
{
    private function config(): ExposureConfig
    {
        return new ExposureConfig('emmcp', 'emcp_', 'EMMCP');
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

    public function testOauthTokenValidButLinkedUserUnavailableReturns401(): void
    {
        // A genuinely valid access token (issued through the real
        // authorization-code + PKCE exchange, same as OAuthServerTest) whose
        // fk_user has no corresponding row in llx_user: validateAccessToken()
        // succeeds but getUserApiKey() fails to resolve a REST API key.
        // Since 1.1.0 this is a 401: the user was disabled or their API key
        // removed, the access is over, and the client must go back through
        // sign-in and consent rather than retry.
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
        $this->assertSame(401, $r->httpCode);
        $this->assertSame('Access revoked for the linked Dolibarr user', $r->error);
        $this->assertNull($r->apiKey);
    }

    public function testSeesAuthorizationHeader(): void
    {
        $this->assertTrue(HttpEndpoint::seesAuthorizationHeader(['HTTP_AUTHORIZATION' => 'Bearer x']));
        $this->assertTrue(HttpEndpoint::seesAuthorizationHeader(['REDIRECT_HTTP_AUTHORIZATION' => 'Bearer x']));
        $this->assertFalse(HttpEndpoint::seesAuthorizationHeader([]));
    }
}
