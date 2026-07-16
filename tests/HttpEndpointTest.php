<?php
namespace DolibarrMcpOAuth\Tests;
use DolibarrMcpOAuth\{HttpEndpoint, ExposureConfig};
use DolibarrMcpOAuth\Tests\Fakes\FakeDoliDB;
use PHPUnit\Framework\TestCase;

final class HttpEndpointTest extends TestCase
{
    private function ep(FakeDoliDB $db): HttpEndpoint
    {
        return new HttpEndpoint($db, new ExposureConfig('emmcp', 'emcp_', 'EMMCP', 'emmcp'));
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
}
