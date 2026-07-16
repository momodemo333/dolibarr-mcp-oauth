<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth\Tests;

use DolibarrMcpOAuth\{OAuthRouter, OAuthServer, ExposureConfig};
use DolibarrMcpOAuth\Tests\Fakes\FakeDoliDB;
use PHPUnit\Framework\TestCase;

final class OAuthRouterTest extends TestCase
{
    private function server(FakeDoliDB $db): OAuthServer
    {
        return new OAuthServer($db, new ExposureConfig('emmcp', 'emcp_', 'EMMCP'));
    }

    public function testAuthServerMetadataAdvertisesS256(): void
    {
        $server = $this->server(new FakeDoliDB());
        $config = new ExposureConfig('emmcp', 'emcp_', 'EMMCP');
        $r = new OAuthRouter($server, $config, 'https://x/oauth.php', 'https://x/mcp.php');
        $m = $r->metadataAuthorizationServer();
        $this->assertSame(['S256'], $m['code_challenge_methods_supported']);
        $this->assertSame('https://x/oauth.php/token', $m['token_endpoint']);
    }
    public function testTokenUnsupportedGrantReturns400(): void
    {
        $server = $this->server(new FakeDoliDB());
        $config = new ExposureConfig('emmcp', 'emcp_', 'EMMCP');
        $r = new OAuthRouter($server, $config, 'https://x/oauth.php', 'https://x/mcp.php');
        $out = $r->handleToken(fn($n,$d) => $n === 'grant_type' ? 'password' : '', []);
        $this->assertSame(400, $out['httpCode']);
        $this->assertSame('unsupported_grant_type', $out['payload']['error']);
    }
}
