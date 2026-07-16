<?php
namespace DolibarrMcpOAuth\Tests\Support;
use DolibarrMcpOAuth\Support\UrlHelper;
use PHPUnit\Framework\TestCase;

final class UrlHelperTest extends TestCase
{
    public function testUpgradesHttpToHttpsWhenForwardedProtoHttps(): void
    {
        $this->assertSame('https://x/y', UrlHelper::upgradeScheme('http://x/y', ['HTTP_X_FORWARDED_PROTO' => 'https']));
    }
    public function testLeavesHttpWhenNotTls(): void
    {
        $this->assertSame('http://x/y', UrlHelper::upgradeScheme('http://x/y', []));
    }
    public function testLeavesHttpsUntouched(): void
    {
        $this->assertSame('https://x/y', UrlHelper::upgradeScheme('https://x/y', ['SERVER_PORT' => '443']));
    }
}
