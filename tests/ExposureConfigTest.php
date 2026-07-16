<?php
namespace DolibarrMcpOAuth\Tests;
use DolibarrMcpOAuth\ExposureConfig;
use PHPUnit\Framework\TestCase;

final class ExposureConfigTest extends TestCase
{
    public function testHoldsPrefixesAndTtls(): void
    {
        $c = new ExposureConfig(tablePrefix: 'emmcp', tokenPrefix: 'emcp_', logPrefix: 'EMMCP');
        $this->assertSame('emmcp', $c->tablePrefix);
        $this->assertSame('emcp_', $c->tokenPrefix);
        $this->assertSame('EMMCP', $c->logPrefix);
        $this->assertSame(3600, $c->accessTokenTtl());
        $this->assertSame(2592000, $c->refreshTokenTtl());
        $this->assertSame(120, $c->authCodeTtl());
    }
}
