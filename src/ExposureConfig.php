<?php
declare(strict_types=1);
namespace DolibarrMcpOAuth;

final class ExposureConfig
{
    public const ACCESS_TOKEN_TTL = 3600;
    public const REFRESH_TOKEN_TTL = 2592000;
    public const AUTH_CODE_TTL = 120;

    public function __construct(
        public readonly string $tablePrefix,
        public readonly string $tokenPrefix,
        public readonly string $logPrefix,
        public readonly string $moduleSlug,
    ) {
    }

    public function accessTokenTtl(): int { return self::ACCESS_TOKEN_TTL; }
    public function refreshTokenTtl(): int { return self::REFRESH_TOKEN_TTL; }
    public function authCodeTtl(): int { return self::AUTH_CODE_TTL; }
}
