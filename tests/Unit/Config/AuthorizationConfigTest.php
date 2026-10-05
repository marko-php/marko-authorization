<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Config;

use Marko\Authorization\Config\AuthorizationConfig;
use Marko\Config\ConfigRepository;
use Marko\Config\Exceptions\ConfigException;
use Marko\Testing\Fake\FakeConfigRepository;

function shippedAuthorizationConfig(): AuthorizationConfig
{
    return new AuthorizationConfig(
        config: new ConfigRepository([
            'authorization' => require dirname(__DIR__, 3) . '/config/authorization.php',
        ]),
    );
}

it('creates AuthorizationConfig with default guard accessor', function (): void {
    $config = new AuthorizationConfig(
        config: new FakeConfigRepository([
            'authorization.default_guard' => 'web',
        ]),
    );

    expect($config->defaultGuard())->toBe('web');
});

it('returns configured default guard', function (): void {
    $config = new AuthorizationConfig(
        config: new FakeConfigRepository([
            'authorization.default_guard' => 'api',
        ]),
    );

    expect($config->defaultGuard())->toBe('api');
});

it('returns null for the shipped config so the authentication default guard is used', function (): void {
    expect(shippedAuthorizationConfig()->defaultGuard())->toBeNull();
});

it('returns null when the default guard is an empty string', function (): void {
    $config = new AuthorizationConfig(
        config: new ConfigRepository(['authorization' => ['default_guard' => '']]),
    );

    expect($config->defaultGuard())->toBeNull();
});

it('throws a ConfigException when the default guard is not a string or null', function (): void {
    $config = new AuthorizationConfig(
        config: new ConfigRepository(['authorization' => ['default_guard' => ['web']]]),
    );

    expect(fn (): ?string => $config->defaultGuard())->toThrow(ConfigException::class);
});
