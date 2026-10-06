<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Routing;

use Closure;
use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authorization\Attributes\Can;
use Marko\Authorization\Config\AuthorizationConfig;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Exceptions\AuthorizationConfigurationException;
use Marko\Authorization\PolicyRegistry;
use Marko\Authorization\Routing\CanAttributeReader;
use Marko\Authorization\Routing\CanConfigurationValidator;
use Marko\Authorization\Routing\CanRouteFinder;
use Marko\Core\Container\Container;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;
use Marko\Testing\Fake\FakeConfigRepository;
use Marko\Testing\Fake\FakeGuard;
use RuntimeException;

class ValidatorController
{
    /** @noinspection PhpUnused - Read via reflection */
    #[Can('edit')]
    public function edit(): void {}

    /** @noinspection PhpUnused - Read via reflection */
    public function index(): void {}
}

/**
 * An AuthManager whose guard() is a test double: it records the requested
 * names and returns or throws whatever $build does.
 */
class ValidatorAuthManager extends AuthManager
{
    /** @var array<int, ?string> */
    public array $requested = [];

    /**
     * @param Closure(?string): GuardInterface $build
     * @noinspection PhpMissingParentConstructorInspection - Test double skips the real dependencies
     */
    public function __construct(
        private readonly Closure $build,
    ) {}

    public function guard(
        ?string $name = null,
    ): GuardInterface {
        $this->requested[] = $name;

        return ($this->build)($name);
    }
}

function validatorRoutes(
    string $action,
): RouteCollection {
    $routes = new RouteCollection();
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: "/$action",
        controller: ValidatorController::class,
        action: $action,
    ));

    return $routes;
}

/**
 * @param array<string, mixed> $config
 */
function validatorContainer(
    ValidatorAuthManager $authManager,
    array $config = ['authorization.default_guard' => null, 'authentication.default.guard' => 'web'],
): Container {
    $configRepository = new FakeConfigRepository($config);
    $container = new Container();
    $container->instance(AuthManager::class, $authManager);
    $container->instance(AuthorizationConfig::class, new AuthorizationConfig($configRepository));
    $container->instance(AuthConfig::class, new AuthConfig($configRepository));
    $container->bind(GateInterface::class, fn (): GateInterface => throw new RuntimeException('Gate must stay lazy'));

    return $container;
}

function canValidator(
    Container $container,
): CanConfigurationValidator {
    return new CanConfigurationValidator(new CanRouteFinder(new CanAttributeReader()), $container);
}

it('builds nothing when no route uses Can', function (): void {
    $authManager = new ValidatorAuthManager(fn (): GuardInterface => throw new RuntimeException('must not build'));

    $result = canValidator(validatorContainer($authManager))->validate(validatorRoutes('index'));

    expect($result)->toBe([])
        ->and($authManager->requested)->toBe([]);
});

it('builds the authorization guard when a route uses Can', function (): void {
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard(name: $name ?? 'web'));

    canValidator(validatorContainer($authManager))->validate(validatorRoutes('edit'));

    expect($authManager->requested)->toBe(['web']);
});

it('never resolves the GateInterface singleton', function (): void {
    // validatorContainer() binds GateInterface to a factory that throws.
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard(name: $name ?? 'web'));

    expect(canValidator(validatorContainer($authManager))->validate(validatorRoutes('edit')))
        ->toBe([ValidatorController::class . '::edit']);
});

it('builds the guard named by authorization.default_guard', function (): void {
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard(name: $name ?? 'web'));
    $container = validatorContainer($authManager, [
        'authorization.default_guard' => 'api',
        'authentication.default.guard' => 'web',
    ]);

    canValidator($container)->validate(validatorRoutes('edit'));

    expect($authManager->requested)->toBe(['api']);
});

it('returns the Can route keys', function (): void {
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard(name: $name ?? 'web'));

    expect(canValidator(validatorContainer($authManager))->validate(validatorRoutes('edit')))
        ->toBe([ValidatorController::class . '::edit']);
});

it('throws AuthorizationConfigurationException naming the guard when the guard cannot be built', function (): void {
    $cause = new RuntimeException('No UserProviderInterface binding');
    $authManager = new ValidatorAuthManager(fn (): GuardInterface => throw $cause);

    try {
        canValidator(validatorContainer($authManager))->validate(validatorRoutes('edit'));
        $this->fail('Expected AuthorizationConfigurationException');
    } catch (AuthorizationConfigurationException $e) {
        expect($e->getMessage())->toContain("guard 'web'")
            ->toContain('No UserProviderInterface binding')
            ->and($e->getContext())->toContain(ValidatorController::class . '::edit')
            ->and($e->getPrevious())->toBe($cause);
    }
});

it('names the default authentication guard when its name cannot be read', function (): void {
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard());

    // No authentication.default.guard: reading the guard name itself fails.
    $container = validatorContainer($authManager, ['authorization.default_guard' => null]);

    expect(fn () => canValidator($container)->validate(validatorRoutes('edit')))
        ->toThrow(AuthorizationConfigurationException::class, 'the default authentication guard');
});

it('throws when the policy registry cannot be built', function (): void {
    $authManager = new ValidatorAuthManager(fn (?string $name): GuardInterface => new FakeGuard(name: $name ?? 'web'));
    $container = validatorContainer($authManager);
    $container->bind(PolicyRegistry::class, fn (): PolicyRegistry => throw new RuntimeException('Registry broken'));

    expect(fn () => canValidator($container)->validate(validatorRoutes('edit')))
        ->toThrow(AuthorizationConfigurationException::class, 'Registry broken');
});
