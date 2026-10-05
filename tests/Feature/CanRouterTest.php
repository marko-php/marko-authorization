<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Feature;

use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authorization\Attributes\Can;
use Marko\Authorization\AuthorizableInterface;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Gate;
use Marko\Authorization\Middleware\AuthorizationMiddleware;
use Marko\Authorization\PolicyRegistry;
use Marko\Core\Container\Container;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;
use Marko\Routing\RouteMatcher;
use Marko\Routing\Router;
use Marko\Testing\Fake\FakeGuard;

class RouterPostController
{
    /** @noinspection PhpUnused - Invoked via the router */
    #[Can('edit')]
    public function edit(): Response
    {
        return new Response(body: 'edited');
    }

    /** @noinspection PhpUnused - Invoked via the router */
    public function index(): Response
    {
        return new Response(body: 'index');
    }
}

#[Can('admin.access')]
class RouterAdminController
{
    /** @noinspection PhpUnused - Invoked via the router */
    public function dashboard(): Response
    {
        return new Response(body: 'dashboard');
    }

    /** @noinspection PhpUnused - Invoked via the router */
    #[Can('admin.reports')]
    public function reports(): Response
    {
        return new Response(body: 'reports');
    }
}

class RouterStubUser implements AuthorizableInterface
{
    public function getAuthIdentifier(): int
    {
        return 1;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return 'hashed';
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken(
        ?string $token,
    ): void {}

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    public function can(
        string $ability,
        mixed ...$arguments,
    ): bool {
        return false;
    }
}

/**
 * Build a real Router with AuthorizationMiddleware registered as global
 * middleware, resolved by the real container exactly as in production.
 *
 * @param array<string, bool> $abilities
 */
function createAuthorizedRouter(
    array $abilities,
    bool $authenticated = true,
): Router {
    $guard = new FakeGuard(name: 'web', attemptResult: false);

    if ($authenticated) {
        $guard->setUser(new RouterStubUser());
    }

    $gate = new Gate(
        guard: $guard,
        policyRegistry: new PolicyRegistry(),
    );

    foreach ($abilities as $ability => $allowed) {
        $gate->define($ability, fn (?AuthorizableInterface $user): bool => $allowed);
    }

    $container = new Container();
    $container->instance(GuardInterface::class, $guard);
    $container->instance(GateInterface::class, $gate);

    $routes = new RouteCollection();
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/posts/edit',
        controller: RouterPostController::class,
        action: 'edit',
    ));
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/posts',
        controller: RouterPostController::class,
        action: 'index',
    ));
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/admin',
        controller: RouterAdminController::class,
        action: 'dashboard',
    ));
    $routes->add(new RouteDefinition(
        method: 'GET',
        path: '/admin/reports',
        controller: RouterAdminController::class,
        action: 'reports',
    ));

    return new Router(
        matcher: new RouteMatcher($routes),
        container: $container,
        globalMiddleware: [AuthorizationMiddleware::class],
    );
}

/**
 * @param array<string, string> $headers
 */
function createRouterRequest(
    string $path,
    array $headers = [],
): Request {
    return new Request(server: [
        'REQUEST_METHOD' => 'GET',
        'REQUEST_URI' => $path,
        ...$headers,
    ]);
}

it('returns 403 through the router when the gate denies a Can ability', function (): void {
    $router = createAuthorizedRouter(abilities: ['edit' => false]);

    $response = $router->handle(createRouterRequest('/posts/edit'));

    expect($response->statusCode())->toBe(403)
        ->and($response->body())->toBe('Forbidden');
});

it('returns 200 through the router when the gate allows a Can ability', function (): void {
    $router = createAuthorizedRouter(abilities: ['edit' => true]);

    $response = $router->handle(createRouterRequest('/posts/edit'));

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('edited');
});

it('returns plain 401 through the router for unauthenticated requests', function (): void {
    $router = createAuthorizedRouter(abilities: ['edit' => true], authenticated: false);

    $response = $router->handle(createRouterRequest('/posts/edit'));

    expect($response->statusCode())->toBe(401)
        ->and($response->body())->toBe('Unauthorized');
});

it('returns JSON 401 through the router for unauthenticated JSON requests', function (): void {
    $router = createAuthorizedRouter(abilities: ['edit' => true], authenticated: false);

    $response = $router->handle(createRouterRequest('/posts/edit', ['HTTP_ACCEPT' => 'application/json']));

    expect($response->statusCode())->toBe(401)
        ->and($response->body())->toBe('{"error":"Unauthorized"}');
});

it('passes routes without Can through the global middleware untouched', function (): void {
    $router = createAuthorizedRouter(abilities: [], authenticated: false);

    $response = $router->handle(createRouterRequest('/posts'));

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('index');
});

it('applies a class-level Can to every action', function (): void {
    $denied = createAuthorizedRouter(abilities: ['admin.access' => false]);
    $allowed = createAuthorizedRouter(abilities: ['admin.access' => true]);

    expect($denied->handle(createRouterRequest('/admin'))->statusCode())->toBe(403)
        ->and($allowed->handle(createRouterRequest('/admin'))->body())->toBe('dashboard');
});

it('lets a method-level Can override the class-level Can', function (): void {
    $router = createAuthorizedRouter(abilities: ['admin.access' => false, 'admin.reports' => true]);

    $response = $router->handle(createRouterRequest('/admin/reports'));

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('reports');
});
