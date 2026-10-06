<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Routing;

use Marko\Authorization\Attributes\Can;
use Marko\Authorization\Middleware\AuthorizationMiddleware;
use Marko\Authorization\Routing\CanAttributeReader;
use Marko\Authorization\Routing\CanRouteFinder;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;

class FinderPostController
{
    /** @noinspection PhpUnused - Read via reflection */
    #[Can('edit')]
    public function edit(): void {}

    /** @noinspection PhpUnused - Read via reflection */
    public function index(): void {}
}

#[Can('admin.access')]
class FinderAdminController
{
    /** @noinspection PhpUnused - Read via reflection */
    public function dashboard(): void {}
}

/**
 * @param array<int, string> $withoutMiddleware
 */
function finderRoute(
    string $controller,
    string $action,
    string $method = 'GET',
    array $withoutMiddleware = [],
): RouteDefinition {
    return new RouteDefinition(
        method: $method,
        path: '/' . strtolower(substr(strrchr($controller, '\\'), 1)) . "/$action/" . strtolower($method),
        controller: $controller,
        action: $action,
        withoutMiddleware: $withoutMiddleware,
    );
}

function finderRoutes(
    RouteDefinition ...$routes,
): RouteCollection {
    $collection = new RouteCollection();

    foreach ($routes as $route) {
        $collection->add($route);
    }

    return $collection;
}

it('returns the controller::action keys of routes with a method-level Can', function (): void {
    $routes = finderRoutes(finderRoute(FinderPostController::class, 'edit'));

    expect(new CanRouteFinder(new CanAttributeReader())->find($routes))
        ->toBe([FinderPostController::class . '::edit']);
});

it('includes routes protected by a class-level Can', function (): void {
    $routes = finderRoutes(finderRoute(FinderAdminController::class, 'dashboard'));

    expect(new CanRouteFinder(new CanAttributeReader())->find($routes))
        ->toBe([FinderAdminController::class . '::dashboard']);
});

it('skips routes without Can', function (): void {
    $routes = finderRoutes(finderRoute(FinderPostController::class, 'index'));

    expect(new CanRouteFinder(new CanAttributeReader())->find($routes))->toBe([]);
});

it('skips Can routes that exclude AuthorizationMiddleware', function (): void {
    $routes = finderRoutes(
        finderRoute(FinderPostController::class, 'edit', withoutMiddleware: [AuthorizationMiddleware::class]),
    );

    expect(new CanRouteFinder(new CanAttributeReader())->find($routes))->toBe([]);
});

it('lists an action once when several routes point to it', function (): void {
    $routes = finderRoutes(
        finderRoute(FinderPostController::class, 'edit'),
        finderRoute(FinderPostController::class, 'edit', 'POST'),
    );

    expect(new CanRouteFinder(new CanAttributeReader())->find($routes))
        ->toBe([FinderPostController::class . '::edit']);
});
