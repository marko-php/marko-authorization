<?php

declare(strict_types=1);

namespace Marko\Authorization\Routing;

use Marko\Authorization\Middleware\AuthorizationMiddleware;
use Marko\Routing\RouteCollection;
use Marko\Routing\RouteDefinition;
use ReflectionException;

/**
 * Finds the routes that AuthorizationMiddleware will enforce #[Can] on.
 *
 * A route counts when its action (or controller class) carries #[Can] and it
 * does not exclude AuthorizationMiddleware with #[WithoutMiddleware]. Reads
 * attributes through reflection, so it only runs on live boots and while
 * compiling the discovery cache.
 */
readonly class CanRouteFinder
{
    public function __construct(
        private CanAttributeReader $canAttributeReader,
    ) {}

    /**
     * @return array<int, string> "controller::action" keys, each listed once, in route order
     *
     * @throws ReflectionException
     */
    public function find(
        RouteCollection $routes,
    ): array {
        $keys = [];

        foreach ($routes->all() as $route) {
            if ($this->isEnforced($route)) {
                $keys[$route->controller . '::' . $route->action] = true;
            }
        }

        return array_keys($keys);
    }

    /**
     * @throws ReflectionException
     */
    private function isEnforced(
        RouteDefinition $route,
    ): bool {
        if (in_array(AuthorizationMiddleware::class, $route->withoutMiddleware, true)) {
            return false;
        }

        return $this->canAttributeReader->read($route->controller, $route->action) !== null;
    }
}
