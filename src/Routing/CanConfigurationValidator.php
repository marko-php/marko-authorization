<?php

declare(strict_types=1);

namespace Marko\Authorization\Routing;

use Marko\Authentication\AuthManager;
use Marko\Authentication\Config\AuthConfig;
use Marko\Authorization\Config\AuthorizationConfig;
use Marko\Authorization\Exceptions\AuthorizationConfigurationException;
use Marko\Authorization\PolicyRegistry;
use Marko\Core\Container\ContainerInterface;
use Marko\Routing\RouteCollection;
use ReflectionException;
use Throwable;

/**
 * Proves at boot that #[Can] routes can be enforced.
 *
 * When any route uses #[Can], builds the guard AuthorizationMiddleware
 * authenticates with (the same guard the Gate authorizes with) and the
 * Gate's PolicyRegistry, exactly once. Any failure becomes an
 * AuthorizationConfigurationException naming the guard and the #[Can] routes, instead of an error on the first #[Can] request.
 * Apps without #[Can] routes build nothing, so they still boot without any
 * authentication configuration.
 *
 * The GateInterface singleton itself is never built here. It keeps the guard
 * it is built with, so building it at boot would pin that guard and ignore a
 * guard swapped in later through AuthManager::useGuard() (as the HTTP test
 * client's actingAs() does). The Gate is still built lazily, on the first
 * #[Can] request.
 *
 * The services are resolved through the container on purpose: the point is
 * to check that the container can build them, and to wrap whatever it throws.
 */
readonly class CanConfigurationValidator
{
    public function __construct(
        private CanRouteFinder $canRouteFinder,
        private ContainerInterface $container,
    ) {}

    /**
     * @return array<int, string> "controller::action" keys of the #[Can] routes
     *
     * @throws AuthorizationConfigurationException|ReflectionException
     */
    public function validate(
        RouteCollection $routes,
    ): array {
        $canRoutes = $this->canRouteFinder->find($routes);

        if ($canRoutes === []) {
            return [];
        }

        $guard = null;

        try {
            $guard = $this->container->get(AuthorizationConfig::class)->defaultGuard()
                ?? $this->container->get(AuthConfig::class)->defaultGuard();
            $this->container->get(AuthManager::class)->guard($guard);
            $this->container->get(PolicyRegistry::class);
        } catch (Throwable $e) {
            throw AuthorizationConfigurationException::cannotBuildForCan($guard, $canRoutes, $e);
        }

        return $canRoutes;
    }
}
