<?php

declare(strict_types=1);

namespace Marko\Authorization\Exceptions;

use Marko\Core\Exceptions\MarkoException;
use Throwable;

/**
 * Routes use #[Can], but the guard that enforces it (or the Gate's policy
 * registry) cannot be built.
 *
 * Thrown at boot (live boots and `marko discovery:cache`), never while
 * handling a request, so it is a plain MarkoException rather than an HTTP one.
 */
class AuthorizationConfigurationException extends MarkoException
{
    private const int MAX_LISTED_ROUTES = 5;

    /**
     * @param ?string $guard The guard #[Can] authenticates with, or null when its name could not be read
     * @param array<int, string> $canRoutes "controller::action" keys of the routes protected by #[Can]
     */
    public static function cannotBuildForCan(
        ?string $guard,
        array $canRoutes,
        Throwable $previous,
    ): self {
        $guardLabel = $guard === null ? 'the default authentication guard' : "guard '$guard'";
        $listed = array_slice($canRoutes, 0, self::MAX_LISTED_ROUTES);
        $remaining = count($canRoutes) - count($listed);
        $routeList = implode(', ', $listed) . ($remaining > 0 ? " (and $remaining more)" : '');

        return new self(
            message: "Routes use #[Can], but $guardLabel cannot be built: {$previous->getMessage()}",
            context: "While checking the authorization setup at boot. #[Can] routes: $routeList",
            suggestion: 'Define the guard under authentication.guards (or set authorization.default_guard to a defined guard), '
                . 'bind a UserProviderInterface, install a session driver (such as marko/session-file) for a session guard, '
                . 'and bind a TokenRepositoryInterface for a token guard. '
                . 'If these routes should not be protected, remove #[Can] or exclude AuthorizationMiddleware with #[WithoutMiddleware].',
            previous: $previous,
        );
    }
}
