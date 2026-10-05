<?php

declare(strict_types=1);

use Marko\Authentication\AuthManager;
use Marko\Authorization\Config\AuthorizationConfig;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Gate;
use Marko\Authorization\Middleware\AuthorizationMiddleware;
use Marko\Authorization\PolicyRegistry;
use Marko\Core\Container\ContainerInterface;

return [
    // SessionMiddleware is registered globally by the session drivers; it must run first.
    'sequence' => [
        'after' => ['marko/session-file', 'marko/session-database'],
    ],
    'bindings' => [
        GateInterface::class => function (ContainerInterface $container): GateInterface {
            $authManager = $container->get(AuthManager::class);
            $config = $container->get(AuthorizationConfig::class);
            $defaultGuard = $config->defaultGuard();

            return new Gate(
                guard: $authManager->guard($defaultGuard),
                policyRegistry: $container->get(PolicyRegistry::class),
            );
        },
        // Check authentication against the same guard the Gate authorizes with.
        AuthorizationMiddleware::class => function (ContainerInterface $container): AuthorizationMiddleware {
            $authManager = $container->get(AuthManager::class);
            $config = $container->get(AuthorizationConfig::class);

            return new AuthorizationMiddleware(
                gate: $container->get(GateInterface::class),
                guard: $authManager->guard($config->defaultGuard()),
            );
        },
    ],
    'singletons' => [
        PolicyRegistry::class,
        GateInterface::class,
        AuthorizationMiddleware::class,
    ],
    'globalMiddleware' => [
        AuthorizationMiddleware::class,
    ],
];
