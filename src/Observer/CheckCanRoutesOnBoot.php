<?php

declare(strict_types=1);

namespace Marko\Authorization\Observer;

use Marko\Authorization\Exceptions\AuthorizationConfigurationException;
use Marko\Authorization\Routing\CanConfigurationValidator;
use Marko\Core\Attributes\Observer;
use Marko\Core\Container\ContainerInterface;
use Marko\Core\Discovery\CachedDiscovery;
use Marko\Core\Event\ApplicationBooted;
use Marko\Routing\RouteCollection;
use Psr\Container\ContainerExceptionInterface;
use ReflectionException;

/**
 * Fails a live boot when routes use #[Can] but the guard cannot be built.
 *
 * Runs after every module boot callback (ApplicationBooted), so guard drivers
 * that any module registers from its boot callback already exist. Live boots
 * cover development and `marko discovery:cache`, which always boots live, so
 * a broken setup never produces a cache.
 *
 * A boot served from the discovery cache does nothing: no route reflection
 * and no guard. Under PHP-FPM every request is a boot, and that cache was
 * built by a live boot that passed this check. The only collaborators
 * resolved before that early return are the two injected here; the validator
 * and the route list are resolved only on a live boot.
 */
#[Observer(event: ApplicationBooted::class)]
readonly class CheckCanRoutesOnBoot
{
    public function __construct(
        private CachedDiscovery $cachedDiscovery,
        private ContainerInterface $container,
    ) {}

    /**
     * @throws AuthorizationConfigurationException|ContainerExceptionInterface|ReflectionException
     */
    public function handle(
        ApplicationBooted $event,
    ): void {
        if ($this->cachedDiscovery->isCached()) {
            return;
        }

        $this->container->get(CanConfigurationValidator::class)->validate(
            $this->container->get(RouteCollection::class),
        );
    }
}
