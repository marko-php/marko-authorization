<?php

declare(strict_types=1);

namespace Marko\Authorization;

use Marko\Authorization\Exceptions\PolicyException;

class PolicyRegistry
{
    /** @var array<class-string, class-string> */
    private array $policies = [];

    /**
     * Register a policy class for an entity class.
     *
     * @param class-string $entityClass
     * @param class-string $policyClass
     * @throws PolicyException
     */
    public function register(
        string $entityClass,
        string $policyClass,
    ): void {
        if (isset($this->policies[$entityClass])) {
            throw PolicyException::duplicatePolicy(
                entityClass: $entityClass,
                policyClass: $policyClass,
                existing: $this->policies[$entityClass],
            );
        }

        $this->policies[$entityClass] = $policyClass;
    }

    /**
     * Resolve the policy class for the given entity.
     *
     * @param class-string $entityClass
     * @return class-string|null
     */
    public function resolve(
        string $entityClass,
    ): ?string {
        return $this->policies[$entityClass] ?? null;
    }

    /**
     * Check if a policy has a method for the given ability.
     */
    public function hasAbility(
        string $policyClass,
        string $ability,
    ): bool {
        return method_exists($policyClass, $ability);
    }
}
