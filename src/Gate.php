<?php

declare(strict_types=1);

namespace Marko\Authorization;

use Marko\Authentication\Contracts\AbilityScopedGuardInterface;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Exceptions\AuthorizationException;
use Marko\Authorization\Exceptions\PolicyException;

/**
 * Decides abilities through gate closures, then registered policies, and
 * denies anything undefined.
 *
 * When the guard is an AbilityScopedGuardInterface (the token guard), an
 * authenticated user's credential must also grant the ability: a token
 * scoped to ['posts:read'] is denied 'posts:delete' even when the user's
 * closure or policy would allow it. Guests are not affected, so closures
 * and policies that allow guests keep working.
 */
class Gate implements GateInterface
{
    /** @var array<string, callable> */
    private array $abilities = [];

    public function __construct(
        private readonly GuardInterface $guard,
        private readonly PolicyRegistry $policyRegistry,
    ) {}

    public function define(
        string $ability,
        callable $callback,
    ): void {
        $this->abilities[$ability] = $callback;
    }

    /**
     * @throws PolicyException
     */
    public function allows(
        string $ability,
        mixed ...$arguments,
    ): bool {
        $user = $this->resolveUser();

        // A scoped credential (an API token) can only narrow the user's authority
        if ($user !== null && $this->guard instanceof AbilityScopedGuardInterface
            && !$this->guard->hasAbility($ability)) {
            return false;
        }

        // Check explicit gate closures first
        if (isset($this->abilities[$ability])) {
            return (bool) ($this->abilities[$ability])($user, ...$arguments);
        }

        // Check if first argument is an object with a registered policy
        if ($arguments !== [] && is_object($arguments[0])) {
            $entity = $arguments[0];
            $policyClass = $this->policyRegistry->resolve($entity::class);

            if ($policyClass !== null) {
                return $this->callPolicy($policyClass, $ability, $user, $arguments);
            }
        }

        // Check if first argument is a class string with a registered policy
        if ($arguments !== [] && is_string($arguments[0]) && class_exists($arguments[0])) {
            $policyClass = $this->policyRegistry->resolve($arguments[0]);

            if ($policyClass !== null) {
                return $this->callPolicy($policyClass, $ability, $user, $arguments);
            }
        }

        // Deny by default for undefined abilities
        return false;
    }

    /**
     * @throws PolicyException
     */
    public function denies(
        string $ability,
        mixed ...$arguments,
    ): bool {
        return !$this->allows($ability, ...$arguments);
    }

    /**
     * @throws AuthorizationException|PolicyException
     */
    public function authorize(
        string $ability,
        mixed ...$arguments,
    ): bool {
        if ($this->allows($ability, ...$arguments)) {
            return true;
        }

        throw AuthorizationException::forbidden(
            ability: $ability,
            resource: $this->resolveResourceName($arguments),
        );
    }

    /**
     * @throws PolicyException
     */
    public function policy(
        string $entityClass,
        string $policyClass,
    ): void {
        $this->policyRegistry->register($entityClass, $policyClass);
    }

    private function resolveUser(): ?AuthorizableInterface
    {
        $user = $this->guard->user();

        if ($user instanceof AuthorizableInterface) {
            return $user;
        }

        return null;
    }

    /**
     * @param array<int, mixed> $arguments
     * @throws PolicyException
     */
    private function callPolicy(
        string $policyClass,
        string $ability,
        ?AuthorizableInterface $user,
        array $arguments,
    ): bool {
        if (!$this->policyRegistry->hasAbility($policyClass, $ability)) {
            throw PolicyException::missingMethod(
                policyClass: $policyClass,
                ability: $ability,
            );
        }

        $policy = new $policyClass();

        return (bool) $policy->{$ability}($user, ...$arguments);
    }

    /**
     * @param array<int, mixed> $arguments
     */
    private function resolveResourceName(
        array $arguments,
    ): string {
        if ($arguments !== [] && is_object($arguments[0])) {
            return $arguments[0]::class;
        }

        if ($arguments !== [] && is_string($arguments[0])) {
            return $arguments[0];
        }

        return 'unknown';
    }
}
