<?php

declare(strict_types=1);

namespace Marko\Authorization\Contracts;

use Marko\Authorization\AuthorizableInterface;
use Marko\Authorization\Exceptions\AuthorizationException;
use Marko\Authorization\Exceptions\PolicyException;

interface GateInterface
{
    /**
     * Define an ability with a closure.
     *
     * @param callable(?AuthorizableInterface, mixed...): bool $callback
     */
    public function define(
        string $ability,
        callable $callback,
    ): void;

    /**
     * Check if the given ability is allowed.
     *
     * @throws PolicyException When the matching policy has no method for the ability
     */
    public function allows(
        string $ability,
        mixed ...$arguments,
    ): bool;

    /**
     * Check if the given ability is denied.
     *
     * @throws PolicyException When the matching policy has no method for the ability
     */
    public function denies(
        string $ability,
        mixed ...$arguments,
    ): bool;

    /**
     * Authorize the given ability. Throws on denial.
     *
     * The thrown AuthorizationException implements HttpExceptionInterface,
     * so an uncaught denial in a controller renders as a 403.
     *
     * @throws AuthorizationException|PolicyException
     */
    public function authorize(
        string $ability,
        mixed ...$arguments,
    ): bool;

    /**
     * Register a policy class for an entity class.
     *
     * @param class-string $entityClass
     * @param class-string $policyClass
     * @throws PolicyException When a policy is already registered for the entity
     */
    public function policy(
        string $entityClass,
        string $policyClass,
    ): void;
}
