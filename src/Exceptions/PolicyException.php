<?php

declare(strict_types=1);

namespace Marko\Authorization\Exceptions;

use Marko\Core\Exceptions\MarkoException;

/**
 * A policy is registered or written incorrectly.
 *
 * This is a developer error, not a denied request, so it deliberately does
 * not implement HttpExceptionInterface: it surfaces as a 500 with the full
 * message instead of being hidden behind a "Forbidden" page.
 */
class PolicyException extends MarkoException
{
    public static function duplicatePolicy(
        string $entityClass,
        string $policyClass,
        string $existing,
    ): self {
        return new self(
            message: "A policy is already registered for '$entityClass'",
            context: "Attempted to register '$policyClass' for '$entityClass', but '$existing' is already registered",
            suggestion: 'Remove the duplicate policy registration or use a different entity class',
        );
    }

    public static function missingMethod(
        string $policyClass,
        string $ability,
    ): self {
        return new self(
            message: "Policy '$policyClass' does not have a '$ability' method",
            context: "Attempted to check ability '$ability' on policy '$policyClass' but the method does not exist",
            suggestion: "Add a public '$ability' method to '$policyClass'",
        );
    }
}
