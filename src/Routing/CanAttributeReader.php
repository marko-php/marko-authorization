<?php

declare(strict_types=1);

namespace Marko\Authorization\Routing;

use Marko\Authorization\Attributes\Can;
use ReflectionClass;
use ReflectionException;
use ReflectionMethod;

/**
 * Reads the #[Can] that protects a controller action.
 *
 * A method-level #[Can] replaces a class-level one. Shared by
 * AuthorizationMiddleware (per request) and CanRouteFinder (boot check), so
 * both agree on which routes #[Can] protects.
 */
readonly class CanAttributeReader
{
    /**
     * @throws ReflectionException
     */
    public function read(
        string $controller,
        string $action,
    ): ?Can {
        $attributes = new ReflectionMethod($controller, $action)->getAttributes(Can::class);

        if ($attributes === []) {
            $attributes = new ReflectionClass($controller)->getAttributes(Can::class);
        }

        return $attributes === [] ? null : $attributes[0]->newInstance();
    }
}
