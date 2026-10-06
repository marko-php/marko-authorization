<?php

declare(strict_types=1);

namespace Marko\Authorization\Exceptions;

use Marko\Core\Exceptions\HttpExceptionInterface;
use Marko\Core\Exceptions\MarkoException;
use Throwable;

/**
 * The current user may not perform an ability.
 *
 * Rendered by the routing pipeline as 403 with a generic message: the
 * ability and resource stay on the exception (for logs) and are never sent
 * to the client.
 */
class AuthorizationException extends MarkoException implements HttpExceptionInterface
{
    public function __construct(
        string $message = 'Forbidden',
        private readonly string $ability = '',
        private readonly string $resource = '',
        string $context = '',
        string $suggestion = '',
        ?Throwable $previous = null,
    ) {
        parent::__construct(
            message: $message,
            context: $context,
            suggestion: $suggestion,
            previous: $previous,
        );
    }

    public function getAbility(): string
    {
        return $this->ability;
    }

    public function getResource(): string
    {
        return $this->resource;
    }

    public function getStatusCode(): int
    {
        return 403;
    }

    /**
     * @return array<string, string>
     */
    public function getHeaders(): array
    {
        return [];
    }

    /**
     * @return array<string, mixed>
     */
    public function getResponseData(): array
    {
        return ['message' => 'Forbidden.'];
    }

    public static function forbidden(
        string $ability,
        string $resource,
    ): self {
        return new self(
            message: 'Forbidden',
            ability: $ability,
            resource: $resource,
            context: "Unable to perform '$ability' on '$resource'",
            suggestion: 'You do not have permission to perform this action',
        );
    }
}
