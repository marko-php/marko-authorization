<?php

declare(strict_types=1);

namespace Marko\Authorization\Middleware;

use JsonException;
use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authorization\Attributes\Can;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Routing\Middleware\MiddlewareInterface;
use ReflectionClass;
use ReflectionException;
use ReflectionMethod;

/**
 * Enforces #[Can] on the matched controller action.
 *
 * Reads the matched route from the request (set by the Router before the
 * pipeline runs). A method-level #[Can] overrides a class-level one. Routes
 * without #[Can] pass straight through.
 */
class AuthorizationMiddleware implements MiddlewareInterface
{
    /**
     * Resolved #[Can] per "controller::action". Holds only immutable attribute
     * data, so it is safe to keep across requests in long-running workers.
     *
     * @var array<string, ?Can>
     */
    private array $resolved = [];

    public function __construct(
        private readonly GateInterface $gate,
        private readonly GuardInterface $guard,
    ) {}

    /**
     * @throws ReflectionException|JsonException
     */
    public function handle(
        Request $request,
        callable $next,
    ): Response {
        $canAttribute = $this->resolveCanAttribute($request);

        if ($canAttribute === null) {
            return $next($request);
        }

        if (!$this->guard->check()) {
            return $this->unauthorizedResponse($request);
        }

        $arguments = [];

        if ($canAttribute->entityClass !== null) {
            $arguments[] = $canAttribute->entityClass;
        }

        if ($this->gate->allows($canAttribute->ability, ...$arguments)) {
            return $next($request);
        }

        return $this->forbiddenResponse($request);
    }

    /**
     * @throws ReflectionException
     */
    private function resolveCanAttribute(
        Request $request,
    ): ?Can {
        $controller = $request->controller();
        $action = $request->action();

        if ($controller === null || $action === null) {
            return null;
        }

        $key = $controller . '::' . $action;

        if (!array_key_exists($key, $this->resolved)) {
            $this->resolved[$key] = $this->readCanAttribute($controller, $action);
        }

        return $this->resolved[$key];
    }

    /**
     * @throws ReflectionException
     */
    private function readCanAttribute(
        string $controller,
        string $action,
    ): ?Can {
        $method = new ReflectionMethod($controller, $action);
        $attributes = $method->getAttributes(Can::class);

        if ($attributes === []) {
            $attributes = new ReflectionClass($controller)->getAttributes(Can::class);
        }

        return $attributes === [] ? null : $attributes[0]->newInstance();
    }

    /**
     * @throws JsonException
     */
    private function unauthorizedResponse(
        Request $request,
    ): Response {
        if ($this->isJsonRequest($request)) {
            return Response::json(
                data: ['error' => 'Unauthorized'],
                statusCode: 401,
            );
        }

        return new Response(
            body: 'Unauthorized',
            statusCode: 401,
        );
    }

    /**
     * @throws JsonException
     */
    private function forbiddenResponse(
        Request $request,
    ): Response {
        if ($this->isJsonRequest($request)) {
            return Response::json(
                data: ['error' => 'Forbidden'],
                statusCode: 403,
            );
        }

        return new Response(
            body: 'Forbidden',
            statusCode: 403,
        );
    }

    private function isJsonRequest(
        Request $request,
    ): bool {
        $accept = $request->header('Accept');

        return $accept !== null && str_contains($accept, 'application/json');
    }
}
