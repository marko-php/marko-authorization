<?php

declare(strict_types=1);

namespace Marko\Authorization\Middleware;

use Marko\Authentication\Contracts\GuardInterface;
use Marko\Authorization\Attributes\Can;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Exceptions\AuthorizationException;
use Marko\Authorization\Exceptions\PolicyException;
use Marko\Routing\Exceptions\HttpException;
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
 *
 * Failures are thrown, never rendered here: a guest gets an HttpException
 * (401) and a denied user an AuthorizationException (403). The routing
 * pipeline renders both through ExceptionRenderer, with content negotiation
 * and any app-level renderer Preference.
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
     * @throws AuthorizationException|HttpException|PolicyException|ReflectionException
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
            throw HttpException::unauthorized('Unauthorized.');
        }

        $arguments = [];

        if ($canAttribute->entityClass !== null) {
            $arguments[] = $canAttribute->entityClass;
        }

        if ($this->gate->allows($canAttribute->ability, ...$arguments)) {
            return $next($request);
        }

        throw AuthorizationException::forbidden(
            ability: $canAttribute->ability,
            resource: $canAttribute->entityClass ?? $request->controller() . '::' . $request->action(),
        );
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
}
