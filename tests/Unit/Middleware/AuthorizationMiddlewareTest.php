<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Middleware;

use Marko\Authorization\Attributes\Can;
use Marko\Authorization\AuthorizableInterface;
use Marko\Authorization\Contracts\GateInterface;
use Marko\Authorization\Gate;
use Marko\Authorization\Middleware\AuthorizationMiddleware;
use Marko\Authorization\PolicyRegistry;
use Marko\Routing\Http\Request;
use Marko\Routing\Http\Response;
use Marko\Testing\Fake\FakeGuard;

// Test controllers
class PostController
{
    #[Can('create-post')]
    public function create(): Response
    {
        return new Response(body: 'created', statusCode: 200);
    }

    public function index(): Response
    {
        return new Response(body: 'index', statusCode: 200);
    }

    #[Can('update', 'App\\Entity\\Post')]
    public function update(): Response
    {
        return new Response(body: 'updated', statusCode: 200);
    }
}

// Stub AuthorizableInterface user for middleware tests
class MiddlewareStubUser implements AuthorizableInterface
{
    public function __construct(
        private readonly int $id = 1,
    ) {}

    public function getAuthIdentifier(): int|string
    {
        return $this->id;
    }

    public function getAuthIdentifierName(): string
    {
        return 'id';
    }

    public function getAuthPassword(): string
    {
        return 'hashed';
    }

    public function getRememberToken(): ?string
    {
        return null;
    }

    public function setRememberToken(
        ?string $token,
    ): void {}

    public function getRememberTokenName(): string
    {
        return 'remember_token';
    }

    public function can(
        string $ability,
        mixed ...$arguments,
    ): bool {
        return false;
    }
}

function createMiddlewareGate(
    ?FakeGuard $guard = null,
): Gate {
    return new Gate(
        guard: $guard ?? new FakeGuard(name: 'middleware-test', attemptResult: false),
        policyRegistry: new PolicyRegistry(),
    );
}

function createAuthMiddleware(
    GateInterface $gate,
    FakeGuard $guard,
): AuthorizationMiddleware {
    return new AuthorizationMiddleware(
        gate: $gate,
        guard: $guard,
    );
}

/**
 * @param array<string, mixed> $server
 */
function createRoutedRequest(
    string $action,
    array $server = [],
): Request {
    return new Request(server: $server)->withRoute(PostController::class, $action);
}

function createSuccessfulNext(): callable
{
    return fn (Request $r): Response => new Response(body: 'success', statusCode: 200);
}

it('allows request when gate allows the ability', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => true);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create');
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('success');
});

it('returns 403 when gate denies the ability', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => false);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create');
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(403)
        ->and($response->body())->toBe('Forbidden');
});

it('returns JSON 403 for API requests when denied', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => false);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create', [
        'HTTP_ACCEPT' => 'application/json',
    ]);
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(403)
        ->and($response->headers())->toHaveKey('Content-Type')
        ->and($response->headers()['Content-Type'])->toBe('application/json')
        ->and(json_decode($response->body(), true))->toBe(['error' => 'Forbidden']);
});

it('skips authorization when no Can attribute is present', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('index');
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('success');
});

it('reads Can attribute from controller method via reflection', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);
    // Define the ability that matches the #[Can('create-post')] attribute
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => true);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create');
    $response = $middleware->handle($request, createSuccessfulNext());

    // If attribute was read correctly, the gate allows it
    expect($response->statusCode())->toBe(200);
});

it('returns 401 when user is not authenticated', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false); // No user set

    $gate = createMiddlewareGate(guard: $guard);
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => true);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create', [
        'HTTP_ACCEPT' => 'application/json',
    ]);
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(401);
});

it('returns plain 401 for web requests when not authenticated', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false); // No user set

    $gate = createMiddlewareGate(guard: $guard);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('create');
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(401)
        ->and($response->body())->toBe('Unauthorized');
});

it('passes entity class from Can attribute to gate', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);

    // Define the ability that will receive the entity class as argument
    $receivedArgs = [];
    $gate->define('update', function (?AuthorizableInterface $user, mixed ...$args) use (&$receivedArgs): bool {
        $receivedArgs = $args;

        return true;
    });

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $request = createRoutedRequest('update');
    $response = $middleware->handle($request, createSuccessfulNext());

    expect($response->statusCode())->toBe(200)
        ->and($receivedArgs)->toBe(['App\\Entity\\Post']);
});

it('passes through when the request has no matched route', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false); // No user set

    $middleware = createAuthMiddleware(gate: createMiddlewareGate(guard: $guard), guard: $guard);

    $response = $middleware->handle(new Request(), createSuccessfulNext());

    expect($response->statusCode())->toBe(200)
        ->and($response->body())->toBe('success');
});

it('reuses the resolved Can attribute for repeated requests to the same action', function (): void {
    $guard = new FakeGuard(name: 'middleware-test', attemptResult: false);
    $guard->setUser(new MiddlewareStubUser());

    $gate = createMiddlewareGate(guard: $guard);
    $gate->define('create-post', fn (?AuthorizableInterface $user): bool => false);

    $middleware = createAuthMiddleware(gate: $gate, guard: $guard);

    $first = $middleware->handle(createRoutedRequest('create'), createSuccessfulNext());
    $second = $middleware->handle(createRoutedRequest('create'), createSuccessfulNext());
    $unprotected = $middleware->handle(createRoutedRequest('index'), createSuccessfulNext());

    expect($first->statusCode())->toBe(403)
        ->and($second->statusCode())->toBe(403)
        ->and($unprotected->statusCode())->toBe(200);
});
