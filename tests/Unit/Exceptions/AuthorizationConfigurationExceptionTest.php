<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Exceptions;

use Marko\Authorization\Exceptions\AuthorizationConfigurationException;
use Marko\Core\Exceptions\HttpExceptionInterface;
use Marko\Core\Exceptions\MarkoException;
use RuntimeException;

it('is a MarkoException and not an HTTP exception', function (): void {
    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: 'web',
        canRoutes: ['App\\AdminController::dashboard'],
        previous: new RuntimeException('No user provider'),
    );

    expect($exception)->toBeInstanceOf(MarkoException::class)
        ->not->toBeInstanceOf(HttpExceptionInterface::class);
});

it('names the guard and the original error in the message', function (): void {
    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: 'web',
        canRoutes: ['App\\AdminController::dashboard'],
        previous: new RuntimeException('No user provider'),
    );

    expect($exception->getMessage())
        ->toContain("'web'")
        ->toContain('No user provider');
});

it('describes an unknown guard name as the default guard', function (): void {
    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: null,
        canRoutes: ['App\\AdminController::dashboard'],
        previous: new RuntimeException('Config key missing'),
    );

    expect($exception->getMessage())->toContain('the default authentication guard');
});

it('lists the Can routes as examples, capped at five with a count of the rest', function (): void {
    $routes = array_map(fn (int $i): string => "App\\Controller$i::index", range(1, 7));

    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: 'web',
        canRoutes: $routes,
        previous: new RuntimeException('boom'),
    );

    expect($exception->getContext())
        ->toContain('App\\Controller1::index')
        ->toContain('App\\Controller5::index')
        ->not->toContain('App\\Controller6::index')
        ->toContain('and 2 more');
});

it('keeps the original exception as previous', function (): void {
    $previous = new RuntimeException('No user provider');

    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: 'web',
        canRoutes: ['App\\AdminController::dashboard'],
        previous: $previous,
    );

    expect($exception->getPrevious())->toBe($previous);
});

it('suggests configuring authentication.guards, a user provider and a session driver', function (): void {
    $exception = AuthorizationConfigurationException::cannotBuildForCan(
        guard: 'web',
        canRoutes: ['App\\AdminController::dashboard'],
        previous: new RuntimeException('boom'),
    );

    expect($exception->getSuggestion())
        ->toContain('authentication.guards')
        ->toContain('UserProviderInterface')
        ->toContain('session driver');
});
