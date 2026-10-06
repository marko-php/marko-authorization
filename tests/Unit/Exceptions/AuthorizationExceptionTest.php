<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Exceptions;

use Marko\Authorization\Exceptions\AuthorizationException;
use Marko\Authorization\Exceptions\PolicyException;
use Marko\Core\Exceptions\HttpExceptionInterface;
use Marko\Core\Exceptions\MarkoException;

it('implements HttpExceptionInterface with a 403 status and no headers', function (): void {
    $exception = AuthorizationException::forbidden(
        ability: 'delete',
        resource: 'Comment',
    );

    expect($exception)->toBeInstanceOf(HttpExceptionInterface::class)
        ->toBeInstanceOf(MarkoException::class)
        ->and($exception->getStatusCode())->toBe(403)
        ->and($exception->getHeaders())->toBeEmpty();
});

it('never exposes the ability or resource name in the response data', function (): void {
    $exception = AuthorizationException::forbidden(
        ability: 'delete-secret-thing',
        resource: 'App\\Entity\\InternalLedger',
    );

    $encoded = json_encode($exception->getResponseData(), JSON_THROW_ON_ERROR);

    expect($exception->getResponseData())->toBe(['message' => 'Forbidden.'])
        ->and($encoded)->not->toContain('delete-secret-thing')
        ->not->toContain('InternalLedger');
});

it('keeps the ability and resource for logging', function (): void {
    $exception = AuthorizationException::forbidden(
        ability: 'delete',
        resource: 'Comment',
    );

    expect($exception->getAbility())->toBe('delete')
        ->and($exception->getResource())->toBe('Comment')
        ->and($exception->getContext())->toContain('delete')
        ->toContain('Comment');
});

it('forwards context and suggestion to MarkoException', function (): void {
    $exception = new AuthorizationException(
        message: 'Access denied',
        ability: 'create',
        resource: 'Article',
        context: 'User lacks create permission on Article',
        suggestion: 'Ensure the user has the create ability or register a policy',
    );

    expect($exception->getMessage())->toBe('Access denied')
        ->and($exception->getContext())->toBe('User lacks create permission on Article')
        ->and($exception->getSuggestion())->toBe('Ensure the user has the create ability or register a policy')
        ->and($exception->getAbility())->toBe('create')
        ->and($exception->getResource())->toBe('Article');
});

it('defaults the message to Forbidden', function (): void {
    $exception = new AuthorizationException();

    expect($exception->getMessage())->toBe('Forbidden')
        ->and($exception->getAbility())->toBe('')
        ->and($exception->getResource())->toBe('');
});

it('does not implement HttpExceptionInterface on PolicyException', function (): void {
    $exception = PolicyException::missingMethod(
        policyClass: 'App\\Policy\\PostPolicy',
        ability: 'publish',
    );

    expect($exception)->toBeInstanceOf(MarkoException::class)
        ->not->toBeInstanceOf(HttpExceptionInterface::class)
        ->and($exception->getMessage())->toContain('App\\Policy\\PostPolicy')
        ->toContain('publish')
        ->and($exception->getSuggestion())->toContain('publish');
});

it('describes a duplicate policy registration on PolicyException', function (): void {
    $exception = PolicyException::duplicatePolicy(
        entityClass: 'App\\Entity\\Post',
        policyClass: 'App\\Policy\\NewPostPolicy',
        existing: 'App\\Policy\\PostPolicy',
    );

    expect($exception->getMessage())->toContain('App\\Entity\\Post')
        ->and($exception->getContext())->toContain('App\\Policy\\NewPostPolicy')
        ->toContain('App\\Policy\\PostPolicy');
});
