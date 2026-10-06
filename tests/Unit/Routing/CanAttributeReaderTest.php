<?php

declare(strict_types=1);

namespace Marko\Authorization\Tests\Unit\Routing;

use Marko\Authorization\Attributes\Can;
use Marko\Authorization\Routing\CanAttributeReader;

class ReaderMethodController
{
    /** @noinspection PhpUnused - Read via reflection */
    #[Can('edit', 'App\\Entity\\Post')]
    public function edit(): void {}

    /** @noinspection PhpUnused - Read via reflection */
    public function index(): void {}
}

#[Can('admin.access')]
class ReaderClassController
{
    /** @noinspection PhpUnused - Read via reflection */
    public function dashboard(): void {}

    /** @noinspection PhpUnused - Read via reflection */
    #[Can('admin.reports')]
    public function reports(): void {}
}

it('returns the method-level Can attribute', function (): void {
    $can = new CanAttributeReader()->read(ReaderMethodController::class, 'edit');

    expect($can)->toBeInstanceOf(Can::class)
        ->and($can?->ability)->toBe('edit')
        ->and($can?->entityClass)->toBe('App\\Entity\\Post');
});

it('falls back to the class-level Can attribute', function (): void {
    $can = new CanAttributeReader()->read(ReaderClassController::class, 'dashboard');

    expect($can?->ability)->toBe('admin.access');
});

it('prefers the method-level Can over the class-level one', function (): void {
    $can = new CanAttributeReader()->read(ReaderClassController::class, 'reports');

    expect($can?->ability)->toBe('admin.reports');
});

it('returns null when neither the method nor the class has Can', function (): void {
    expect(new CanAttributeReader()->read(ReaderMethodController::class, 'index'))->toBeNull();
});
