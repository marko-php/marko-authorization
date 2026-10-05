# marko/authorization

Gates, policies, and the `#[Can]` attribute -- control who can do what with expressive, testable authorization checks.

## Installation

```bash
composer require marko/authorization
```

## Quick Example

```php
use Marko\Authorization\Attributes\Can;
use Marko\Routing\Attributes\Get;
use Marko\Routing\Http\Response;

class AdminController
{
    // Enforced on every request once the package is installed: 401 if logged out, 403 if denied
    #[Get('/admin')]
    #[Can('admin.access')]
    public function dashboard(): Response
    {
        return new Response('Welcome');
    }
}
```

## Documentation

Full usage, API reference, and examples: [marko/authorization](https://marko.build/docs/packages/authorization/)
