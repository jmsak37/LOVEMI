# Contributing to LOVEMI

Thank you for contributing to the LOVEMI project.

## Before Making Changes

Read:

- `README.md`
- `LICENSE`
- `SECURITY.md`

Understand the existing project structure before modifying files.

## Development Rules

Do not remove existing functionality unless the change specifically
requires it.

Prefer small, focused changes.

Use the existing database structure before creating duplicate tables.

Use the existing APIs where possible.

Keep authentication and authorization on the server.

Do not place secrets in HTML, JavaScript, CSS, SQL dumps intended for
public sharing, or Git repositories.

## Database Changes

Database modifications should be added through a new migration.

Do not silently modify an existing migration that may already have been
executed on another installation.

Use the next available migration number.

Document:

- New tables.
- New columns.
- New indexes.
- Foreign keys.
- Triggers.
- Views.
- Data migrations.

## API Changes

API endpoints should:

- Return consistent JSON.
- Validate incoming data.
- Verify authentication.
- Verify authorization.
- Use prepared statements.
- Return appropriate HTTP status codes.
- Avoid leaking database errors.

## Frontend Changes

Maintain responsive behavior.

Test desktop and mobile layouts.

Do not trust browser validation as the only validation.

## Testing

Before committing:

1. Test login.
2. Test registration.
3. Test logout.
4. Test password recovery.
5. Test account verification.
6. Test profiles.
7. Test posts.
8. Test comments and reactions.
9. Test connections.
10. Test messaging.
11. Test notifications.
12. Test premium access.
13. Test payments.
14. Test support.
15. Test administrator authorization.

## Commit Messages

Use clear commit messages.

Examples:

`fix: correct profile-code resolution`

`fix: persist post likes`

`feat: add support email verification`

`security: rate-limit password reset`

`docs: update deployment instructions`

## Pull Requests

A pull request should explain:

- What changed.
- Why it changed.
- Files affected.
- Database changes.
- Security impact.
- Testing performed.

---

Copyright (c) 2026 LOVEMI
All Rights Reserved.