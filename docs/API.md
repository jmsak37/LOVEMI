# LOVEMI API Documentation

## API Principles

LOVEMI APIs should:

- Accept validated input.
- Authenticate requests where required.
- Authorize protected operations.
- Return JSON.
- Use appropriate HTTP status codes.
- Use prepared database statements.
- Never expose secrets.
- Never return raw PHP warnings/notices as API output.

## Authentication APIs

Location:

api/auth/

Examples include:

- login.php
- logout.php
- registration.php
- session.php
- forgot-password.php
- reset-password.php
- verify-2fa.php
- setup-2fa.php

## Connection APIs

Location:

api/connections/

Includes operations for:

- Creating connections.
- Accepting connections.
- Rejecting connections.
- Cancelling connections.
- Blocking users.
- Unblocking users.
- Listing connections.
- Checking connection status.

## Chat APIs

Location:

api/chat/

Includes:

- Conversations.
- Messages.
- Sending messages.
- Marking messages read.
- Typing status.
- Online status.
- Message reporting.

## Post APIs

Location:

api/posts/

Includes:

- Creating posts.
- Updating posts.
- Deleting posts.
- Listing posts.
- Viewing posts.
- Comments.
- Reactions.
- Media.
- Reporting.

## Profile APIs

Location:

api/profile/

Includes:

- Profile data.
- Profile resolution.
- Follow functionality.
- Likes.
- Comments.
- Posts.
- Chat access.
- Video streaming.

## Premium APIs

Location:

api/premium/

Includes:

- Premium status.
- Subscription.
- Renewal.
- Deactivation.
- Payment status.
- Access checking.
- Subscription history.

## Payment APIs

Location:

api/payments/

Payment operations must always be verified server-side.

A successful browser redirect must never be considered sufficient evidence
of payment.

## Support APIs

Location:

api/support/

Support verification can include:

- Ticket access.
- Email verification.
- Two-factor authentication.
- Conversations.
- Replies.
- Closing/resolving tickets.

## Response Format

Successful example:

{
    "success": true,
    "message": "Operation completed successfully",
    "data": {}
}

Error example:

{
    "success": false,
    "message": "Unable to complete the request"
}

Sensitive internal errors should be logged server-side instead of being
returned to ordinary users.