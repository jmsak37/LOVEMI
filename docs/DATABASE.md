# LOVEMI Database Documentation

Database name:

lovemi

## Main Areas

### Users

Stores the core account information.

### Profiles

Stores public/profile information associated with users.

### Profile Codes

Provides the mechanism used to resolve profile identifiers.

### Connections

Stores user connection/friend relationships.

### Conversations

Stores conversation records.

### Messages

Stores private conversation messages.

### Posts

Stores user-generated posts.

### Post Photos

Associates media with posts.

### Post Comments

Stores post comments and replies.

### Post Likes / Reactions

Stores user reactions to content.

### Notifications

Stores user notifications.

### Payments

Stores payment records.

### Payment Receipts

Stores payment receipt information.

### Services

Stores services available through the application.

### Subscriptions

Stores Premium subscription records.

### Support Tickets

Stores support requests.

### Reports

Stores reports submitted against users/content/messages.

### Permissions and Roles

Stores administrative roles and permission assignments.

### Audit Logs

Stores administrator/system activity records.

## Database Rules

Use PDO prepared statements.

Never concatenate raw user input into SQL.

Preserve foreign-key relationships.

Do not delete parent records without understanding their dependent
records and application behavior.

## Migrations

New schema changes should be introduced as numbered migrations.

Example:

database/migrations/024_new_feature.sql

Do not modify a migration that has already been deployed unless there is
a documented reason and migration strategy.

## Views and Triggers

The database includes views and triggers used to support application
behavior.

Important database behavior includes:

- Connection-related conversation/notification behavior.
- Payment success notifications.
- Premium subscription protection.
- User/profile initialization.
- Notification-related behavior.

Database changes should therefore be tested against existing triggers and
views.

## Backup

Database backups must be stored outside the publicly accessible web root
whenever possible.

Backups containing personal information must be protected appropriately.