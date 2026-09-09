# LOVEMI Production Deployment

## Production Requirements

Use:

- HTTPS.
- PHP 8.x.
- MariaDB/MySQL.
- Secure database credentials.
- Secure file permissions.
- Secure environment configuration.
- Proper scheduled tasks/cron.
- Regular backups.

## Deployment Checklist

### Application

- [ ] Production URL configured.
- [ ] Debug mode disabled.
- [ ] PHP errors hidden from visitors.
- [ ] HTTPS enabled.
- [ ] Correct timezone configured.
- [ ] Secure session cookies enabled.

### Database

- [ ] Production database created.
- [ ] Database credentials secured.
- [ ] Latest migrations applied.
- [ ] Foreign keys verified.
- [ ] Backup tested.

### Email

- [ ] Production sender configured.
- [ ] SMTP/API credentials secured.
- [ ] Email delivery tested.
- [ ] Password-reset email tested.
- [ ] Support verification email tested.

### Payments

- [ ] Production payment credentials configured.
- [ ] Callback URLs configured.
- [ ] Payment verification tested.
- [ ] Successful payment status verified server-side.
- [ ] Receipt generation tested.

### Uploads

- [ ] Upload directories protected.
- [ ] File-size limits configured.
- [ ] File-type validation enabled.
- [ ] Executable uploads blocked.

### Security

- [ ] Admin authorization tested.
- [ ] Login rate limiting tested.
- [ ] Password reset tested.
- [ ] 2FA tested.
- [ ] Support verification tested.
- [ ] CSRF protection tested.
- [ ] SQL injection tests completed.
- [ ] XSS tests completed.

## Deployment Rule

Do not deploy debug code, test credentials, database dumps, backup
archives, or development secrets into public web directories.