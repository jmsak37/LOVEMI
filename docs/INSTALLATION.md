# LOVEMI Installation Guide

## Requirements

Recommended local development environment:

- Windows
- XAMPP
- Apache
- PHP 8.x
- MariaDB/MySQL
- Composer
- Modern web browser

## 1. Install XAMPP

Install XAMPP and enable:

- Apache
- MySQL/MariaDB

## 2. Copy LOVEMI

Place the project in:

C:\xampp\htdocs\LOVEMI

## 3. Create the Database

Open phpMyAdmin.

Create:

lovemi

Import:

database/lovemi.sql

## 4. Configure Database Connection

Configure:

config/database.php

Use the local database credentials.

Do not publish production credentials.

## 5. Install Composer Dependencies

Open Command Prompt:

cd C:\xampp\htdocs\LOVEMI

Then run:

composer install

If Composer dependencies have already been installed, verify that the
vendor directory is present.

## 6. Configure Email

Configure the central LOVEMI email service using secure credentials.

Do not put SMTP credentials into public JavaScript or HTML.

## 7. Configure Payments

Configure the required payment provider credentials.

Never use production payment credentials during development unless the
provider explicitly requires them.

## 8. Start Apache and Database

Open XAMPP Control Panel.

Start:

Apache

MySQL

## 9. Open LOVEMI

Visit:

http://localhost/LOVEMI/

## 10. First Test

Test:

- Registration.
- Login.
- Logout.
- Profile.
- Discover.
- Posts.
- Comments.
- Connections.
- Messages.
- Notifications.
- Premium.
- Support.
- Administrator login.

## Important

Production installations must use HTTPS.

Production secrets must not be committed to Git.

Database backups must be protected from public access.