<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - MAIN EMAIL SERVICE
|--------------------------------------------------------------------------
|
| File:
| C:\xampp\htdocs\LOVEMI\services\email\main-email-service.php
|
| This file uses the existing:
| C:\xampp\htdocs\LOVEMI\services\email\email-service.php
|
| Do NOT put SMTP passwords in this file.
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/email-service.php';

/*
|--------------------------------------------------------------------------
| CONSTANTS
|--------------------------------------------------------------------------
*/

const LOVEMI_EMAIL_LOGO_CID = 'lovemi_logo@lovemi';

/*
|--------------------------------------------------------------------------
| APPLICATION URL
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiAppUrl')) {

    function mainLovemiAppUrl(): string
    {
        /*
        |--------------------------------------------------------------------------
        | Production URL can be supplied with LOVEMI_APP_URL.
        |--------------------------------------------------------------------------
        */
        $configured = getenv('LOVEMI_APP_URL');

        if (
            is_string($configured)
            &&
            trim($configured) !== ''
        ) {
            return rtrim(
                trim($configured),
                '/'
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Detect current host for local XAMPP.
        |--------------------------------------------------------------------------
        */
        $https =
            (
                !empty($_SERVER['HTTPS'])
                &&
                strtolower(
                    (string)$_SERVER['HTTPS']
                ) !== 'off'
            )
            ||
            (
                (int)(
                    $_SERVER['SERVER_PORT']
                    ?? 80
                ) === 443
            );

        $scheme = $https
            ? 'https'
            : 'http';

        $host = trim(
            (string)(
                $_SERVER['HTTP_HOST']
                ??
                $_SERVER['SERVER_NAME']
                ??
                'localhost'
            )
        );

        if ($host === '') {
            $host = 'localhost';
        }

        /*
        |--------------------------------------------------------------------------
        | LOVEMI local XAMPP application.
        |--------------------------------------------------------------------------
        */
        return $scheme . '://' . $host . '/LOVEMI';
    }
}

/*
|--------------------------------------------------------------------------
| SAFE LOVEMI URL
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiSafeUrl')) {

    function mainLovemiSafeUrl(string $path): string
    {
        $path = trim($path);

        if ($path === '') {
            $path = 'notifications.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Never allow an external URL to be injected into notification
        | buttons.
        |--------------------------------------------------------------------------
        */
        if (
            preg_match(
                '#^https?://#i',
                $path
            )
            ||
            str_starts_with(
                $path,
                '//'
            )
        ) {
            return mainLovemiAppUrl()
                . '/notifications.html';
        }

        return mainLovemiAppUrl()
            . '/'
            . ltrim($path, '/');
    }
}

/*
|--------------------------------------------------------------------------
| HTML ESCAPING
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiEsc')) {

    function mainLovemiEsc(mixed $value): string
    {
        return htmlspecialchars(
            (string)$value,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );
    }
}

/*
|--------------------------------------------------------------------------
| NOTIFICATION CATEGORY
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiNotificationCategory')) {

    function mainLovemiNotificationCategory(
        array $notification
    ): string {

        $slug = strtolower(
            trim(
                (string)(
                    $notification['notification_slug']
                    ?? ''
                )
            )
        );

        $referenceType = strtolower(
            trim(
                (string)(
                    $notification['reference_type']
                    ?? ''
                )
            )
        );

        if (
            $slug === 'new_message'
            ||
            $referenceType === 'message'
            ||
            $referenceType === 'conversation'
        ) {
            return 'Message';
        }

        if (
            str_contains(
                $slug,
                'connection'
            )
            ||
            $referenceType === 'connection'
        ) {
            return 'Connection';
        }

        if (
            str_contains(
                $slug,
                'premium'
            )
            ||
            $referenceType === 'subscription'
        ) {
            return 'Premium';
        }

        if (
            str_contains(
                $slug,
                'payment'
            )
            ||
            $referenceType === 'payment'
        ) {
            return 'Payment';
        }

        if (
            str_contains(
                $slug,
                'post'
            )
            ||
            $referenceType === 'post'
        ) {
            return 'Post';
        }

        if (
            str_contains(
                $slug,
                'photo'
            )
            ||
            $referenceType === 'photo'
        ) {
            return 'Photo';
        }

        return 'Notification';
    }
}

/*
|--------------------------------------------------------------------------
| NOTIFICATION DESTINATION
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiNotificationPath')) {

    function mainLovemiNotificationPath(
        array $notification
    ): string {

        $referenceType = strtolower(
            trim(
                (string)(
                    $notification['reference_type']
                    ?? ''
                )
            )
        );

        $referenceId = (int)(
            $notification['reference_id']
            ?? 0
        );

        $slug = strtolower(
            trim(
                (string)(
                    $notification['notification_slug']
                    ?? ''
                )
            )
        );

        /*
        |--------------------------------------------------------------------------
        | Messages
        |--------------------------------------------------------------------------
        */
        if (
            $slug === 'new_message'
            ||
            $referenceType === 'message'
        ) {

            if ($referenceId > 0) {
                return 'messages.html?message_id='
                    . $referenceId;
            }

            return 'messages.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Conversations
        |--------------------------------------------------------------------------
        */
        if (
            $referenceType === 'conversation'
        ) {

            if ($referenceId > 0) {
                return 'messages.html?conversation_id='
                    . $referenceId;
            }

            return 'messages.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Connections
        |--------------------------------------------------------------------------
        */
        if (
            str_contains(
                $slug,
                'connection'
            )
            ||
            $referenceType === 'connection'
        ) {
            return 'connections.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Premium
        |--------------------------------------------------------------------------
        */
        if (
            str_contains(
                $slug,
                'premium'
            )
            ||
            $referenceType === 'subscription'
        ) {
            return 'premium.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Payments
        |--------------------------------------------------------------------------
        */
        if (
            str_contains(
                $slug,
                'payment'
            )
            ||
            $referenceType === 'payment'
        ) {
            return 'premium.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Posts
        |--------------------------------------------------------------------------
        */
        if (
            str_contains(
                $slug,
                'post'
            )
            ||
            $referenceType === 'post'
        ) {

            if ($referenceId > 0) {
                return 'dashboard.html#post-'
                    . $referenceId;
            }

            return 'dashboard.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Photos
        |--------------------------------------------------------------------------
        */
        if (
            str_contains(
                $slug,
                'photo'
            )
            ||
            $referenceType === 'photo'
        ) {
            return 'photos.html';
        }

        /*
        |--------------------------------------------------------------------------
        | Fallback
        |--------------------------------------------------------------------------
        */
        return 'notifications.html';
    }
}

/*
|--------------------------------------------------------------------------
| SAFE NOTIFICATION MESSAGE
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiNotificationHtml')) {

    function mainLovemiNotificationHtml(
        string $message
    ): string {

        $message = trim($message);

        if ($message === '') {
            return 'You have a new notification on LOVEMI.';
        }

        /*
        |--------------------------------------------------------------------------
        | Notification text is treated as text, not arbitrary HTML.
        |--------------------------------------------------------------------------
        */
        return nl2br(
            mainLovemiEsc($message),
            false
        );
    }
}

/*
|--------------------------------------------------------------------------
| EMAIL LOGO PATH
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiLogoPath')) {

    function mainLovemiLogoPath(): ?string
    {
        /*
        |--------------------------------------------------------------------------
        | EXACT LOVEMI LOGO:
        |
        | C:\xampp\htdocs\LOVEMI\assets\logo1\logo1.png
        |--------------------------------------------------------------------------
        */
        $path = dirname(
            __DIR__,
            2
        )
        . DIRECTORY_SEPARATOR
        . 'assets'
        . DIRECTORY_SEPARATOR
        . 'logo1'
        . DIRECTORY_SEPARATOR
        . 'logo1.png';

        if (!is_file($path)) {

            error_log(
                '[LOVEMI EMAIL] Logo not found: '
                . $path
            );

            return null;
        }

        $realPath = realpath($path);

        if (
            $realPath === false
            ||
            !is_file($realPath)
        ) {

            error_log(
                '[LOVEMI EMAIL] Logo realpath failed: '
                . $path
            );

            return null;
        }

        return $realPath;
    }
}

/*
|--------------------------------------------------------------------------
| COMMON EMAIL HEADER
|--------------------------------------------------------------------------
*/

if (!function_exists('mainLovemiEmailLogoHtml')) {

    function mainLovemiEmailLogoHtml(
        bool $logoAvailable
    ): string {

        if (!$logoAvailable) {

            return '
                <div
                    style="
                        width:88px;
                        height:88px;
                        margin:0 auto;
                        border-radius:22px;
                        background:#ffffff;
                        color:#6d28d9;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        font-family:Arial,Helvetica,sans-serif;
                        font-size:20px;
                        font-weight:900;
                        letter-spacing:1px;
                    "
                >
                    LOVEMI
                </div>
            ';
        }

        /*
        |--------------------------------------------------------------------------
        | Dedicated MIME Content-ID.
        |
        | This must exactly match the embedded image CID.
        |--------------------------------------------------------------------------
        */
        return '
            <img
                src="cid:' .
                    LOVEMI_EMAIL_LOGO_CID .
                '"
                alt="LOVEMI"
                width="88"
                height="88"
                style="
                    display:block;
                    width:88px;
                    height:88px;
                    margin:0 auto;
                    border:0;
                    outline:none;
                    text-decoration:none;
                    object-fit:contain;
                "
            >
        ';
    }
}

/*
|--------------------------------------------------------------------------
| SEND NOTIFICATION EMAIL
|--------------------------------------------------------------------------
*/

if (!function_exists('sendLovemiNotificationEmail')) {

    function sendLovemiNotificationEmail(
        string $recipientEmail,
        string $recipientName,
        array $notification
    ): bool {

        $recipientEmail = trim(
            $recipientEmail
        );

        if (
            $recipientEmail === ''
            ||
            !filter_var(
                $recipientEmail,
                FILTER_VALIDATE_EMAIL
            )
        ) {
            throw new InvalidArgumentException(
                'Invalid LOVEMI recipient email address.'
            );
        }

        $recipientName = trim(
            $recipientName
        );

        if ($recipientName === '') {
            $recipientName = 'LOVEMI Member';
        }

        $notificationId = (int)(
            $notification['id']
            ?? 0
        );

        $title = trim(
            (string)(
                $notification['title']
                ?? 'LOVEMI Notification'
            )
        );

        if ($title === '') {
            $title = 'LOVEMI Notification';
        }

        $message = trim(
            (string)(
                $notification['message']
                ?? ''
            )
        );

        $createdAt = trim(
            (string)(
                $notification['created_at']
                ?? ''
            )
        );

        if ($createdAt === '') {
            $createdAt = date(
                'Y-m-d H:i:s'
            );
        }

        $category =
            mainLovemiNotificationCategory(
                $notification
            );

        $destination =
            mainLovemiNotificationPath(
                $notification
            );

        $viewUrl =
            mainLovemiSafeUrl(
                $destination
            );

        /*
        |--------------------------------------------------------------------------
        | Correct physical logo.
        |--------------------------------------------------------------------------
        */
        $logoPath =
            mainLovemiLogoPath();

        $logoAvailable =
            $logoPath !== null;

        $logoHtml =
            mainLovemiEmailLogoHtml(
                $logoAvailable
            );

        /*
        |--------------------------------------------------------------------------
        | Subject.
        |--------------------------------------------------------------------------
        */
        $subject =
            'LOVEMI - '
            . $title;

        /*
        |--------------------------------------------------------------------------
        | Official branded notification email.
        |--------------------------------------------------------------------------
        */
        $html = '
<!DOCTYPE html>
<html
    lang="en"
>
<head>

<meta
    charset="UTF-8"
>

<meta
    name="viewport"
    content="width=device-width, initial-scale=1.0"
>

<meta
    name="x-apple-disable-message-reformatting"
>

<title>'
    . mainLovemiEsc(
        $subject
      )
    . '</title>

</head>

<body
    style="
        margin:0;
        padding:0;
        background:#f4f1fb;
        font-family:
            Arial,
            Helvetica,
            sans-serif;
        color:#1f2937;
    "
>

<!-- OUTER WRAPPER -->
<table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    border="0"
    style="
        width:100%;
        margin:0;
        padding:0;
        background:#f4f1fb;
    "
>

<tr>

<td
    align="center"
    style="
        padding:38px 14px;
    "
>

<!-- MAIN EMAIL -->
<table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    border="0"
    style="
        max-width:680px;
        width:100%;
        background:#ffffff;
        border-radius:24px;
        overflow:hidden;
        border:1px solid #e9e2f9;
        box-shadow:
            0 18px 55px
            rgba(76,29,149,.10);
    "
>

<!-- =========================================================
     BRAND HEADER
========================================================= -->
<tr>

<td
    align="center"
    style="
        padding:38px 28px 32px;
        background:
            linear-gradient(
                135deg,
                #5b21b6 0%,
                #7c3aed 48%,
                #9333ea 100%
            );
    "
>

'
    . $logoHtml
    . '

<div
    style="
        margin-top:18px;
        color:#ffffff;
        font-size:30px;
        line-height:1.2;
        font-weight:900;
        letter-spacing:.5px;
    "
>
    LOVEMI
</div>

<div
    style="
        margin-top:7px;
        color:#ede9fe;
        font-size:11px;
        line-height:1.5;
        font-weight:800;
        letter-spacing:2.4px;
        text-transform:uppercase;
    "
>
    Discover • Connect • Meet
</div>

</td>

</tr>

<!-- =========================================================
     INTRO
========================================================= -->
<tr>

<td
    style="
        padding:34px 34px 12px;
    "
>

<div
    style="
        color:#111827;
        font-size:18px;
        line-height:1.55;
        font-weight:700;
    "
>
    Hello
    <strong>'
    . mainLovemiEsc(
        $recipientName
      )
    . '</strong>,
</div>

<div
    style="
        margin-top:9px;
        color:#6b7280;
        font-size:14px;
        line-height:1.7;
    "
>
    There is a new update waiting for you on your LOVEMI account.
</div>

</td>

</tr>

<!-- =========================================================
     NOTIFICATION CARD
========================================================= -->
<tr>

<td
    style="
        padding:18px 34px 8px;
    "
>

<table
    role="presentation"
    width="100%"
    cellspacing="0"
    cellpadding="0"
    border="0"
    style="
        width:100%;
        border:1px solid #e6dcfa;
        border-radius:18px;
        background:#fbfaff;
    "
>

<tr>

<td
    style="
        padding:24px;
    "
>

<!-- CATEGORY -->
<table
    role="presentation"
    cellspacing="0"
    cellpadding="0"
    border="0"
>

<tr>

<td
    style="
        padding:7px 12px;
        border-radius:999px;
        background:#eee7ff;
        color:#6d28d9;
        font-size:10px;
        line-height:1.2;
        font-weight:900;
        text-transform:uppercase;
        letter-spacing:.7px;
    "
>
'
    . mainLovemiEsc(
        $category
      )
    . '
</td>

</tr>

</table>

<!-- TITLE -->
<h1
    style="
        margin:17px 0 10px;
        padding:0;
        color:#111827;
        font-size:25px;
        line-height:1.35;
        font-weight:900;
    "
>
'
    . mainLovemiEsc(
        $title
      )
    . '
</h1>

<!-- MESSAGE -->
<div
    style="
        color:#4b5563;
        font-size:15px;
        line-height:1.8;
        word-break:break-word;
    "
>
'
    . mainLovemiNotificationHtml(
        $message
      )
    . '
</div>

<!-- DATE / ID -->
<div
    style="
        margin-top:22px;
        padding-top:16px;
        border-top:1px solid #ece6f8;
        color:#9ca3af;
        font-size:11px;
        line-height:1.7;
    "
>

<div>
    Notification date:
    <strong
        style="
            color:#6b7280;
        "
    >'
        . mainLovemiEsc(
            $createdAt
          )
        . '</strong>
</div>
'
    .
    (
        $notificationId > 0
        ?
        '
        <div>
            Notification reference:
            <strong
                style="
                    color:#6b7280;
                "
            >#'
            . mainLovemiEsc(
                $notificationId
              )
            . '</strong>
        </div>
        '
        :
        ''
    )
    . '

</div>

</td>

</tr>

</table>

</td>

</tr>

<!-- =========================================================
     ACTION BUTTON
========================================================= -->
<tr>

<td
    align="center"
    style="
        padding:24px 34px 14px;
    "
>

<a
    href="'
    . mainLovemiEsc(
        $viewUrl
      )
    . '"
    target="_blank"
    style="
        display:inline-block;
        background:#6d28d9;
        color:#ffffff;
        text-decoration:none;
        font-size:14px;
        line-height:1;
        font-weight:900;
        padding:15px 28px;
        border-radius:13px;
        box-shadow:
            0 8px 22px
            rgba(109,40,217,.20);
    "
>
    View Notification
</a>

</td>

</tr>

<!-- =========================================================
     INFORMATION
========================================================= -->
<tr>

<td
    style="
        padding:10px 34px 30px;
    "
>

<div
    style="
        padding:17px 18px;
        background:#f8f7fc;
        border:1px solid #eeeaf7;
        border-radius:13px;
        color:#6b7280;
        font-size:11px;
        line-height:1.7;
        text-align:center;
    "
>
    You are receiving this message because email notifications
    are enabled for your LOVEMI account.
</div>

</td>

</tr>

<!-- =========================================================
     FOOTER
========================================================= -->
<tr>

<td
    align="center"
    style="
        padding:27px 28px 31px;
        background:#faf9fd;
        border-top:1px solid #eeeaf6;
    "
>

<div
    style="
        color:#6d28d9;
        font-size:18px;
        line-height:1.2;
        font-weight:900;
        letter-spacing:.4px;
    "
>
    LOVEMI
</div>

<div
    style="
        margin-top:7px;
        color:#8b8599;
        font-size:10px;
        line-height:1.6;
        font-weight:800;
        letter-spacing:1.8px;
        text-transform:uppercase;
    "
>
    Discover • Connect • Meet
</div>

<div
    style="
        margin-top:17px;
        color:#aaa3b5;
        font-size:10px;
        line-height:1.7;
    "
>
    This is an automated LOVEMI notification.
    Please do not reply directly to this email.
</div>

<div
    style="
        margin-top:8px;
        color:#b5afbd;
        font-size:10px;
        line-height:1.7;
    "
>
    © '
    . date('Y')
    . ' LOVEMI. All rights reserved.
</div>

</td>

</tr>

</table>

</td>

</tr>

</table>

</body>
</html>
';

        /*
        |--------------------------------------------------------------------------
        | SEND USING THE EXISTING PHPMailer SERVICE.
        |--------------------------------------------------------------------------
        |
        | The existing sendLovemiPaymentEmail() already embeds an image
        | using PHPMailer addEmbeddedImage(). We need one small improvement:
        | the existing function uses the CID "lovemi_logo".
        |
        | Therefore, to guarantee Gmail compatibility, this notification
        | email attempts to use the normal mail service with the physical
        | logo path first.
        |--------------------------------------------------------------------------
        */

        if (
            function_exists(
                'sendLovemiPaymentEmail'
            )
        ) {

            /*
            |--------------------------------------------------------------------------
            | Existing mail function expects the embedded CID:
            | "lovemi_logo"
            |
            | The HTML above uses:
            | "lovemi_logo@lovemi"
            |
            | Because the existing service has a fixed CID, create a second
            | body using that exact CID when calling the existing service.
            |--------------------------------------------------------------------------
            */

            $gmailCompatibleHtml =
                str_replace(
                    'cid:' .
                    LOVEMI_EMAIL_LOGO_CID,
                    'cid:lovemi_logo',
                    $html
                );

            $result =
                sendLovemiPaymentEmail(
                    $recipientEmail,
                    $recipientName,
                    $subject,
                    $gmailCompatibleHtml,
                    $logoPath
                );

            if ($result === true) {
                return true;
            }

            /*
            |--------------------------------------------------------------------------
            | If the dedicated payment helper failed, try the standard
            | LOVEMI email function so the notification itself is not lost.
            |--------------------------------------------------------------------------
            */
        }

        if (
            function_exists(
                'sendLovemiEmail'
            )
        ) {

            return sendLovemiEmail(
                $recipientEmail,
                $recipientName,
                $subject,
                $html,
                strip_tags(
                    $html
                )
            );
        }

        throw new RuntimeException(
            'LOVEMI email service is unavailable.'
        );
    }
}

/*
|--------------------------------------------------------------------------
| PAYMENT SUCCESS EMAIL
|--------------------------------------------------------------------------
*/

if (!function_exists('sendLovemiPaymentSuccessEmail')) {

    function sendLovemiPaymentSuccessEmail(
        string $recipientEmail,
        string $recipientName,
        string $serviceName,
        string $amountText,
        string $receiptUrl
    ): bool {

        $logoPath =
            mainLovemiLogoPath();

        $logoHtml =
            mainLovemiEmailLogoHtml(
                $logoPath !== null
            );

        $safeName =
            mainLovemiEsc(
                $recipientName
            );

        $safeService =
            mainLovemiEsc(
                $serviceName
            );

        $safeAmount =
            mainLovemiEsc(
                $amountText
            );

        $receipt =
            mainLovemiSafeUrl(
                $receiptUrl
            );

        $html = '
<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LOVEMI Payment Successful</title>
</head>

<body
style="
    margin:0;
    padding:30px 15px;
    background:#f4f1fb;
    font-family:Arial,Helvetica,sans-serif;
"
>

<table
role="presentation"
width="100%"
cellspacing="0"
cellpadding="0"
border="0"
>

<tr>
<td align="center">

<table
role="presentation"
width="100%"
cellspacing="0"
cellpadding="0"
border="0"
style="
    max-width:650px;
    background:#ffffff;
    border:1px solid #e8e1f7;
    border-radius:22px;
    overflow:hidden;
"
>

<tr>

<td
align="center"
style="
    padding:34px 25px;
    background:linear-gradient(
        135deg,
        #5b21b6,
        #9333ea
    );
"
>

'
. $logoHtml .
'

<div
style="
    margin-top:15px;
    color:#ffffff;
    font-size:28px;
    font-weight:900;
"
>
LOVEMI
</div>

<div
style="
    margin-top:6px;
    color:#ede9fe;
    font-size:11px;
    font-weight:800;
    letter-spacing:2px;
"
>
Discover • Connect • Meet
</div>

</td>

</tr>

<tr>

<td
style="
    padding:32px;
"
>

<h1
style="
    margin:0 0 15px;
    color:#15803d;
    font-size:25px;
"
>
Payment Successful
</h1>

<p
style="
    margin:0 0 15px;
    color:#374151;
    font-size:15px;
    line-height:1.7;
"
>
Hello <strong>'
. $safeName .
'</strong>,
</p>

<p
style="
    margin:0 0 22px;
    color:#4b5563;
    font-size:14px;
    line-height:1.7;
"
>
Your payment for
<strong>'
. $safeService .
'</strong>
has been successfully completed.
</p>

<div
style="
    padding:18px;
    background:#f0fdf4;
    border:1px solid #bbf7d0;
    border-radius:14px;
    color:#166534;
    font-size:14px;
    line-height:1.7;
"
>
Payment amount:
<strong>'
. $safeAmount .
'</strong>
</div>

<div
style="
    text-align:center;
    margin-top:25px;
"
>

<a
href="'
. mainLovemiEsc(
    $receipt
  )
. '"
target="_blank"
style="
    display:inline-block;
    padding:14px 24px;
    background:#6d28d9;
    color:#ffffff;
    text-decoration:none;
    font-weight:800;
    border-radius:12px;
"
>
View Receipt
</a>

</div>

</td>

</tr>

<tr>

<td
align="center"
style="
    padding:25px;
    background:#faf9fd;
    border-top:1px solid #eeeaf6;
    color:#9992a5;
    font-size:10px;
"
>
LOVEMI • Discover • Connect • Meet
</td>

</tr>

</table>

</td>
</tr>
</table>

</body>
</html>
';

        if (
            function_exists(
                'sendLovemiPaymentEmail'
            )
        ) {

            /*
            |--------------------------------------------------------------------------
            | Match the existing email-service.php CID.
            |--------------------------------------------------------------------------
            */
            $html = str_replace(
                'cid:' .
                LOVEMI_EMAIL_LOGO_CID,
                'cid:lovemi_logo',
                $html
            );

            return sendLovemiPaymentEmail(
                $recipientEmail,
                $recipientName,
                'LOVEMI Payment Successful',
                $html,
                $logoPath
            );
        }

        return sendLovemiEmail(
            $recipientEmail,
            $recipientName,
            'LOVEMI Payment Successful',
            $html
        );
    }
}

/*
|--------------------------------------------------------------------------
| PAYMENT FAILED / NOT COMPLETED EMAIL
|--------------------------------------------------------------------------
*/

if (!function_exists('sendLovemiPaymentFailedEmail')) {

    function sendLovemiPaymentFailedEmail(
        string $recipientEmail,
        string $recipientName,
        string $serviceName,
        string $statusText,
        string $resumeUrl
    ): bool {

        $logoPath =
            mainLovemiLogoPath();

        $logoHtml =
            mainLovemiEmailLogoHtml(
                $logoPath !== null
            );

        $html = '
<!doctype html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LOVEMI Payment Not Completed</title>
</head>

<body
style="
    margin:0;
    padding:30px 15px;
    background:#f4f1fb;
    font-family:Arial,Helvetica,sans-serif;
"
>

<table
role="presentation"
width="100%"
cellspacing="0"
cellpadding="0"
border="0"
>

<tr>
<td align="center">

<table
role="presentation"
width="100%"
cellspacing="0"
cellpadding="0"
border="0"
style="
    max-width:650px;
    background:#ffffff;
    border:1px solid #e8e1f7;
    border-radius:22px;
    overflow:hidden;
"
>

<tr>

<td
align="center"
style="
    padding:34px 25px;
    background:linear-gradient(
        135deg,
        #5b21b6,
        #9333ea
    );
"
>

'
. $logoHtml .
'

<div
style="
    margin-top:15px;
    color:#ffffff;
    font-size:28px;
    font-weight:900;
"
>
LOVEMI
</div>

<div
style="
    margin-top:6px;
    color:#ede9fe;
    font-size:11px;
    font-weight:800;
    letter-spacing:2px;
"
>
Discover • Connect • Meet
</div>

</td>

</tr>

<tr>

<td
style="
    padding:32px;
"
>

<h1
style="
    margin:0 0 15px;
    color:#b91c1c;
    font-size:25px;
"
>
Payment Not Completed
</h1>

<p
style="
    margin:0 0 15px;
    color:#374151;
    font-size:15px;
    line-height:1.7;
"
>
Hello <strong>'
. mainLovemiEsc(
    $recipientName
  )
. '</strong>,
</p>

<p
style="
    margin:0 0 22px;
    color:#4b5563;
    font-size:14px;
    line-height:1.7;
"
>
The payment for
<strong>'
. mainLovemiEsc(
    $serviceName
  )
. '</strong>
was not completed successfully.
</p>

<div
style="
    padding:18px;
    background:#fef2f2;
    border:1px solid #fecaca;
    border-radius:14px;
    color:#991b1b;
    font-size:14px;
    line-height:1.7;
"
>
Payment status:
<strong>'
. mainLovemiEsc(
    $statusText
  )
. '</strong>
</div>

<div
style="
    text-align:center;
    margin-top:25px;
"
>

<a
href="'
. mainLovemiEsc(
    mainLovemiSafeUrl(
        $resumeUrl
    )
  )
. '"
target="_blank"
style="
    display:inline-block;
    padding:14px 24px;
    background:#6d28d9;
    color:#ffffff;
    text-decoration:none;
    font-weight:800;
    border-radius:12px;
"
>
Continue Payment
</a>

</div>

</td>

</tr>

<tr>

<td
align="center"
style="
    padding:25px;
    background:#faf9fd;
    border-top:1px solid #eeeaf6;
    color:#9992a5;
    font-size:10px;
"
>
LOVEMI • Discover • Connect • Meet
</td>

</tr>

</table>

</td>
</tr>
</table>

</body>
</html>
';

        if (
            function_exists(
                'sendLovemiPaymentEmail'
            )
        ) {

            $html = str_replace(
                'cid:' .
                LOVEMI_EMAIL_LOGO_CID,
                'cid:lovemi_logo',
                $html
            );

            return sendLovemiPaymentEmail(
                $recipientEmail,
                $recipientName,
                'LOVEMI Payment Not Completed',
                $html,
                $logoPath
            );
        }

        return sendLovemiEmail(
            $recipientEmail,
            $recipientName,
            'LOVEMI Payment Not Completed',
            $html
        );
    }
}