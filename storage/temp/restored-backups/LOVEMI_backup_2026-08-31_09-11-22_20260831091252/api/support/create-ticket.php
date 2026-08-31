<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - CREATE SUPPORT TICKET
|--------------------------------------------------------------------------
|
| File:
| C:\xampp\htdocs\LOVEMI\api\support\create-ticket.php
|
| Accepts JSON or normal POST data:
|
| {
|   "name": "John Doe",
|   "email": "john@example.com",
|   "category": "account",
|   "subject": "Unable to login",
|   "message": "I need help logging into my account."
| }
|
| The endpoint:
|
| 1. Validates the request.
| 2. Detects the logged-in LOVEMI user when available.
| 3. Saves the ticket in MySQL.
| 4. Sends the ticket to:
|       eduassistasc@gmail.com
| 5. Sends a confirmation email to the customer.
|
|--------------------------------------------------------------------------
*/


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   PHPMailer
============================================================ */

/*
 * Your current project contains Composer and PHPMailer under:
 *
 * C:\xampp\htdocs\LOVEMI\api\auth\vendor\autoload.php
 *
 * Use Composer's autoloader first.
 */

$vendorAutoload =
    __DIR__
    . DIRECTORY_SEPARATOR
    . '..'
    . DIRECTORY_SEPARATOR
    . 'auth'
    . DIRECTORY_SEPARATOR
    . 'vendor'
    . DIRECTORY_SEPARATOR
    . 'autoload.php';


if (
    !is_file(
        $vendorAutoload
    )
) {

    /*
     * Fallback to the bundled PHPMailer source.
     */

    $phpMailerException =
        __DIR__
        . DIRECTORY_SEPARATOR
        . '..'
        . DIRECTORY_SEPARATOR
        . 'auth'
        . DIRECTORY_SEPARATOR
        . 'PHPMailer'
        . DIRECTORY_SEPARATOR
        . 'src'
        . DIRECTORY_SEPARATOR
        . 'Exception.php';


    $phpMailer =
        __DIR__
        . DIRECTORY_SEPARATOR
        . '..'
        . DIRECTORY_SEPARATOR
        . 'auth'
        . DIRECTORY_SEPARATOR
        . 'PHPMailer'
        . DIRECTORY_SEPARATOR
        . 'src'
        . DIRECTORY_SEPARATOR
        . 'PHPMailer.php';


    $phpMailerSmtp =
        __DIR__
        . DIRECTORY_SEPARATOR
        . '..'
        . DIRECTORY_SEPARATOR
        . 'auth'
        . DIRECTORY_SEPARATOR
        . 'PHPMailer'
        . DIRECTORY_SEPARATOR
        . 'src'
        . DIRECTORY_SEPARATOR
        . 'SMTP.php';


    if (
        is_file(
            $phpMailerException
        )
        &&
        is_file(
            $phpMailer
        )
        &&
        is_file(
            $phpMailerSmtp
        )
    ) {

        require_once $phpMailerException;
        require_once $phpMailer;
        require_once $phpMailerSmtp;

    } else {

        header(
            'Content-Type: application/json; charset=utf-8'
        );

        http_response_code(500);

        echo json_encode(
            [
                'success' => false,
                'message' =>
                    'PHPMailer is not installed correctly.',
                'code' =>
                    'MAILER_NOT_AVAILABLE'
            ],
            JSON_UNESCAPED_UNICODE |
            JSON_UNESCAPED_SLASHES
        );

        exit;

    }

} else {

    require_once $vendorAutoload;

}


use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;


/* ============================================================
   HEADERS
============================================================ */

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);

header(
    'X-Content-Type-Options: nosniff'
);


/* ============================================================
   SESSION
============================================================ */

if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   CONFIGURATION
============================================================ */

/*
 * Sender account.
 */

const LOVEMI_SUPPORT_EMAIL =
    'eduassistasc@gmail.com';


/*
 * Display name.
 */

const LOVEMI_SUPPORT_NAME =
    'LOVEMI Support';


/*
 * SMTP server.
 */

const LOVEMI_SMTP_HOST =
    'smtp.gmail.com';


const LOVEMI_SMTP_PORT =
    587;


/*
 * TLS encryption.
 */

const LOVEMI_SMTP_ENCRYPTION =
    'tls';


/*
 * IMPORTANT:
 *
 * Do NOT put your Gmail app password directly into this file.
 *
 * Configure:
 *
 * LOVEMI_EMAIL_APP_PASSWORD
 *
 * as an environment variable in Apache/PHP/XAMPP.
 *
 * Example value:
 *
 *    getenv('LOVEMI_EMAIL_APP_PASSWORD')
 *
 * The actual password is deliberately not included here.
 */


/* ============================================================
   RESPONSE HELPER
============================================================ */

function ticketResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/* ============================================================
   METHOD
============================================================ */

if (
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'POST'
) {

    ticketResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   INPUT
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $rawBody,
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


/* ============================================================
   READ INPUT
============================================================ */

$name =
    trim(
        (string)
        (
            $input['name']
            ??
            ''
        )
    );


$email =
    trim(
        (string)
        (
            $input['email']
            ??
            ''
        )
    );


$category =
    trim(
        (string)
        (
            $input['category']
            ??
            'other'
        )
    );


$subject =
    trim(
        (string)
        (
            $input['subject']
            ??
            ''
        )
    );


$message =
    trim(
        (string)
        (
            $input['message']
            ??
            ''
        )
    );


/* ============================================================
   BASIC VALIDATION
============================================================ */

if (
    $name === ''
) {

    ticketResponse(
        false,
        'Your name is required.',
        [
            'code' =>
                'NAME_REQUIRED'
        ],
        422
    );

}


if (
    mb_strlen(
        $name
    )
    >
    120
) {

    ticketResponse(
        false,
        'Your name is too long.',
        [
            'code' =>
                'NAME_TOO_LONG'
        ],
        422
    );

}


/* ============================================================
   EMAIL VALIDATION
============================================================ */

if (
    $email === ''
) {

    ticketResponse(
        false,
        'Your email address is required.',
        [
            'code' =>
                'EMAIL_REQUIRED'
        ],
        422
    );

}


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    ticketResponse(
        false,
        'Please provide a valid email address.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


if (
    mb_strlen(
        $email
    )
    >
    190
) {

    ticketResponse(
        false,
        'The email address is too long.',
        [
            'code' =>
                'EMAIL_TOO_LONG'
        ],
        422
    );

}


/* ============================================================
   CATEGORY
============================================================ */

$allowedCategories = [

    'account',
    'login',
    'premium',
    'profile',
    'connection',
    'report',
    'technical',
    'contact',
    'other'

];


$category =
    strtolower(
        $category
    );


if (
    !in_array(
        $category,
        $allowedCategories,
        true
    )
) {

    $category =
        'other';

}


/* ============================================================
   SUBJECT
============================================================ */

if (
    $subject === ''
) {

    ticketResponse(
        false,
        'Subject is required.',
        [
            'code' =>
                'SUBJECT_REQUIRED'
        ],
        422
    );

}


if (
    mb_strlen(
        $subject
    )
    >
    180
) {

    ticketResponse(
        false,
        'The subject is too long.',
        [
            'code' =>
                'SUBJECT_TOO_LONG'
        ],
        422
    );

}


/* ============================================================
   MESSAGE
============================================================ */

if (
    $message === ''
) {

    ticketResponse(
        false,
        'Please enter your message.',
        [
            'code' =>
                'MESSAGE_REQUIRED'
        ],
        422
    );

}


if (
    mb_strlen(
        $message
    )
    >
    5000
) {

    ticketResponse(
        false,
        'Your message is too long.',
        [
            'code' =>
                'MESSAGE_TOO_LONG'
        ],
        422
    );

}


/* ============================================================
   ANTI-HEADER-INJECTION
============================================================ */

if (
    preg_match(
        "/[\r\n]/",
        $email
    )
) {

    ticketResponse(
        false,
        'Invalid email address.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


if (
    preg_match(
        "/[\r\n]/",
        $subject
    )
) {

    ticketResponse(
        false,
        'Invalid subject.',
        [
            'code' =>
                'INVALID_SUBJECT'
        ],
        422
    );

}


/* ============================================================
   DATABASE CONNECTION
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SUPPORT DATABASE] '
        .
        $e->getMessage()
    );


    ticketResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   CURRENT USER
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        null;


/* ============================================================
   OPTIONAL USER VERIFICATION
============================================================ */

if (
    $userId !== null
    &&
    $userId > 0
) {

    try {

        $userStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    username,
                    full_names,
                    email,
                    is_active,
                    is_suspended,
                    is_deleted

                FROM users

                WHERE id =
                    :user_id

                LIMIT 1
                "
            );


        $userStmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $currentUser =
            $userStmt->fetch();

    } catch (
        Throwable $e
    ) {

        $currentUser =
            null;

    }


    if (
        $currentUser
    ) {

        /*
         * When the person is logged in, prefer the
         * verified account email only when the submitted
         * email matches it.
         *
         * We do not expose any other private account data.
         */

        if (
            !empty(
                $currentUser['email']
            )
            &&
            strcasecmp(
                $email,
                $currentUser['email']
            )
            ===
            0
        ) {

            $userId =
                (int)
                $currentUser['id'];

        }

    }

}


/* ============================================================
   CREATE SUPPORT TABLE IF NEEDED
============================================================ */

/*
 * The current LOVEMI schema does not have a dedicated
 * support_tickets table in the project tree.
 *
 * This endpoint creates the table safely if it does not
 * already exist.
 *
 * Later, the CREATE TABLE statement can be moved into:
 *
 * database/migrations/...
 *
 * without changing the rest of this endpoint.
 */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS support_tickets
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            user_id BIGINT UNSIGNED NULL,

            name VARCHAR(120) NOT NULL,

            email VARCHAR(190) NOT NULL,

            category VARCHAR(40) NOT NULL DEFAULT 'other',

            subject VARCHAR(180) NOT NULL,

            message TEXT NOT NULL,

            status VARCHAR(30) NOT NULL DEFAULT 'open',

            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            KEY idx_support_user_id (user_id),

            KEY idx_support_email (email),

            KEY idx_support_status (status),

            KEY idx_support_created_at (created_at)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SUPPORT TABLE] '
        .
        $e->getMessage()
    );


    ticketResponse(
        false,
        'The support system could not be initialized.',
        [
            'code' =>
                'SUPPORT_TABLE_ERROR'
        ],
        500
    );

}


/* ============================================================
   SIMPLE DUPLICATE SUBMISSION CHECK
============================================================ */

try {

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT

                id

            FROM support_tickets

            WHERE email =
                  :email

              AND subject =
                  :subject

              AND message =
                  :message

              AND created_at >=
                  DATE_SUB(
                      CURRENT_TIMESTAMP,
                      INTERVAL 5 MINUTE
                  )

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':email' =>
                $email,

            ':subject' =>
                $subject,

            ':message' =>
                $message

        ]
    );


    $duplicateId =
        $duplicateStmt->fetchColumn();

} catch (
    Throwable $e
) {

    $duplicateId =
        null;

}


if (
    $duplicateId
) {

    ticketResponse(
        true,
        'This support request was already submitted recently.',
        [

            'ticket_id' =>
                (int)
                $duplicateId,

            'duplicate' =>
                true

        ]
    );

}


/* ============================================================
   SAVE TICKET
============================================================ */

try {

    $insertStmt =
        $pdo->prepare(
            "
            INSERT INTO support_tickets
            (
                user_id,
                name,
                email,
                category,
                subject,
                message,
                status
            )
            VALUES
            (
                :user_id,
                :name,
                :email,
                :category,
                :subject,
                :message,
                'open'
            )
            "
        );


    $insertStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':name' =>
                $name,

            ':email' =>
                $email,

            ':category' =>
                $category,

            ':subject' =>
                $subject,

            ':message' =>
                $message

        ]
    );


    $ticketId =
        (int)
        $pdo->lastInsertId();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SUPPORT INSERT] '
        .
        $e->getMessage()
    );


    ticketResponse(
        false,
        'The support ticket could not be saved.',
        [
            'code' =>
                'TICKET_SAVE_FAILED'
        ],
        500
    );

}


/* ============================================================
   GENERATE ADMIN EMAIL CONTENT
============================================================ */

$ticketNumber =
    'LM-TKT-'
    .
    str_pad(
        (string)
        $ticketId,
        6,
        '0',
        STR_PAD_LEFT
    );


$safeName =
    htmlspecialchars(
        $name,
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$safeEmail =
    htmlspecialchars(
        $email,
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$safeCategory =
    htmlspecialchars(
        ucfirst(
            $category
        ),
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$safeSubject =
    htmlspecialchars(
        $subject,
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$safeMessage =
    nl2br(
        htmlspecialchars(
            $message,
            ENT_QUOTES |
            ENT_SUBSTITUTE,
            'UTF-8'
        )
    );


$userAgent =
    htmlspecialchars(
        (string)
        (
            $_SERVER['HTTP_USER_AGENT']
            ??
            'Unknown'
        ),
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$remoteAddress =
    htmlspecialchars(
        (string)
        (
            $_SERVER['REMOTE_ADDR']
            ??
            'Unknown'
        ),
        ENT_QUOTES |
        ENT_SUBSTITUTE,
        'UTF-8'
    );


$adminHtml =
    "
    <!DOCTYPE html>

    <html>

    <head>

        <meta charset='UTF-8'>

        <style>

            body {
                font-family: Arial, sans-serif;
                background: #f7f7fb;
                color: #202638;
                margin: 0;
                padding: 30px;
            }

            .wrapper {
                max-width: 680px;
                margin: auto;
                background: #ffffff;
                border-radius: 16px;
                overflow: hidden;
                box-shadow: 0 10px 30px rgba(0,0,0,.08);
            }

            .header {
                background: #e91e63;
                color: #ffffff;
                padding: 24px;
            }

            .body {
                padding: 28px;
            }

            .row {
                padding: 12px 0;
                border-bottom: 1px solid #eeeeee;
            }

            .label {
                font-weight: 700;
                color: #5d6675;
                display: block;
                margin-bottom: 4px;
            }

            .message {
                margin-top: 22px;
                padding: 18px;
                background: #f8f8fb;
                border-radius: 12px;
            }

            .footer {
                padding: 18px 28px;
                background: #fafafd;
                color: #747c8b;
                font-size: 12px;
            }

        </style>

    </head>

    <body>

        <div class='wrapper'>

            <div class='header'>

                <h2 style='margin:0;'>
                    New LOVEMI Support Ticket
                </h2>

                <div style='margin-top:6px;'>
                    {$ticketNumber}
                </div>

            </div>


            <div class='body'>

                <div class='row'>

                    <span class='label'>
                        Name
                    </span>

                    {$safeName}

                </div>


                <div class='row'>

                    <span class='label'>
                        Email
                    </span>

                    {$safeEmail}

                </div>


                <div class='row'>

                    <span class='label'>
                        Category
                    </span>

                    {$safeCategory}

                </div>


                <div class='row'>

                    <span class='label'>
                        Subject
                    </span>

                    {$safeSubject}

                </div>


                <div class='message'>

                    <strong>
                        Message
                    </strong>

                    <div style='margin-top:10px;'>
                        {$safeMessage}
                    </div>

                </div>


                <div style='margin-top:22px;'>

                    <strong>
                        Ticket ID:
                    </strong>

                    {$ticketId}

                </div>


                <div style='margin-top:8px;font-size:12px;color:#7b8290;'>

                    Submitted from:
                    {$remoteAddress}

                </div>


                <div style='margin-top:5px;font-size:12px;color:#7b8290;'>

                    Browser:
                    {$userAgent}

                </div>

            </div>


            <div class='footer'>

                LOVEMI Support System

            </div>

        </div>

    </body>

    </html>
    ";


/* ============================================================
   ADMIN PLAIN TEXT
============================================================ */

$adminText =
    "LOVEMI SUPPORT TICKET\n"
    .
    "======================\n\n"
    .
    "Ticket: {$ticketNumber}\n"
    .
    "Ticket ID: {$ticketId}\n"
    .
    "Name: {$name}\n"
    .
    "Email: {$email}\n"
    .
    "Category: {$category}\n"
    .
    "Subject: {$subject}\n\n"
    .
    "Message:\n"
    .
    $message
    .
    "\n\n"
    .
    "IP: "
    .
    (
        $_SERVER['REMOTE_ADDR']
        ??
        'Unknown'
    )
    .
    "\n";


/* ============================================================
   MAIL PASSWORD
============================================================ */

/*
|--------------------------------------------------------------------------
| Read the SMTP password securely.
|--------------------------------------------------------------------------
|
| Priority:
|
| 1. Environment variable:
|       LOVEMI_EMAIL_APP_PASSWORD
|
| 2. PHP constant with the same name.
|
| The actual secret is never written into the source below.
|
|--------------------------------------------------------------------------
*/

$smtpPassword =
    getenv(
        'LOVEMI_EMAIL_APP_PASSWORD'
    );


if (
    $smtpPassword === false
    ||
    trim(
        $smtpPassword
    )
    ===
    ''
) {

    if (
        defined(
            'LOVEMI_EMAIL_APP_PASSWORD'
        )
    ) {

        $smtpPassword =
            constant(
                'LOVEMI_EMAIL_APP_PASSWORD'
            );

    }

}


if (
    !is_string(
        $smtpPassword
    )
    ||
    trim(
        $smtpPassword
    )
    ===
    ''
) {

    /*
     * Do not delete the saved database ticket.
     *
     * The ticket has already been stored safely in MySQL.
     */

    error_log(
        '[LOVEMI SUPPORT MAIL] SMTP password is not configured.'
    );


    ticketResponse(
        false,
        'Your support ticket was saved, but email delivery is not configured on the server yet.',
        [

            'code' =>
                'SMTP_NOT_CONFIGURED',

            'ticket_id' =>
                $ticketId,

            'ticket_number' =>
                $ticketNumber,

            'saved' =>
                true

        ],
        503
    );

}


/* ============================================================
   SEND EMAIL TO LOVEMI SUPPORT
============================================================ */

$mail =
    new PHPMailer(
        true
    );


$adminMailSent =
    false;


try {

    /*
     * SMTP configuration.
     */

    $mail->isSMTP();

    $mail->Host =
        LOVEMI_SMTP_HOST;

    $mail->SMTPAuth =
        true;

    $mail->Username =
        LOVEMI_SUPPORT_EMAIL;

    $mail->Password =
        $smtpPassword;

    $mail->SMTPSecure =
        LOVEMI_SMTP_ENCRYPTION;

    $mail->Port =
        LOVEMI_SMTP_PORT;


    /*
     * Security/debugging.
     */

    $mail->SMTPDebug =
        0;

    $mail->Timeout =
        30;


    /*
     * Sender.
     */

    $mail->setFrom(
        LOVEMI_SUPPORT_EMAIL,
        LOVEMI_SUPPORT_NAME
    );


    /*
     * Main support recipient.
     */

    $mail->addAddress(
        LOVEMI_SUPPORT_EMAIL,
        LOVEMI_SUPPORT_NAME
    );


    /*
     * Reply directly to the customer.
     */

    $mail->addReplyTo(
        $email,
        $name
    );


    /*
     * Email.
     */

    $mail->isHTML(
        true
    );


    $mail->CharSet =
        'UTF-8';


    $mail->Subject =
        '[LOVEMI SUPPORT] ' .
        $ticketNumber .
        ' - ' .
        $subject;


    $mail->Body =
        $adminHtml;


    $mail->AltBody =
        $adminText;


    $mail->send();


    $adminMailSent =
        true;

} catch (
    Exception $e
) {

    error_log(
        '[LOVEMI SUPPORT ADMIN EMAIL] '
        .
        $mail->ErrorInfo
        .
        ' | '
        .
        $e->getMessage()
    );

}


/* ============================================================
   SEND CUSTOMER CONFIRMATION
============================================================ */

$confirmationSent =
    false;


if (
    $adminMailSent
) {

    $confirmationMail =
        new PHPMailer(
            true
        );


    try {

        $confirmationMail->isSMTP();

        $confirmationMail->Host =
            LOVEMI_SMTP_HOST;

        $confirmationMail->SMTPAuth =
            true;

        $confirmationMail->Username =
            LOVEMI_SUPPORT_EMAIL;

        $confirmationMail->Password =
            $smtpPassword;

        $confirmationMail->SMTPSecure =
            LOVEMI_SMTP_ENCRYPTION;

        $confirmationMail->Port =
            LOVEMI_SMTP_PORT;

        $confirmationMail->SMTPDebug =
            0;

        $confirmationMail->Timeout =
            30;

        $confirmationMail->setFrom(
            LOVEMI_SUPPORT_EMAIL,
            LOVEMI_SUPPORT_NAME
        );

        $confirmationMail->addAddress(
            $email,
            $name
        );

        $confirmationMail->isHTML(
            true
        );

        $confirmationMail->CharSet =
            'UTF-8';


        $confirmationSubject =
            'LOVEMI Support Ticket Received - '
            .
            $ticketNumber;


        $confirmationHtml =
            "
            <!DOCTYPE html>

            <html>

            <head>

                <meta charset='UTF-8'>

                <style>

                    body {
                        font-family: Arial, sans-serif;
                        background: #f7f7fb;
                        color: #202638;
                        margin: 0;
                        padding: 30px;
                    }

                    .card {
                        max-width: 620px;
                        margin: auto;
                        background: #ffffff;
                        border-radius: 16px;
                        overflow: hidden;
                        box-shadow: 0 10px 30px rgba(0,0,0,.08);
                    }

                    .header {
                        background: #e91e63;
                        color: #ffffff;
                        padding: 25px;
                    }

                    .body {
                        padding: 30px;
                    }

                    .ticket {
                        padding: 15px;
                        border-radius: 12px;
                        background: #f8f8fb;
                        margin: 20px 0;
                    }

                    .footer {
                        padding: 18px 30px;
                        background: #fafafd;
                        color: #747c8b;
                        font-size: 12px;
                    }

                </style>

            </head>

            <body>

                <div class='card'>

                    <div class='header'>

                        <h2 style='margin:0;'>
                            LOVEMI Support
                        </h2>

                    </div>


                    <div class='body'>

                        <p>
                            Hello {$safeName},
                        </p>

                        <p>
                            We have received your support request.
                            Our support team can review it using
                            the ticket number below.
                        </p>


                        <div class='ticket'>

                            <strong>
                                Ticket Number
                            </strong>

                            <div style='font-size:20px;margin-top:7px;'>

                                {$ticketNumber}

                            </div>


                            <div style='margin-top:12px;'>

                                <strong>
                                    Subject:
                                </strong>

                                {$safeSubject}

                            </div>

                        </div>


                        <p>
                            Please keep this ticket number for
                            future reference.
                        </p>


                        <p>
                            LOVEMI Support<br>
                            {$safeEmail}
                        </p>

                    </div>


                    <div class='footer'>

                        Support email:
                        eduassistasc@gmail.com

                    </div>

                </div>

            </body>

            </html>
            ";


        $confirmationText =
            "Hello {$name},\n\n"
            .
            "Your LOVEMI support ticket has been received.\n\n"
            .
            "Ticket: {$ticketNumber}\n"
            .
            "Subject: {$subject}\n\n"
            .
            "Please keep this ticket number for reference.\n\n"
            .
            "LOVEMI Support\n"
            .
            "eduassistasc@gmail.com";


        $confirmationMail->Subject =
            $confirmationSubject;


        $confirmationMail->Body =
            $confirmationHtml;


        $confirmationMail->AltBody =
            $confirmationText;


        $confirmationMail->send();


        $confirmationSent =
            true;

    } catch (
        Exception $e
    ) {

        error_log(
            '[LOVEMI SUPPORT CUSTOMER EMAIL] '
            .
            $confirmationMail->ErrorInfo
            .
            ' | '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   UPDATE STATUS
============================================================ */

if (
    $adminMailSent
) {

    try {

        $statusStmt =
            $pdo->prepare(
                "
                UPDATE support_tickets

                SET

                    status =
                        'received',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :ticket_id

                LIMIT 1
                "
            );


        $statusStmt->execute(
            [
                ':ticket_id' =>
                    $ticketId
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI SUPPORT STATUS UPDATE] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   FINAL RESPONSE
============================================================ */

if (
    $adminMailSent
) {

    ticketResponse(
        true,
        'Your support ticket has been sent successfully.',
        [

            'ticket_id' =>
                $ticketId,

            'ticket_number' =>
                $ticketNumber,

            'email_sent' =>
                true,

            'confirmation_sent' =>
                $confirmationSent,

            'status' =>
                'received'

        ],
        201
    );

}


/*
|--------------------------------------------------------------------------
| Ticket was saved but email failed.
|--------------------------------------------------------------------------
*/

ticketResponse(
    false,
    'Your support ticket was saved, but the support email could not be delivered. Please try again later.',
    [

        'ticket_id' =>
            $ticketId,

        'ticket_number' =>
            $ticketNumber,

        'saved' =>
            true,

        'email_sent' =>
            false,

        'status' =>
            'open'

    ],
    503
);