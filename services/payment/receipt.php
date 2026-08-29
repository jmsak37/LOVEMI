<?php
/**
 * ============================================================
 * LOVEMI EMAIL SERVICE
 * ============================================================
 *
 * Central email service for:
 *
 *     - email verification
 *     - password/reset messages
 *     - Premium notifications
 *     - payment notifications
 *     - account notifications
 *     - system notifications
 *
 * PHPMailer is used.
 *
 * Credentials MUST be server-side environment variables.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   LOAD PHPMailer
============================================================ */

/*
 * Your current project has:
 *
 * api/auth/vendor/autoload.php
 *
 * which contains PHPMailer.
 */

$autoload =
    dirname(
        __DIR__,
        2
    )
    .
    DIRECTORY_SEPARATOR
    .
    'api'
    .
    DIRECTORY_SEPARATOR
    .
    'auth'
    .
    DIRECTORY_SEPARATOR
    .
    'vendor'
    .
    DIRECTORY_SEPARATOR
    .
    'autoload.php';


if (
    is_file($autoload)
) {

    require_once $autoload;

} else {

    /*
     * Fallback for installations that use the bundled PHPMailer
     * directly rather than Composer.
     */

    $phpmailerSrc =
        dirname(
            __DIR__,
            2
        )
        .
        DIRECTORY_SEPARATOR
        .
        'api'
        .
        DIRECTORY_SEPARATOR
        .
        'auth'
        .
        DIRECTORY_SEPARATOR
        .
        'PHPMailer'
        .
        DIRECTORY_SEPARATOR
        .
        'src';


    require_once
        $phpmailerSrc
        .
        DIRECTORY_SEPARATOR
        .
        'Exception.php';


    require_once
        $phpmailerSrc
        .
        DIRECTORY_SEPARATOR
        .
        'PHPMailer.php';


    require_once
        $phpmailerSrc
        .
        DIRECTORY_SEPARATOR
        .
        'SMTP.php';

}


use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPMailer\PHPMailer\PHPMailer;


/* ============================================================
   SERVICE EXCEPTION
============================================================ */

class LovemiEmailException extends RuntimeException
{
}


/* ============================================================
   EMAIL SERVICE CLASS
============================================================ */

final class LovemiEmailService
{

    private string $host;

    private int $port;

    private string $username;

    private string $password;

    private string $encryption;

    private string $fromEmail;

    private string $fromName;

    private int $timeout;


    /* ========================================================
       CONSTRUCTOR
    ========================================================= */

    public function __construct()
    {

        $this->host =
            $this->env(
                'LOVEMI_MAIL_HOST',
                'smtp.gmail.com'
            );


        $this->port =
            (int)
            $this->env(
                'LOVEMI_MAIL_PORT',
                '587'
            );


        $this->username =
            $this->env(
                'LOVEMI_MAIL_USERNAME'
            );


        $this->password =
            $this->env(
                'LOVEMI_MAIL_PASSWORD'
            );


        $this->encryption =
            strtolower(
                $this->env(
                    'LOVEMI_MAIL_ENCRYPTION',
                    'tls'
                )
            );


        $this->fromEmail =
            $this->env(
                'LOVEMI_MAIL_FROM',
                $this->username
            );


        $this->fromName =
            $this->env(
                'LOVEMI_MAIL_FROM_NAME',
                'LOVEMI'
            );


        $this->timeout =
            max(
                10,
                (int)
                $this->env(
                    'LOVEMI_MAIL_TIMEOUT',
                    '30'
                )
            );

    }


    /* ========================================================
       ENVIRONMENT
    ========================================================= */

    private function env(
        string $name,
        string $default = ''
    ): string {

        $value =
            getenv(
                $name
            );


        if (
            $value === false
        ) {

            return $default;

        }


        return trim(
            (string)
            $value
        );

    }


    /* ========================================================
       CONFIGURED
    ========================================================= */

    public function isConfigured(): bool
    {

        return
            $this->host !== ''
            &&
            $this->username !== ''
            &&
            $this->password !== ''
            &&
            filter_var(
                $this->fromEmail,
                FILTER_VALIDATE_EMAIL
            ) !== false;

    }


    /* ========================================================
       MAILER
    ========================================================= */

    private function createMailer(): PHPMailer
    {

        if (
            !$this->isConfigured()
        ) {

            throw new LovemiEmailException(
                'LOVEMI email service is not configured.'
            );

        }


        $mail =
            new PHPMailer(
                true
            );


        /*
         * SMTP.
         */

        $mail->isSMTP();


        $mail->Host =
            $this->host;


        $mail->Port =
            $this->port;


        $mail->SMTPAuth =
            true;


        $mail->Username =
            $this->username;


        $mail->Password =
            $this->password;


        $mail->Timeout =
            $this->timeout;


        /*
         * Encryption.
         */

        if (
            $this->encryption ===
            'ssl'
            ||
            $this->port === 465
        ) {

            $mail->SMTPSecure =
                PHPMailer::ENCRYPTION_SMTPS;

        } else {

            $mail->SMTPSecure =
                PHPMailer::ENCRYPTION_STARTTLS;

        }


        /*
         * Security.
         */

        $mail->CharSet =
            'UTF-8';


        $mail->Encoding =
            'base64';


        $mail->setFrom(
            $this->fromEmail,
            $this->fromName
        );


        /*
         * Avoid accidental debug output.
         */

        $mail->SMTPDebug =
            0;


        return $mail;

    }


    /* ========================================================
       SEND HTML EMAIL
    ========================================================= */

    public function send(
        string $to,
        string $subject,
        string $html,
        ?string $plainText = null,
        ?string $replyTo = null
    ): bool {

        if (
            !filter_var(
                $to,
                FILTER_VALIDATE_EMAIL
            )
        ) {

            throw new LovemiEmailException(
                'Invalid recipient email address.'
            );

        }


        if (
            trim($subject) === ''
        ) {

            throw new LovemiEmailException(
                'Email subject cannot be empty.'
            );

        }


        if (
            trim($html) === ''
        ) {

            throw new LovemiEmailException(
                'Email body cannot be empty.'
            );

        }


        try {

            $mail =
                $this->createMailer();


            $mail->addAddress(
                $to
            );


            if (
                $replyTo !== null
                &&
                filter_var(
                    $replyTo,
                    FILTER_VALIDATE_EMAIL
                )
            ) {

                $mail->addReplyTo(
                    $replyTo
                );

            }


            $mail->Subject =
                $subject;


            $mail->isHTML(
                true
            );


            $mail->Body =
                $html;


            $mail->AltBody =
                $plainText
                ??
                $this->htmlToText(
                    $html
                );


            $mail->send();


            return true;


        } catch (
            PHPMailerException $e
        ) {

            error_log(
                '[LOVEMI EMAIL] '
                .
                $e->getMessage()
            );


            throw new LovemiEmailException(
                'The email could not be sent.'
            );

        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI EMAIL GENERAL] '
                .
                $e->getMessage()
            );


            throw new LovemiEmailException(
                'The email could not be sent.'
            );

        }

    }


    /* ========================================================
       HTML TO TEXT
    ========================================================= */

    private function htmlToText(
        string $html
    ): string {

        $text =
            preg_replace(
                '/<br\s*\/?>/i',
                "\n",
                $html
            );


        $text =
            preg_replace(
                '/<\/p>/i',
                "\n\n",
                (string)
                $text
            );


        $text =
            strip_tags(
                (string)
                $text
            );


        $text =
            html_entity_decode(
                $text,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $text =
            preg_replace(
                "/[ \t]+/",
                " ",
                $text
            );


        $text =
            preg_replace(
                "/\n{3,}/",
                "\n\n",
                (string)
                $text
            );


        return trim(
            (string)
            $text
        );

    }


    /* ========================================================
       EMAIL VERIFICATION
    ========================================================= */

    public function sendVerificationCode(
        string $to,
        string $name,
        string $code,
        int $expiresMinutes = 2
    ): bool {

        $safeName =
            htmlspecialchars(
                $name,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $safeCode =
            htmlspecialchars(
                $code,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $expiresMinutes =
            max(
                1,
                $expiresMinutes
            );


        $subject =
            'LOVEMI Email Verification Code';


        $html = $this->baseTemplate(
            'Verify your LOVEMI account',
            "
            <p>Hello {$safeName},</p>

            <p>
                Your LOVEMI verification code is:
            </p>

            <div class=\"code\">
                {$safeCode}
            </div>

            <p>
                This code expires in
                {$expiresMinutes}
                minute(s).
            </p>

            <p>
                Do not share this code with anyone.
            </p>
            "
        );


        return $this->send(
            $to,
            $subject,
            $html
        );

    }


    /* ========================================================
       PASSWORD RESET
    ========================================================= */

    public function sendPasswordResetCode(
        string $to,
        string $name,
        string $code,
        int $expiresMinutes = 10
    ): bool {

        $safeName =
            htmlspecialchars(
                $name,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $safeCode =
            htmlspecialchars(
                $code,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $subject =
            'LOVEMI Password Reset Verification';


        $html =
            $this->baseTemplate(
                'Password reset request',
                "
                <p>Hello {$safeName},</p>

                <p>
                    Your password reset verification code is:
                </p>

                <div class=\"code\">
                    {$safeCode}
                </div>

                <p>
                    This code expires in
                    {$expiresMinutes}
                    minute(s).
                </p>

                <p>
                    If you did not request a password reset,
                    you can safely ignore this email.
                </p>
                "
            );


        return $this->send(
            $to,
            $subject,
            $html
        );

    }


    /* ========================================================
       PREMIUM ACTIVATED
    ========================================================= */

    public function sendPremiumActivated(
        string $to,
        string $name,
        string $serviceName,
        string $endAt,
        string $amountDisplay
    ): bool {

        $safeName =
            htmlspecialchars(
                $name,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $safeService =
            htmlspecialchars(
                $serviceName,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $safeEnd =
            htmlspecialchars(
                $endAt,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $safeAmount =
            htmlspecialchars(
                $amountDisplay,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $html =
            $this->baseTemplate(
                'LOVEMI Premium Activated',
                "
                <p>Hello {$safeName},</p>

                <p>
                    Your LOVEMI Premium membership is now active.
                </p>

                <p>
                    <strong>Service:</strong>
                    {$safeService}
                </p>

                <p>
                    <strong>Amount:</strong>
                    {$safeAmount}
                </p>

                <p>
                    <strong>Expires:</strong>
                    {$safeEnd}
                </p>

                <p>
                    Thank you for using LOVEMI.
                </p>
                "
            );


        return $this->send(
            $to,
            'LOVEMI Premium Activated',
            $html
        );

    }


    /* ========================================================
       BASE TEMPLATE
    ========================================================= */

    private function baseTemplate(
        string $title,
        string $content
    ): string {

        $safeTitle =
            htmlspecialchars(
                $title,
                ENT_QUOTES |
                ENT_HTML5,
                'UTF-8'
            );


        $appName =
            'LOVEMI';


        return "
        <!DOCTYPE html>

        <html lang=\"en\">

        <head>

            <meta charset=\"UTF-8\">

            <meta name=\"viewport\"
                  content=\"width=device-width,
                           initial-scale=1.0\">

            <title>
                {$safeTitle}
            </title>

        </head>

        <body
            style=\"
                margin:0;
                padding:0;
                background:#f7f7fb;
                font-family:Arial,sans-serif;
                color:#18181b;
            \">

            <div
                style=\"
                    max-width:620px;
                    margin:35px auto;
                    padding:20px;
                \">

                <div
                    style=\"
                        background:white;
                        border:1px solid #e9e9ef;
                        border-radius:18px;
                        padding:30px;
                    \">

                    <h1
                        style=\"
                            margin:0 0 20px;
                            color:#6d28d9;
                            font-size:26px;
                        \">

                        {$appName}

                    </h1>

                    <h2
                        style=\"
                            margin:0 0 15px;
                            font-size:19px;
                        \">

                        {$safeTitle}

                    </h2>

                    <div
                        style=\"
                            font-size:14px;
                            line-height:1.7;
                        \">

                        {$content}

                    </div>

                </div>

                <p
                    style=\"
                        text-align:center;
                        color:#9898a1;
                        font-size:11px;
                        margin-top:18px;
                    \">

                    © "
                    . date('Y')
                    . "
                    LOVEMI.
                    All rights reserved.

                </p>

            </div>

        </body>

        </html>
        ";

    }

}


/* ============================================================
   FACTORY
============================================================ */

function lovemiEmailService(): LovemiEmailService
{

    static $service = null;


    if (
        $service === null
    ) {

        $service =
            new LovemiEmailService();

    }


    return $service;

}