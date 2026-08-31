<?php
/**
 * ============================================================
 * LOVEMI - EMAIL SERVICE
 * ============================================================
 *
 * Uses PHPMailer + Gmail SMTP.
 *
 * The SMTP password is read from:
 *
 * LOVEMI_SMTP_PASSWORD
 *
 * Never hardcode the Gmail app password in source code.
 * ============================================================
 */

declare(strict_types=1);


use PHPMailer\PHPMailer\Exception;
use PHPMailer\PHPMailer\PHPMailer;


/* ============================================================
   PHPMailer
============================================================ */

$autoloadPaths = [

    __DIR__ . '/../../api/auth/vendor/autoload.php',

    __DIR__ . '/../../api/auth/PHPMailer/src/PHPMailer.php'

];


$autoloadLoaded = false;


foreach ($autoloadPaths as $path) {

    if (is_file($path)) {

        if (
            str_ends_with(
                $path,
                'autoload.php'
            )
        ) {

            require_once $path;

        } else {

            require_once
                __DIR__ . '/../../api/auth/PHPMailer/src/Exception.php';

            require_once
                __DIR__ . '/../../api/auth/PHPMailer/src/PHPMailer.php';

            require_once
                __DIR__ . '/../../api/auth/PHPMailer/src/SMTP.php';

        }


        $autoloadLoaded = true;

        break;
    }
}


if (!$autoloadLoaded) {

    throw new RuntimeException(
        'PHPMailer installation could not be found.'
    );
}


/* ============================================================
   SEND EMAIL
============================================================ */

function sendLovemiEmail(
    string $recipientEmail,
    string $recipientName,
    string $subject,
    string $htmlBody,
    ?string $plainBody = null
): bool {

    $smtpPassword =
        'perydjozslvakfwt';


    if (
        !is_string($smtpPassword)
        ||
        trim($smtpPassword) === ''
    ) {

        throw new RuntimeException(
            'LOVEMI_SMTP_PASSWORD is not configured.'
        );
    }


    $mail =
        new PHPMailer(true);


    try {

        $mail->isSMTP();


        $mail->Host =
            'smtp.gmail.com';


        $mail->SMTPAuth =
            true;


        $mail->Username =
            'eduassistasc@gmail.com';


        $mail->Password =
            $smtpPassword;


        $mail->SMTPSecure =
            PHPMailer::ENCRYPTION_STARTTLS;


        $mail->Port =
            587;


        $mail->CharSet =
            'UTF-8';


        $mail->setFrom(
            'eduassistasc@gmail.com',
            'LOVEMI'
        );


        $mail->addAddress(
            $recipientEmail,
            $recipientName
        );


        $mail->isHTML(true);


        $mail->Subject =
            $subject;


        $mail->Body =
            $htmlBody;


        $mail->AltBody =
            $plainBody
            ??
            strip_tags(
                $htmlBody
            );


        $mail->send();


        return true;


    } catch (Exception $e) {

        error_log(
            '[LOVEMI EMAIL ERROR] '
            . $e->getMessage()
        );


        return false;
    }
}


/* ============================================================
   VERIFICATION EMAIL
============================================================ */

function sendLovemiVerificationEmail(
    string $email,
    string $fullName,
    string $code
): bool {

    $safeName =
        htmlspecialchars(
            $fullName,
            ENT_QUOTES,
            'UTF-8'
        );


    $safeCode =
        htmlspecialchars(
            $code,
            ENT_QUOTES,
            'UTF-8'
        );


    $html = <<<HTML
<!DOCTYPE html>
<html>
<body style="margin:0;background:#f7f7fb;font-family:Arial,sans-serif;">

<div style="max-width:600px;margin:30px auto;background:#ffffff;border-radius:18px;padding:35px;">

    <h1 style="color:#6d28d9;margin-top:0;">
        LOVEMI
    </h1>

    <p>
        Hello {$safeName},
    </p>

    <p>
        Thank you for creating your LOVEMI account.
        Use the verification code below to verify your email address.
    </p>

    <div style="
        text-align:center;
        margin:30px 0;
        padding:20px;
        background:#f3e8ff;
        border-radius:14px;
        font-size:30px;
        font-weight:bold;
        letter-spacing:8px;
        color:#6d28d9;
    ">
        {$safeCode}
    </div>

    <p>
        This verification code expires in 10 minutes.
    </p>

    <p>
        Do not share this code with anyone.
    </p>

    <p style="color:#777;">
        LOVEMI<br>
        Discover • Connect • Meet
    </p>

</div>

</body>
</html>
HTML;


    return sendLovemiEmail(
        $email,
        $fullName,
        'LOVEMI Email Verification Code',
        $html
    );
}