<?php

/**
 * ============================================================
 * LOVEMI - VERIFY PASSWORD RESET LINK
 * ============================================================
 *
 * The user reaches this endpoint from the email.
 *
 * This endpoint:
 *
 * 1. Validates email + reset token.
 * 2. Checks that the reset request is still active.
 * 3. Checks expiry.
 * 4. Marks the link as verified.
 * 5. Stores the reset request ID in session.
 * 6. Redirects to reset-password.html.
 *
 * The verification code is NOT accepted here.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

date_default_timezone_set(
    'Africa/Nairobi'
);


if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   ERROR PAGE
============================================================ */

function resetLinkError(
    string $message
): never {

    http_response_code(
        400
    );

    header(
        'Content-Type: text/html; charset=utf-8'
    );

    $safeMessage =
        htmlspecialchars(
            $message,
            ENT_QUOTES |
            ENT_HTML5,
            'UTF-8'
        );

    echo <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>LOVEMI | Invalid Reset Link</title>
<style>
body{
    margin:0;
    min-height:100vh;
    display:flex;
    align-items:center;
    justify-content:center;
    background:#f7f7fb;
    font-family:Arial,sans-serif;
    color:#18181b;
}
.card{
    width:min(92%,520px);
    background:#fff;
    border:1px solid #e8e8ef;
    border-radius:20px;
    padding:30px;
    box-shadow:0 18px 55px rgba(24,24,27,.09);
}
h1{
    margin:0 0 10px;
    color:#7c3aed;
    font-family:Georgia,serif;
}
p{
    color:#71717a;
    line-height:1.7;
}
a{
    display:inline-block;
    margin-top:10px;
    padding:12px 18px;
    border-radius:10px;
    color:#fff;
    background:linear-gradient(135deg,#7c3aed,#ec4899);
    text-decoration:none;
    font-weight:bold;
}
</style>
</head>
<body>
<div class="card">
    <h1>LOVEMI</h1>
    <h2>Reset Link Problem</h2>
    <p>{$safeMessage}</p>
    <a href="../../forgot-password.html">
        Request a New Reset Email
    </a>
</div>
</body>
</html>
HTML;

    exit;
}


/* ============================================================
   INPUT
============================================================ */

$email =
    trim(
        (string)(
            $_GET['email']
            ?? ''
        )
    );


$token =
    trim(
        (string)(
            $_GET['token']
            ?? ''
        )
    );


if (
    $email === ''
    ||
    $token === ''
) {

    resetLinkError(
        'The password-reset link is incomplete.'
    );

}


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    resetLinkError(
        'The password-reset email address is invalid.'
    );

}


if (
    strlen($token) < 40
) {

    resetLinkError(
        'The password-reset link is invalid.'
    );

}


/* ============================================================
   TOKEN HASH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $token
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY RESET DB] '
        .
        $e->getMessage()
    );

    resetLinkError(
        'LOVEMI could not connect to the database.'
    );

}


/* ============================================================
   LOAD RESET REQUEST
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                pr.id,
                pr.user_id,
                pr.email,
                pr.reset_token_hash,
                pr.expires_at,
                pr.used_at,
                pr.blocked_at,
                pr.link_verified_at

            FROM password_resets pr

            WHERE pr.email = :email

              AND pr.reset_token_hash = :token_hash

            ORDER BY pr.id DESC

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':email' =>
                $email,

            ':token_hash' =>
                $tokenHash

        ]
    );


    $reset =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY RESET QUERY] '
        .
        $e->getMessage()
    );

    resetLinkError(
        'LOVEMI could not verify the reset request.'
    );

}


/* ============================================================
   VALIDATE REQUEST
============================================================ */

if (
    !$reset
) {

    resetLinkError(
        'This password-reset link is invalid or no longer available.'
    );

}


if (
    !empty(
        $reset['used_at']
    )
) {

    resetLinkError(
        'This password-reset link has already been used.'
    );

}


if (
    !empty(
        $reset['blocked_at']
    )
) {

    resetLinkError(
        'This password-reset request has been blocked. Please start again.'
    );

}


$expiresTimestamp =
    strtotime(
        (string)$reset['expires_at']
    );


if (
    $expiresTimestamp === false
    ||
    $expiresTimestamp < time()
) {

    resetLinkError(
        'This password-reset link has expired. Please request a new one.'
    );

}


/* ============================================================
   MARK LINK VERIFIED
============================================================ */

try {

    $updateStmt =
        $pdo->prepare(
            "
            UPDATE password_resets

            SET
                link_verified_at =
                    COALESCE(
                        link_verified_at,
                        CURRENT_TIMESTAMP
                    )

            WHERE id = :id

              AND used_at IS NULL

              AND blocked_at IS NULL
            "
        );


    $updateStmt->execute(
        [
            ':id' =>
                (int)$reset['id']
        ]
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY RESET UPDATE] '
        .
        $e->getMessage()
    );

    resetLinkError(
        'Unable to verify this password-reset link.'
    );

}


/* ============================================================
   SESSION
============================================================ */

$_SESSION[
    'lovemi_password_reset_request_id'
] =
    (int)$reset['id'];

$_SESSION[
    'lovemi_password_reset_link_verified'
] =
    true;


/* ============================================================
   REDIRECT
============================================================ */

$redirectUrl =
    '../../reset-password.html?email='
    .
    rawurlencode(
        $email
    )
    .
    '&token='
    .
    rawurlencode(
        $token
    );


header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Location: ' . $redirectUrl
);

exit;