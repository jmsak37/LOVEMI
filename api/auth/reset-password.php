<?php

/**
 * ============================================================
 * LOVEMI - RESET PASSWORD API
 * ============================================================
 *
 * Flow:
 *
 * 1. Verification link must already be verified.
 * 2. User enters the 6-digit verification code.
 * 3. Code is checked.
 * 4. New password is saved.
 * 5. Reset request is marked as used.
 * 6. A password-changed security email is sent.
 * 7. Reset session is cleared.
 *
 * GET:
 *   ?action=status&email=...&token=...
 *
 * POST:
 *   email
 *   token
 *   code
 *   password
 *   password_confirmation
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   REQUIRED FILES
============================================================ */

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';


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


/* ============================================================
   TIMEZONE
============================================================ */

date_default_timezone_set(
    'Africa/Nairobi'
);


/* ============================================================
   SESSION
============================================================ */

if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   JSON RESPONSE
============================================================ */

function resetResponse(
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
   BUILD APP URL
============================================================ */

function lovemiAppBaseUrl(): string
{
    /*
     * Prefer explicit production URL when configured.
     *
     * Example:
     * LOVEMI_APP_URL=https://www.example.com/LOVEMI
     */

    $configured =
        trim(
            (string)(
                getenv('LOVEMI_APP_URL')
                ?: ''
            )
        );


    if (
        $configured !== ''
    ) {

        return rtrim(
            $configured,
            '/'
        );

    }


    $https =
        !empty(
            $_SERVER['HTTPS']
        )
        &&
        strtolower(
            (string)$_SERVER['HTTPS']
        ) !== 'off';


    $scheme =
        $https
            ? 'https'
            : 'http';


    $host =
        trim(
            (string)(
                $_SERVER['HTTP_HOST']
                ?? 'localhost'
            )
        );


    /*
     * reset-password.php is located at:
     *
     * /LOVEMI/api/auth/reset-password.php
     *
     * We remove:
     *
     * /api/auth/reset-password.php
     */

    $scriptName =
        str_replace(
            '\\',
            '/',
            (string)(
                $_SERVER['SCRIPT_NAME']
                ?? '/LOVEMI/api/auth/reset-password.php'
            )
        );


    $basePath =
        preg_replace(
            '#/api/auth/reset-password\.php$#',
            '',
            $scriptName
        );


    if (
        !is_string($basePath)
        ||
        $basePath === ''
    ) {

        $basePath =
            '/LOVEMI';

    }


    return
        $scheme
        .
        '://'
        .
        $host
        .
        rtrim(
            $basePath,
            '/'
        );
}


/* ============================================================
   SEND PASSWORD CHANGED EMAIL
============================================================ */

function sendPasswordChangedEmail(
    string $email,
    string $fullName
): bool {

    $safeName =
        htmlspecialchars(
            $fullName,
            ENT_QUOTES |
            ENT_HTML5,
            'UTF-8'
        );


    $year =
        date('Y');


    $dateTime =
        date(
            'F j, Y \a\t g:i A'
        );


    $ipAddress =
        trim(
            (string)(
                $_SERVER['REMOTE_ADDR']
                ?? 'Unknown'
            )
        );


    /*
     * Do not expose an invalid/empty IP address.
     */

    if (
        $ipAddress === ''
    ) {

        $ipAddress =
            'Unknown';

    }


    $safeIp =
        htmlspecialchars(
            $ipAddress,
            ENT_QUOTES |
            ENT_HTML5,
            'UTF-8'
        );


    $loginUrl =
        lovemiAppBaseUrl()
        .
        '/login.html';


    $safeLoginUrl =
        htmlspecialchars(
            $loginUrl,
            ENT_QUOTES |
            ENT_HTML5,
            'UTF-8'
        );


    $html = <<<HTML
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,initial-scale=1.0"
    >

    <title>LOVEMI - Password Changed</title>

</head>


<body
    style="
        margin:0;
        padding:0;
        background:#f7f7fb;
        font-family:
            Arial,
            Helvetica,
            sans-serif;
        color:#18181b;
    "
>

    <div
        style="
            width:100%;
            padding:35px 15px;
            box-sizing:border-box;
        "
    >

        <div
            style="
                max-width:620px;
                margin:0 auto;
                background:#ffffff;
                border:
                    1px solid #e8e8ef;
                border-radius:20px;
                overflow:hidden;
                box-shadow:
                    0 12px 35px
                    rgba(24,24,27,.08);
            "
        >

            <!-- HEADER -->

            <div
                style="
                    padding:28px 30px;
                    background:
                        linear-gradient(
                            135deg,
                            #7c3aed,
                            #ec4899
                        );
                    color:#ffffff;
                "
            >

                <div
                    style="
                        font-family:
                            Georgia,
                            'Times New Roman',
                            serif;
                        font-size:28px;
                        font-weight:800;
                        letter-spacing:.2px;
                    "
                >
                    LOVEMI
                </div>


                <div
                    style="
                        margin-top:6px;
                        font-size:12px;
                        opacity:.95;
                    "
                >
                    Discover • Connect • Meet
                </div>

            </div>


            <!-- CONTENT -->

            <div
                style="
                    padding:32px 30px;
                "
            >

                <div
                    style="
                        display:inline-block;
                        padding:7px 12px;
                        border-radius:999px;
                        background:#ecfdf5;
                        color:#047857;
                        font-size:11px;
                        font-weight:700;
                        letter-spacing:.3px;
                    "
                >
                    SECURITY CONFIRMATION
                </div>


                <h1
                    style="
                        margin:
                            15px 0 12px;
                        font-size:25px;
                        line-height:1.3;
                        color:#18181b;
                    "
                >
                    Your password was changed
                </h1>


                <p
                    style="
                        margin:0 0 16px;
                        font-size:14px;
                        line-height:1.8;
                        color:#27272a;
                    "
                >
                    Hello
                    <strong>{$safeName}</strong>,
                </p>


                <p
                    style="
                        margin:0 0 16px;
                        font-size:14px;
                        line-height:1.8;
                        color:#3f3f46;
                    "
                >
                    Your LOVEMI account password was changed
                    successfully.
                </p>


                <!-- SUCCESS BOX -->

                <div
                    style="
                        margin:
                            22px 0;
                        padding:20px;
                        background:#f0fdf4;
                        border:
                            1px solid #bbf7d0;
                        border-radius:14px;
                    "
                >

                    <div
                        style="
                            font-size:14px;
                            font-weight:700;
                            color:#166534;
                            margin-bottom:8px;
                        "
                    >
                        ✓ Password change completed
                    </div>


                    <div
                        style="
                            font-size:12px;
                            line-height:1.7;
                            color:#3f6212;
                        "
                    >
                        Your new password is now active and
                        your previous password can no longer
                        be used to sign in.
                    </div>

                </div>


                <!-- DETAILS -->

                <div
                    style="
                        margin:
                            22px 0;
                        padding:20px;
                        background:#fafafa;
                        border:
                            1px solid #ececf2;
                        border-radius:14px;
                    "
                >

                    <div
                        style="
                            font-size:12px;
                            font-weight:700;
                            color:#18181b;
                            margin-bottom:14px;
                        "
                    >
                        Password change details
                    </div>


                    <table
                        width="100%"
                        cellpadding="0"
                        cellspacing="0"
                        border="0"
                        style="
                            font-size:12px;
                            line-height:1.7;
                        "
                    >

                        <tr>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#71717a;
                                    width:40%;
                                "
                            >
                                Date
                            </td>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#27272a;
                                    font-weight:600;
                                "
                            >
                                {$dateTime}
                            </td>

                        </tr>


                        <tr>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#71717a;
                                "
                            >
                                Connection
                            </td>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#27272a;
                                    font-weight:600;
                                "
                            >
                                LOVEMI Account Security
                            </td>

                        </tr>


                        <tr>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#71717a;
                                "
                            >
                                IP address
                            </td>

                            <td
                                style="
                                    padding:5px 0;
                                    color:#27272a;
                                    font-weight:600;
                                "
                            >
                                {$safeIp}
                            </td>

                        </tr>

                    </table>

                </div>


                <!-- NOT YOU -->

                <div
                    style="
                        margin:
                            22px 0;
                        padding:18px 20px;
                        background:#fff7ed;
                        border:
                            1px solid #fed7aa;
                        border-radius:14px;
                    "
                >

                    <div
                        style="
                            font-size:13px;
                            font-weight:700;
                            color:#9a3412;
                            margin-bottom:7px;
                        "
                    >
                        Didn't make this change?
                    </div>


                    <div
                        style="
                            font-size:12px;
                            line-height:1.7;
                            color:#7c2d12;
                        "
                    >
                        Please sign in to LOVEMI immediately
                        and review your account security.
                        If you believe someone else accessed
                        your account, contact LOVEMI support.
                    </div>

                </div>


                <!-- LOGIN BUTTON -->

                <div
                    style="
                        text-align:center;
                        margin:28px 0 20px;
                    "
                >

                    <a
                        href="{$safeLoginUrl}"
                        style="
                            display:inline-block;
                            padding:
                                13px 24px;
                            border-radius:10px;
                            background:
                                linear-gradient(
                                    135deg,
                                    #7c3aed,
                                    #ec4899
                                );
                            color:#ffffff;
                            text-decoration:none;
                            font-size:13px;
                            font-weight:700;
                        "
                    >
                        Sign In to LOVEMI
                    </a>

                </div>


                <p
                    style="
                        margin:22px 0 0;
                        padding-top:18px;
                        border-top:
                            1px solid #eeeeF3;
                        font-size:11px;
                        line-height:1.7;
                        color:#71717a;
                    "
                >
                    For your security, LOVEMI will never ask
                    you to send your password or verification
                    code by email, chat or comment.
                </p>

            </div>


            <!-- FOOTER -->

            <div
                style="
                    padding:
                        22px 30px;
                    background:#fafafa;
                    border-top:
                        1px solid #eeeeF3;
                    text-align:center;
                "
            >

                <div
                    style="
                        font-family:
                            Georgia,
                            'Times New Roman',
                            serif;
                        font-size:15px;
                        font-weight:700;
                        color:#18181b;
                    "
                >
                    LOVEMI
                </div>


                <div
                    style="
                        margin-top:5px;
                        font-size:11px;
                        color:#a1a1aa;
                    "
                >
                    Discover • Connect • Meet
                </div>


                <div
                    style="
                        margin-top:10px;
                        font-size:10px;
                        color:#a1a1aa;
                    "
                >
                    © {$year} LOVEMI. All rights reserved.
                </div>

            </div>

        </div>

    </div>

</body>

</html>
HTML;


    $plainText =

        "LOVEMI - PASSWORD CHANGED\n\n"
        .
        "Hello {$fullName},\n\n"
        .
        "Your LOVEMI account password was changed successfully.\n\n"
        .
        "Date: {$dateTime}\n"
        .
        "IP address: {$ipAddress}\n\n"
        .
        "Your new password is now active and your previous password "
        .
        "can no longer be used.\n\n"
        .
        "If you did not make this change, sign in immediately and "
        .
        "contact LOVEMI support.\n\n"
        .
        "LOVEMI\n"
        .
        "Discover • Connect • Meet";


    try {

        return sendLovemiEmail(
            $email,
            $fullName,
            'LOVEMI - Your Password Was Changed Successfully',
            $html,
            $plainText
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PASSWORD CHANGED EMAIL] '
            .
            $e->getMessage()
        );

        return false;
    }
}


/* ============================================================
   GET STATUS
============================================================ */

if (
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ?? ''
        )
    ) === 'GET'
) {

    $action =
        trim(
            (string)(
                $_GET['action']
                ?? ''
            )
        );


    if (
        $action !== 'status'
    ) {

        resetResponse(
            false,
            'Invalid request.',
            [
                'code' =>
                    'INVALID_ACTION'
            ],
            400
        );

    }


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


    $sessionResetId =
        (int)(
            $_SESSION[
                'lovemi_password_reset_request_id'
            ]
            ?? 0
        );


    $sessionVerified =
        !empty(
            $_SESSION[
                'lovemi_password_reset_link_verified'
            ]
        );


    if (
        !$sessionVerified
        ||
        $sessionResetId <= 0
    ) {

        resetResponse(
            false,
            'Open the verification link sent to your email first.',
            [
                'code' =>
                    'RESET_LINK_NOT_VERIFIED',

                'verified' =>
                    false
            ],
            403
        );

    }


    if (
        $email === ''
        ||
        $token === ''
    ) {

        resetResponse(
            false,
            'The reset request is incomplete.',
            [
                'code' =>
                    'RESET_PARAMETERS_MISSING',

                'verified' =>
                    false
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

        resetResponse(
            false,
            'Invalid email address.',
            [
                'code' =>
                    'INVALID_EMAIL',

                'verified' =>
                    false
            ],
            422
        );

    }


    $tokenHash =
        hash(
            'sha256',
            $token
        );


    try {

        $pdo =
            db();


        $stmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    email,
                    expires_at,
                    used_at,
                    blocked_at,
                    link_verified_at

                FROM password_resets

                WHERE id = :id

                  AND email = :email

                  AND reset_token_hash = :token_hash

                LIMIT 1
                "
            );


        $stmt->execute(
            [

                ':id' =>
                    $sessionResetId,

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
            '[LOVEMI RESET STATUS DB] '
            .
            $e->getMessage()
        );


        resetResponse(
            false,
            'Unable to check the password-reset request.',
            [
                'code' =>
                    'DATABASE_ERROR',

                'verified' =>
                    false
            ],
            500
        );

    }


    if (
        !$reset
    ) {

        resetResponse(
            false,
            'This password-reset request is invalid.',
            [
                'code' =>
                    'RESET_NOT_FOUND',

                'verified' =>
                    false
            ],
            400
        );

    }


    if (
        !empty(
            $reset['used_at']
        )
    ) {

        resetResponse(
            false,
            'This password-reset request has already been used.',
            [
                'code' =>
                    'RESET_USED',

                'verified' =>
                    false
            ],
            400
        );

    }


    if (
        !empty(
            $reset['blocked_at']
        )
    ) {

        resetResponse(
            false,
            'This password-reset request has been blocked.',
            [
                'code' =>
                    'RESET_BLOCKED',

                'verified' =>
                    false
            ],
            400
        );

    }


    if (
        empty(
            $reset['link_verified_at']
        )
    ) {

        resetResponse(
            false,
            'Open the verification link first.',
            [
                'code' =>
                    'RESET_LINK_NOT_VERIFIED',

                'verified' =>
                    false
            ],
            403
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

        resetResponse(
            false,
            'This password-reset request has expired.',
            [
                'code' =>
                    'RESET_EXPIRED',

                'verified' =>
                    false
            ],
            400
        );

    }


    resetResponse(
        true,
        'The reset link has been verified. Enter the 6-digit code and your new password.',
        [
            'code' =>
                'RESET_LINK_VERIFIED',

            'verified' =>
                true
        ]
    );

}


/* ============================================================
   POST METHOD
============================================================ */

if (
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ?? ''
        )
    ) !== 'POST'
) {

    resetResponse(
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
   READ INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)$raw,
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


$email =
    trim(
        (string)(
            $input['email']
            ?? ''
        )
    );


$token =
    trim(
        (string)(
            $input['token']
            ?? ''
        )
    );


$verificationCode =
    trim(
        (string)(
            $input['code']
            ?? ''
        )
    );


$password =
    (string)(
        $input['password']
        ?? ''
    );


$passwordConfirmation =
    (string)(
        $input['password_confirmation']
        ?? ''
    );


/* ============================================================
   BASIC VALIDATION
============================================================ */

if (
    $email === ''
    ||
    $token === ''
    ||
    $verificationCode === ''
    ||
    $password === ''
    ||
    $passwordConfirmation === ''
) {

    resetResponse(
        false,
        'All password reset fields are required.',
        [
            'code' =>
                'MISSING_FIELDS'
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

    resetResponse(
        false,
        'Please enter a valid email address.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


if (
    !preg_match(
        '/^\d{6}$/',
        $verificationCode
    )
) {

    resetResponse(
        false,
        'Please enter the 6-digit verification code from your email.',
        [
            'code' =>
                'INVALID_VERIFICATION_CODE_FORMAT'
        ],
        422
    );

}


if (
    strlen($password) < 8
) {

    resetResponse(
        false,
        'Your new password must contain at least 8 characters.',
        [
            'code' =>
                'PASSWORD_TOO_SHORT'
        ],
        422
    );

}


if (
    $password !== $passwordConfirmation
) {

    resetResponse(
        false,
        'The new passwords do not match.',
        [
            'code' =>
                'PASSWORD_MISMATCH'
        ],
        422
    );

}


/* ============================================================
   SESSION SECURITY
============================================================ */

$sessionResetId =
    (int)(
        $_SESSION[
            'lovemi_password_reset_request_id'
        ]
        ?? 0
    );


$sessionVerified =
    !empty(
        $_SESSION[
            'lovemi_password_reset_link_verified'
        ]
    );


if (
    !$sessionVerified
    ||
    $sessionResetId <= 0
) {

    resetResponse(
        false,
        'You must open the password-reset verification link from your email before entering the verification code.',
        [
            'code' =>
                'RESET_LINK_NOT_VERIFIED'
        ],
        403
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
        '[LOVEMI RESET PASSWORD DB] '
        .
        $e->getMessage()
    );


    resetResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
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
                pr.verification_code_hash,
                pr.attempt_count,
                pr.max_attempts,
                pr.expires_at,
                pr.used_at,
                pr.blocked_at,
                pr.link_verified_at,

                u.full_names,
                u.password_hash

            FROM password_resets pr

            INNER JOIN users u
                ON u.id = pr.user_id

            WHERE pr.id = :id

              AND pr.email = :email

              AND pr.reset_token_hash = :token_hash

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':id' =>
                $sessionResetId,

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
        '[LOVEMI RESET PASSWORD QUERY] '
        .
        $e->getMessage()
    );


    resetResponse(
        false,
        'Unable to load the password-reset request.',
        [
            'code' =>
                'RESET_QUERY_FAILED'
        ],
        500
    );

}


/* ============================================================
   REQUEST VALIDATION
============================================================ */

if (
    !$reset
) {

    resetResponse(
        false,
        'This password-reset request is invalid.',
        [
            'code' =>
                'RESET_NOT_FOUND'
        ],
        400
    );

}


if (
    !empty(
        $reset['used_at']
    )
) {

    resetResponse(
        false,
        'This password-reset request has already been used.',
        [
            'code' =>
                'RESET_USED'
        ],
        400
    );

}


if (
    !empty(
        $reset['blocked_at']
    )
) {

    resetResponse(
        false,
        'This password-reset request has been blocked. Please start again.',
        [
            'code' =>
                'RESET_BLOCKED'
        ],
        400
    );

}


if (
    empty(
        $reset['link_verified_at']
    )
) {

    resetResponse(
        false,
        'Open the password-reset verification link first.',
        [
            'code' =>
                'RESET_LINK_NOT_VERIFIED'
        ],
        403
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

    resetResponse(
        false,
        'This password-reset request has expired. Please request a new one.',
        [
            'code' =>
                'RESET_EXPIRED'
        ],
        400
    );

}


/* ============================================================
   VERIFY CODE
============================================================ */

$codeMatches =
    password_verify(
        $verificationCode,
        (string)$reset['verification_code_hash']
    );


if (
    !$codeMatches
) {

    $newAttemptCount =
        ((int)$reset['attempt_count'])
        +
        1;


    $maxAttempts =
        max(
            1,
            (int)$reset['max_attempts']
        );


    if (
        $newAttemptCount >= $maxAttempts
    ) {

        try {

            $blockStmt =
                $pdo->prepare(
                    "
                    UPDATE password_resets

                    SET

                        attempt_count = :attempt_count,

                        blocked_at =
                            CURRENT_TIMESTAMP

                    WHERE id = :id

                      AND used_at IS NULL
                    "
                );


            $blockStmt->execute(
                [

                    ':attempt_count' =>
                        $newAttemptCount,

                    ':id' =>
                        (int)$reset['id']

                ]
            );

        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI RESET BLOCK] '
                .
                $e->getMessage()
            );

        }


        resetResponse(
            false,
            'The verification code was incorrect too many times. Please start a new password reset request.',
            [
                'code' =>
                    'RESET_ATTEMPTS_EXCEEDED'
            ],
            403
        );

    }


    try {

        $attemptStmt =
            $pdo->prepare(
                "
                UPDATE password_resets

                SET
                    attempt_count = :attempt_count

                WHERE id = :id

                  AND used_at IS NULL
                "
            );


        $attemptStmt->execute(
            [

                ':attempt_count' =>
                    $newAttemptCount,

                ':id' =>
                    (int)$reset['id']

            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI RESET ATTEMPT UPDATE] '
            .
            $e->getMessage()
        );

    }


    $remaining =
        max(
            0,
            $maxAttempts - $newAttemptCount
        );


    resetResponse(
        false,
        'The verification code is incorrect.',
        [
            'code' =>
                'VERIFICATION_CODE_INVALID',

            'attempts_remaining' =>
                $remaining
        ],
        422
    );

}


/* ============================================================
   HASH NEW PASSWORD
============================================================ */

try {

    $newPasswordHash =
        password_hash(
            $password,
            PASSWORD_DEFAULT
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PASSWORD HASH] '
        .
        $e->getMessage()
    );


    resetResponse(
        false,
        'Unable to secure the new password.',
        [
            'code' =>
                'PASSWORD_HASH_FAILED'
        ],
        500
    );

}


if (
    !is_string($newPasswordHash)
    ||
    $newPasswordHash === ''
) {

    resetResponse(
        false,
        'Unable to secure the new password.',
        [
            'code' =>
                'PASSWORD_HASH_FAILED'
        ],
        500
    );

}


/* ============================================================
   CHANGE PASSWORD
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Update password.
     */

    $userStmt =
        $pdo->prepare(
            "
            UPDATE users

            SET

                password_hash = :password_hash,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id = :user_id

              AND is_deleted = 0
            "
        );


    $userStmt->execute(
        [

            ':password_hash' =>
                $newPasswordHash,

            ':user_id' =>
                (int)$reset['user_id']

        ]
    );


    if (
        $userStmt->rowCount() < 1
    ) {

        throw new RuntimeException(
            'The user password could not be updated.'
        );

    }


    /*
     * Mark reset request as completely consumed.
     */

    $resetStmt =
        $pdo->prepare(
            "
            UPDATE password_resets

            SET

                code_verified_at =
                    CURRENT_TIMESTAMP,

                used_at =
                    CURRENT_TIMESTAMP

            WHERE id = :id

              AND used_at IS NULL

              AND blocked_at IS NULL
            "
        );


    $resetStmt->execute(
        [
            ':id' =>
                (int)$reset['id']
        ]
    );


    /*
     * Make sure the request was actually consumed.
     */

    if (
        $resetStmt->rowCount() < 1
    ) {

        throw new RuntimeException(
            'The password-reset request could not be finalized.'
        );

    }


    /*
     * Commit password change first.
     *
     * Email delivery happens AFTER the successful database
     * transaction so a temporary SMTP problem cannot undo a
     * valid password change.
     */

    $pdo->commit();


} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI RESET PASSWORD UPDATE] '
        .
        $e->getMessage()
    );


    resetResponse(
        false,
        'The password could not be changed. Please try again.',
        [
            'code' =>
                'PASSWORD_UPDATE_FAILED'
        ],
        500
    );

}


/* ============================================================
   SEND PASSWORD CHANGED EMAIL
============================================================ */

$emailSent =
    false;


try {

    $emailSent =
        sendPasswordChangedEmail(
            $email,
            (string)$reset['full_names']
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PASSWORD CHANGED EMAIL OUTER] '
        .
        $e->getMessage()
    );

    $emailSent =
        false;
}


/* ============================================================
   CLEAR PASSWORD RESET SESSION
============================================================ */

unset(
    $_SESSION[
        'lovemi_password_reset_request_id'
    ]
);

unset(
    $_SESSION[
        'lovemi_password_reset_link_verified'
    ]
);


/* ============================================================
   FINAL RESPONSE
============================================================ */

if (
    $emailSent
) {

    resetResponse(
        true,
        'Your LOVEMI password has been changed successfully. A confirmation email has been sent to your registered email address.',
        [
            'code' =>
                'PASSWORD_RESET_SUCCESS',

            'email_sent' =>
                true
        ]
    );

}


/*
 * Password has still been successfully changed even if SMTP
 * temporarily failed. The API does not falsely report that
 * the password failed.
 */

resetResponse(
    true,
    'Your LOVEMI password has been changed successfully. However, we could not send the confirmation email at this time.',
    [
        'code' =>
            'PASSWORD_RESET_SUCCESS_EMAIL_FAILED',

        'email_sent' =>
            false
    ]
);