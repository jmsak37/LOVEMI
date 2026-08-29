<?php
/**
 * ============================================================
 * LOVEMI - FORGOT PASSWORD API
 * ============================================================
 *
 * User supplies:
 *
 *   phone
 *   id_number
 *
 * The API:
 *
 *   1. Normalizes the phone.
 *   2. Hashes the supplied ID number.
 *   3. Matches both against users.
 *   4. Creates a cryptographically random reset token.
 *   5. Stores only the token hash.
 *   6. Sends the reset link to the user's registered email.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';


/* ============================================================
   HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


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
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function forgotResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    forgotResponse(
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
   JSON INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $raw,
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
   INPUT
============================================================ */

$phone =
    trim(
        (string)
        (
            $input['phone']
            ??
            ''
        )
    );


$idNumber =
    trim(
        (string)
        (
            $input['id_number']
            ??
            ''
        )
    );


if (
    $phone === ''
    ||
    $idNumber === ''
) {

    forgotResponse(
        false,
        'Phone number and ID number are required.',
        [
            'code' =>
                'MISSING_FIELDS'
        ],
        422
    );

}


/* ============================================================
   NORMALIZE PHONE
============================================================ */

/*
 * Keep digits and a possible leading +.
 */

$phone =
    preg_replace(
        '/[^\d+]/',
        '',
        $phone
    );


/*
 * Accept common Kenyan local format too.
 *
 * 0712345678 -> +254712345678
 */

if (
    preg_match(
        '/^0\d{9}$/',
        $phone
    )
) {

    $phone =
        '+254'
        .
        substr(
            $phone,
            1
        );

}


/*
 * If the supplied number begins with +, normalize it.
 */

if (
    !str_starts_with(
        $phone,
        '+'
    )
) {

    /*
     * We cannot safely guess a country for a number without +.
     * The common Kenya local conversion above is supported.
     */

    forgotResponse(
        false,
        'Please enter your phone number with the country code, for example +254712345678.',
        [
            'code' =>
                'PHONE_FORMAT_INVALID'
        ],
        422
    );

}


/* ============================================================
   VALIDATE PHONE
============================================================ */

if (
    !preg_match(
        '/^\+\d{7,15}$/',
        $phone
    )
) {

    forgotResponse(
        false,
        'Please enter a valid phone number.',
        [
            'code' =>
                'PHONE_INVALID'
        ],
        422
    );

}


/* ============================================================
   NORMALIZE ID FOR HASHING
============================================================ */

$normalizedId =
    trim(
        preg_replace(
            '/\s+/',
            '',
            $idNumber
        )
    );


if (
    $normalizedId === ''
) {

    forgotResponse(
        false,
        'Please enter your ID number.',
        [
            'code' =>
                'ID_REQUIRED'
        ],
        422
    );

}


/*
 * Match the SHA-256 ID hash used by LOVEMI.
 */

$idHash =
    hash(
        'sha256',
        $normalizedId
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FORGOT PASSWORD DB] '
        .
        $e->getMessage()
    );


    forgotResponse(
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
   FIND ACCOUNT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                username,
                full_names,
                email,
                phone_number,
                phone_e164,
                id_number_hash,
                account_status,
                email_verified,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE phone_e164 = :phone_e164

              AND id_number_hash = :id_number_hash

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':phone_e164' =>
                $phone,

            ':id_number_hash' =>
                $idHash

        ]
    );


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FORGOT PASSWORD USER QUERY] '
        .
        $e->getMessage()
    );


    forgotResponse(
        false,
        'Unable to verify your account details.',
        [
            'code' =>
                'ACCOUNT_LOOKUP_FAILED'
        ],
        500
    );

}


/* ============================================================
   ACCOUNT NOT FOUND
============================================================ */

/*
 * Do not reveal which identity field failed.
 */

if (
    !$user
) {

    forgotResponse(
        false,
        'The supplied account details could not be verified.',
        [
            'code' =>
                'IDENTITY_NOT_MATCHED'
        ],
        200
    );

}


/* ============================================================
   ACCOUNT STATUS
============================================================ */

if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    forgotResponse(
        false,
        'This account is no longer available.',
        [
            'code' =>
                'ACCOUNT_DELETED'
        ],
        403
    );

}


if (
    (int)
    $user['is_suspended']
    ===
    1
) {

    forgotResponse(
        false,
        'This account is currently suspended. Please contact LOVEMI support.',
        [
            'code' =>
                'ACCOUNT_SUSPENDED'
        ],
        403
    );

}


if (
    (int)
    $user['is_active']
    !==
    1
) {

    forgotResponse(
        false,
        'This account is currently inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );

}


if (
    strtolower(
        (string)
        $user['account_status']
    )
    ===
    'blocked'
) {

    forgotResponse(
        false,
        'This account cannot use password recovery.',
        [
            'code' =>
                'ACCOUNT_BLOCKED'
        ],
        403
    );

}


/* ============================================================
   EMAIL VALIDATION
============================================================ */

$email =
    trim(
        (string)
        $user['email']
    );


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    error_log(
        '[LOVEMI FORGOT PASSWORD NO VALID EMAIL] User ID '
        .
        (int)
        $user['id']
    );


    forgotResponse(
        false,
        'This account does not have a valid recovery email. Please contact LOVEMI support.',
        [
            'code' =>
                'RECOVERY_EMAIL_INVALID'
        ],
        409
    );

}


/* ============================================================
   RATE / ACTIVE TOKEN CONTROL
============================================================ */

try {

    /*
     * Invalidate previous unused reset tokens for this user.
     */

    $invalidateStmt =
        $pdo->prepare(
            "
            UPDATE password_resets

            SET
                used_at =
                    COALESCE(
                        used_at,
                        CURRENT_TIMESTAMP
                    )

            WHERE user_id = :user_id

              AND used_at IS NULL

              AND blocked_at IS NULL
            "
        );


    $invalidateStmt->execute(
        [
            ':user_id' =>
                (int)
                $user['id']
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PASSWORD RESET INVALIDATE] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   CREATE TOKEN
============================================================ */

try {

    $resetToken =
        rtrim(
            strtr(
                base64_encode(
                    random_bytes(
                        48
                    )
                ),
                '+/',
                '-_'
            ),
            '='
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI RESET TOKEN] '
        .
        $e->getMessage()
    );


    forgotResponse(
        false,
        'Unable to create a secure reset request.',
        [
            'code' =>
                'TOKEN_GENERATION_FAILED'
        ],
        500
    );

}


$resetTokenHash =
    hash(
        'sha256',
        $resetToken
    );


/*
 * 15-minute validity.
 */

$expiresAt =
    date(
        'Y-m-d H:i:s',
        time()
        +
        (15 * 60)
    );


/* ============================================================
   INSERT RESET REQUEST
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO password_resets
            (
                user_id,
                email,
                phone_e164,
                id_number_hash,
                reset_token_hash,
                attempt_count,
                max_attempts,
                expires_at
            )
            VALUES
            (
                :user_id,
                :email,
                :phone_e164,
                :id_number_hash,
                :reset_token_hash,
                0,
                3,
                :expires_at
            )
            "
        );


    $stmt->execute(
        [

            ':user_id' =>
                (int)
                $user['id'],

            ':email' =>
                $email,

            ':phone_e164' =>
                $phone,

            ':id_number_hash' =>
                $idHash,

            ':reset_token_hash' =>
                $resetTokenHash,

            ':expires_at' =>
                $expiresAt

        ]
    );


    $resetId =
        (int)
        $pdo->lastInsertId();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI RESET INSERT] '
        .
        $e->getMessage()
    );


    forgotResponse(
        false,
        'Unable to create the password reset request.',
        [
            'code' =>
                'RESET_REQUEST_FAILED'
        ],
        500
    );

}


/* ============================================================
   SAVE SESSION INFORMATION
============================================================ */

$_SESSION[
    'lovemi_password_reset_request_id'
] =
    $resetId;


/* ============================================================
   BUILD RESET URL
============================================================ */

/*
 * Use the current site host/path.
 *
 * This works under XAMPP localhost as well as deployment.
 */

$scheme =
    (
        !empty(
            $_SERVER['HTTPS']
        )
        &&
        $_SERVER['HTTPS'] !== 'off'
    )
        ?
        'https'
        :
        'http';


$host =
    $_SERVER['HTTP_HOST']
    ??
    'localhost';


$basePath =
    rtrim(
        str_replace(
            '\\',
            '/',
            dirname(
                dirname(
                    dirname(
                        $_SERVER['SCRIPT_NAME']
                    )
                )
            )
        ),
        '/'
    );


$resetUrl =
    $scheme
    .
    '://'
    .
    $host
    .
    $basePath
    .
    '/reset-password.html?email='
    .
    urlencode(
        $email
    )
    .
    '&token='
    .
    urlencode(
        $resetToken
    );


/* ============================================================
   EMAIL
============================================================ */

$safeName =
    htmlspecialchars(
        (string)
        $user['full_names'],
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$safeResetUrl =
    htmlspecialchars(
        $resetUrl,
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$emailHtml = <<<HTML
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,initial-scale=1.0"
    >

</head>

<body
    style="
        margin:0;
        padding:0;
        background:#f7f7fb;
        font-family:Arial,sans-serif;
        color:#18181b;
    "
>

    <div
        style="
            max-width:620px;
            margin:35px auto;
            padding:20px;
        "
    >

        <div
            style="
                background:#fff;
                border:1px solid #e8e8ef;
                border-radius:18px;
                padding:30px;
            "
        >

            <h1
                style="
                    margin:0 0 20px;
                    color:#7c3aed;
                "
            >
                LOVEMI
            </h1>

            <h2
                style="
                    margin:0 0 15px;
                "
            >
                Password Reset Request
            </h2>

            <p
                style="
                    line-height:1.7;
                "
            >
                Hello {$safeName},
            </p>

            <p
                style="
                    line-height:1.7;
                "
            >
                A password reset request was made for your
                LOVEMI account.
            </p>

            <p
                style="
                    line-height:1.7;
                "
            >
                Click the button below to create a new password.
                The link expires in 15 minutes.
            </p>

            <p
                style="
                    text-align:center;
                    margin:28px 0;
                "
            >

                <a
                    href="{$safeResetUrl}"
                    style="
                        display:inline-block;
                        background:#7c3aed;
                        color:#fff;
                        text-decoration:none;
                        padding:13px 22px;
                        border-radius:10px;
                        font-weight:bold;
                    "
                >
                    Reset My Password
                </a>

            </p>

            <p
                style="
                    font-size:12px;
                    color:#71717a;
                    line-height:1.7;
                "
            >
                If you did not request this reset, you can ignore
                this email. Your current password will remain unchanged.
            </p>

        </div>

        <p
            style="
                text-align:center;
                color:#a1a1aa;
                font-size:11px;
                margin-top:18px;
            "
        >
            © {date('Y')} LOVEMI
        </p>

    </div>

</body>

</html>
HTML;


/* ============================================================
   SEND EMAIL
============================================================ */

try {

    $emailService =
        lovemiEmailService();


    $emailSent =
        $emailService->send(
            $email,
            'LOVEMI Password Reset',
            $emailHtml,
            'Use the password reset link sent in this email. The link expires in 15 minutes.'
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI RESET EMAIL] '
        .
        $e->getMessage()
    );


    /*
     * Remove the newly-created request if email delivery failed,
     * so the user is not left with a dead token.
     */

    try {

        $deleteStmt =
            $pdo->prepare(
                "
                DELETE FROM password_resets

                WHERE id = :id

                LIMIT 1
                "
            );


        $deleteStmt->execute(
            [
                ':id' =>
                    $resetId
            ]
        );

    } catch (
        Throwable $deleteError
    ) {

        error_log(
            '[LOVEMI RESET CLEANUP] '
            .
            $deleteError->getMessage()
        );

    }


    forgotResponse(
        false,
        'We could not send the password reset email. Please try again later.',
        [
            'code' =>
                'RESET_EMAIL_FAILED'
        ],
        503
    );

}


/* ============================================================
   RESPONSE
============================================================ */

/*
 * Do not return the reset token to the browser.
 */

forgotResponse(
    true,
    'Your account details were verified. A secure password reset link has been sent to your registered email.',
    [
        'expires_in_minutes' =>
            15
    ]
);