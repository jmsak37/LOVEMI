<?php

/**
 * ============================================================
 * LOVEMI - FORGOT PASSWORD API
 * ============================================================
 *
 * Recovery flow:
 *
 * 1. Country is selected.
 * 2. Phone is normalized using the selected country when
 *    the user provides a local number.
 * 3. ID number is SHA-256 hashed.
 * 4. Account is matched.
 * 5. Previous unused reset requests are invalidated.
 * 6. A secure reset token is generated for the link.
 * 7. A separate 6-digit verification code is generated.
 * 8. Only hashes are stored for the token and code.
 * 9. Email contains:
 *      - verification link
 *      - 6-digit verification code
 * 10. User must open the link before the code can be used.
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
   RESPONSE HELPER
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
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ?? ''
        )
    ) !== 'POST'
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
        (string)$raw,
        true
    );

if (
    !is_array($input)
) {

    $input =
        $_POST;

}


/* ============================================================
   INPUT
============================================================ */

$countryId =
    filter_var(
        $input['country_id'] ?? null,
        FILTER_VALIDATE_INT
    );

$phone =
    trim(
        (string)(
            $input['phone']
            ?? ''
        )
    );

$idNumber =
    trim(
        (string)(
            $input['id_number']
            ?? ''
        )
    );


if (
    !$countryId
) {

    forgotResponse(
        false,
        'Please select your country.',
        [
            'code' =>
                'COUNTRY_REQUIRED'
        ],
        422
    );

}


if (
    $phone === ''
) {

    forgotResponse(
        false,
        'Please enter your phone number.',
        [
            'code' =>
                'PHONE_REQUIRED'
        ],
        422
    );

}


if (
    $idNumber === ''
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
   LOAD COUNTRY
============================================================ */

try {

    $countryStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                name,
                iso2,
                iso3,
                phone_code

            FROM countries

            WHERE id = :id

              AND is_active = 1

            LIMIT 1
            "
        );

    $countryStmt->execute(
        [
            ':id' =>
                $countryId
        ]
    );

    $country =
        $countryStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI FORGOT COUNTRY QUERY] '
        .
        $e->getMessage()
    );

    forgotResponse(
        false,
        'Unable to verify the selected country.',
        [
            'code' =>
                'COUNTRY_QUERY_FAILED'
        ],
        500
    );

}


if (
    !$country
) {

    forgotResponse(
        false,
        'The selected country is not available.',
        [
            'code' =>
                'COUNTRY_INVALID'
        ],
        422
    );

}


/* ============================================================
   PHONE NORMALIZATION
============================================================ */

/**
 * Normalize phone using:
 *
 * - selected country for local numbers
 * - entered international country code when + or 00 is used
 *
 * Examples:
 *
 * Kenya +254:
 *
 * 0791642994
 * +254791642994
 * 254791642994
 * 00 254 791642994
 *
 * all resolve to:
 *
 * +254791642994
 */

function normalizeForgotPhone(
    string $rawPhone,
    string $countryPhoneCode
): string {

    $clean =
        preg_replace(
            '/[^\d+]/',
            '',
            trim($rawPhone)
        );

    if (
        !is_string($clean)
        ||
        $clean === ''
    ) {

        throw new InvalidArgumentException(
            'Phone number is empty.'
        );

    }


    /*
     * Remove accidental multiple plus signs.
     */

    if (
        str_contains(
            substr(
                $clean,
                1
            ),
            '+'
        )
    ) {

        throw new InvalidArgumentException(
            'Invalid phone number.'
        );

    }


    $countryDigits =
        preg_replace(
            '/\D+/',
            '',
            $countryPhoneCode
        );

    if (
        !is_string($countryDigits)
        ||
        $countryDigits === ''
    ) {

        throw new InvalidArgumentException(
            'Selected country does not have a valid phone code.'
        );

    }


    /*
     * Explicit international format:
     *
     * +254791642994
     */

    if (
        str_starts_with(
            $clean,
            '+'
        )
    ) {

        $digits =
            preg_replace(
                '/\D+/',
                '',
                $clean
            );

        return '+' . $digits;

    }


    $digits =
        preg_replace(
            '/\D+/',
            '',
            $clean
        );


    if (
        !is_string($digits)
        ||
        $digits === ''
    ) {

        throw new InvalidArgumentException(
            'Invalid phone number.'
        );

    }


    /*
     * 00 international prefix:
     *
     * 00254791642994
     */

    if (
        str_starts_with(
            $digits,
            '00'
        )
    ) {

        $internationalDigits =
            substr(
                $digits,
                2
            );

        return '+' . $internationalDigits;

    }


    /*
     * International number without +
     *
     * 254791642994
     */

    if (
        str_starts_with(
            $digits,
            $countryDigits
        )
        &&
        strlen($digits)
            >
        strlen($countryDigits)
    ) {

        return '+' . $digits;

    }


    /*
     * Local national format:
     *
     * 0791642994
     *
     * Remove the trunk 0 and prepend country code.
     */

    if (
        str_starts_with(
            $digits,
            '0'
        )
    ) {

        $national =
            ltrim(
                $digits,
                '0'
            );

        return
            '+'
            .
            $countryDigits
            .
            $national;

    }


    /*
     * Number without a leading 0 or country code.
     *
     * Example:
     * 791642994
     *
     * With Kenya selected:
     * +254791642994
     */

    return
        '+'
        .
        $countryDigits
        .
        $digits;

}


try {

    $normalizedPhone =
        normalizeForgotPhone(
            $phone,
            (string)$country['phone_code']
        );

} catch (
    Throwable $e
) {

    forgotResponse(
        false,
        $e->getMessage(),
        [
            'code' =>
                'PHONE_NORMALIZATION_FAILED'
        ],
        422
    );

}


/* ============================================================
   PHONE VALIDATION
============================================================ */

if (
    !preg_match(
        '/^\+\d{7,15}$/',
        $normalizedPhone
    )
) {

    forgotResponse(
        false,
        'Please enter a valid phone number. You may enter it in local or international format.',
        [
            'code' =>
                'PHONE_INVALID'
        ],
        422
    );

}


/* ============================================================
   NORMALIZE ID
============================================================ */

$normalizedId =
    preg_replace(
        '/\s+/',
        '',
        $idNumber
    );

if (
    !is_string($normalizedId)
    ||
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


$idHash =
    hash(
        'sha256',
        $normalizedId
    );


/* ============================================================
   FIND ACCOUNT
============================================================ */

try {

    /*
     * For legacy data, phone_number may contain:
     *
     * 791642994
     * 0791642994
     *
     * while phone_e164 contains:
     *
     * +254791642994
     *
     * We therefore check the canonical E.164 number first,
     * while also checking a few safe local representations.
     */

    $normalizedDigits =
        preg_replace(
            '/\D+/',
            '',
            $normalizedPhone
        );

    $countryDigits =
        preg_replace(
            '/\D+/',
            '',
            (string)$country['phone_code']
        );

    $nationalDigits =
        '';

    if (
        is_string($normalizedDigits)
        &&
        is_string($countryDigits)
        &&
        str_starts_with(
            $normalizedDigits,
            $countryDigits
        )
    ) {

        $nationalDigits =
            substr(
                $normalizedDigits,
                strlen($countryDigits)
            );

    }


    $localWithZero =
        $nationalDigits !== ''
            ? '0' . $nationalDigits
            : '';

    $phoneDigits =
        $normalizedDigits
        ?: '';


    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.email,
                u.phone_number,
                u.phone_e164,
                u.id_number_hash,
                u.account_status,
                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted

            FROM users u

            WHERE

                u.id_number_hash = :id_number_hash

                AND

                (
                    u.phone_e164 = :phone_e164

                    OR u.phone_number = :phone_digits

                    OR u.phone_number = :phone_local_zero

                )

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':id_number_hash' =>
                $idHash,

            ':phone_e164' =>
                $normalizedPhone,

            ':phone_digits' =>
                $phoneDigits,

            ':phone_local_zero' =>
                $localWithZero

        ]
    );


    $user =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

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

if (
    !$user
) {

    forgotResponse(
        false,
        'The supplied account details could not be verified.',
        [
            'code' =>
                'IDENTITY_NOT_MATCHED'
        ]
    );

}


/* ============================================================
   ACCOUNT STATUS
============================================================ */

if (
    (int)$user['is_deleted'] === 1
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
    (int)$user['is_suspended'] === 1
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
    (int)$user['is_active'] !== 1
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
        (string)$user['account_status']
    ) === 'blocked'
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
   EMAIL
============================================================ */

$email =
    trim(
        (string)$user['email']
    );


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    error_log(
        '[LOVEMI FORGOT PASSWORD INVALID EMAIL] User ID '
        .
        (int)$user['id']
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
   TRANSACTION
============================================================ */

$resetId =
    0;

$resetToken =
    '';

$verificationCode =
    '';

$expiresAt =
    '';

try {

    $pdo->beginTransaction();


    /*
     * Invalidate previous unused requests.
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
                (int)$user['id']
        ]
    );


    /*
     * Generate secure reset token.
     */

    $resetToken =
        rtrim(
            strtr(
                base64_encode(
                    random_bytes(48)
                ),
                '+/',
                '-_'
            ),
            '='
        );


    $resetTokenHash =
        hash(
            'sha256',
            $resetToken
        );


    /*
     * Generate separate 6-digit code.
     */

    $verificationCode =
        str_pad(
            (string)random_int(
                0,
                999999
            ),
            6,
            '0',
            STR_PAD_LEFT
        );


    $verificationCodeHash =
        password_hash(
            $verificationCode,
            PASSWORD_DEFAULT
        );


    /*
     * Link and code are valid for 15 minutes.
     */

    $expiresAt =
        date(
            'Y-m-d H:i:s',
            time() + (15 * 60)
        );


    /*
     * Create reset request.
     */

    $insertStmt =
        $pdo->prepare(
            "
            INSERT INTO password_resets
            (
                user_id,
                email,
                phone_e164,
                id_number_hash,
                reset_token_hash,
                verification_code_hash,
                link_verified_at,
                code_verified_at,
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
                :verification_code_hash,
                NULL,
                NULL,
                0,
                3,
                :expires_at
            )
            "
        );


    $insertStmt->execute(
        [

            ':user_id' =>
                (int)$user['id'],

            ':email' =>
                $email,

            ':phone_e164' =>
                $normalizedPhone,

            ':id_number_hash' =>
                $idHash,

            ':reset_token_hash' =>
                $resetTokenHash,

            ':verification_code_hash' =>
                $verificationCodeHash,

            ':expires_at' =>
                $expiresAt

        ]
    );


    $resetId =
        (int)$pdo->lastInsertId();


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
        '[LOVEMI PASSWORD RESET CREATE] '
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
   SAVE SESSION
============================================================ */

$_SESSION[
    'lovemi_password_reset_request_id'
] =
    $resetId;

unset(
    $_SESSION[
        'lovemi_password_reset_link_verified'
    ]
);


/* ============================================================
   BUILD VERIFICATION LINK
============================================================ */

$scheme =
    (
        !empty(
            $_SERVER['HTTPS']
        )
        &&
        $_SERVER['HTTPS'] !== 'off'
    )
        ? 'https'
        : 'http';


$host =
    (string)(
        $_SERVER['HTTP_HOST']
        ?? 'localhost'
    );


$scriptName =
    str_replace(
        '\\',
        '/',
        (string)(
            $_SERVER['SCRIPT_NAME']
            ?? '/LOVEMI/api/auth/forgot-password.php'
        )
    );


/*
 * /LOVEMI/api/auth/forgot-password.php
 *
 * Remove /api/auth/forgot-password.php
 *
 * leaves:
 *
 * /LOVEMI
 */

$basePath =
    preg_replace(
        '#/api/auth/forgot-password\.php$#',
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


$basePath =
    rtrim(
        $basePath,
        '/'
    );


$verifyUrl =
    $scheme
    .
    '://'
    .
    $host
    .
    $basePath
    .
    '/api/auth/verify-reset.php?email='
    .
    rawurlencode(
        $email
    )
    .
    '&token='
    .
    rawurlencode(
        $resetToken
    );


/* ============================================================
   EMAIL HTML
============================================================ */

$safeName =
    htmlspecialchars(
        (string)$user['full_names'],
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$safeEmail =
    htmlspecialchars(
        $email,
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$safeVerifyUrl =
    htmlspecialchars(
        $verifyUrl,
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$safeCode =
    htmlspecialchars(
        $verificationCode,
        ENT_QUOTES |
        ENT_HTML5,
        'UTF-8'
    );


$year =
    date('Y');


$emailHtml = <<<HTML
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width,initial-scale=1.0"
    >

    <title>LOVEMI Password Recovery</title>

</head>

<body
    style="
        margin:0;
        padding:0;
        background:#f7f7fb;
        font-family:Arial,Helvetica,sans-serif;
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
                border:1px solid #e8e8ef;
                border-radius:20px;
                overflow:hidden;
            "
        >

            <div
                style="
                    padding:25px 30px;
                    background:linear-gradient(
                        135deg,
                        #7c3aed,
                        #ec4899
                    );
                    color:#ffffff;
                "
            >

                <div
                    style="
                        font-size:26px;
                        font-weight:800;
                        font-family:Georgia,serif;
                    "
                >
                    LOVEMI
                </div>

                <div
                    style="
                        margin-top:5px;
                        font-size:12px;
                        opacity:.92;
                    "
                >
                    Discover • Connect • Meet
                </div>

            </div>


            <div
                style="
                    padding:30px;
                "
            >

                <div
                    style="
                        display:inline-block;
                        background:#ede9fe;
                        color:#5b21b6;
                        padding:7px 12px;
                        border-radius:999px;
                        font-size:11px;
                        font-weight:bold;
                        margin-bottom:15px;
                    "
                >
                    ACCOUNT SECURITY
                </div>


                <h1
                    style="
                        margin:0 0 14px;
                        font-size:24px;
                        line-height:1.3;
                        color:#18181b;
                    "
                >
                    Password Reset Request
                </h1>


                <p
                    style="
                        margin:0 0 14px;
                        font-size:14px;
                        line-height:1.7;
                    "
                >
                    Hello <strong>{$safeName}</strong>,
                </p>


                <p
                    style="
                        margin:0 0 14px;
                        font-size:14px;
                        line-height:1.7;
                        color:#3f3f46;
                    "
                >
                    A password reset request was made for your
                    LOVEMI account associated with
                    <strong>{$safeEmail}</strong>.
                </p>


                <div
                    style="
                        margin:25px 0;
                        padding:20px;
                        background:#fafafa;
                        border:1px solid #ececf2;
                        border-radius:14px;
                    "
                >

                    <div
                        style="
                            font-size:12px;
                            color:#71717a;
                            margin-bottom:8px;
                            font-weight:bold;
                        "
                    >
                        STEP 1 — VERIFY THE RESET LINK
                    </div>


                    <p
                        style="
                            margin:0 0 16px;
                            font-size:13px;
                            line-height:1.6;
                            color:#3f3f46;
                        "
                    >
                        Open the button below first. LOVEMI will verify
                        that this password-reset request was initiated
                        for your account.
                    </p>


                    <div
                        style="
                            text-align:center;
                        "
                    >

                        <a
                            href="{$safeVerifyUrl}"
                            style="
                                display:inline-block;
                                background:#7c3aed;
                                color:#ffffff;
                                text-decoration:none;
                                padding:13px 22px;
                                border-radius:10px;
                                font-size:13px;
                                font-weight:bold;
                            "
                        >
                            Verify Reset Link
                        </a>

                    </div>

                </div>


                <div
                    style="
                        margin:25px 0;
                        padding:22px;
                        text-align:center;
                        background:#f3e8ff;
                        border-radius:14px;
                    "
                >

                    <div
                        style="
                            font-size:12px;
                            color:#6d28d9;
                            font-weight:bold;
                            margin-bottom:10px;
                        "
                    >
                        STEP 2 — VERIFICATION CODE
                    </div>


                    <div
                        style="
                            font-size:34px;
                            line-height:1;
                            font-weight:800;
                            letter-spacing:9px;
                            color:#5b21b6;
                        "
                    >
                        {$safeCode}
                    </div>


                    <p
                        style="
                            margin:12px 0 0;
                            font-size:12px;
                            color:#6b7280;
                        "
                    >
                        Enter this 6-digit code after the
                        verification link has been opened.
                    </p>

                </div>


                <div
                    style="
                        margin-top:25px;
                        padding-top:20px;
                        border-top:1px solid #ededf2;
                    "
                >

                    <p
                        style="
                            margin:0 0 10px;
                            font-size:12px;
                            line-height:1.7;
                            color:#71717a;
                        "
                    >
                        This password-reset request expires in
                        <strong>15 minutes</strong>.
                    </p>


                    <p
                        style="
                            margin:0;
                            font-size:12px;
                            line-height:1.7;
                            color:#71717a;
                        "
                    >
                        If you did not request a password reset,
                        you can safely ignore this email. Your
                        current password will remain unchanged.
                    </p>

                </div>

            </div>


            <div
                style="
                    padding:20px 30px;
                    background:#fafafa;
                    border-top:1px solid #eeeeF3;
                    text-align:center;
                "
            >

                <div
                    style="
                        font-size:12px;
                        font-weight:bold;
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


/* ============================================================
   EMAIL PLAIN TEXT
============================================================ */

$emailPlain =

    "LOVEMI PASSWORD RESET\n\n"
    .
    "Hello {$user['full_names']},\n\n"
    .
    "A password reset request was made for your LOVEMI account.\n\n"
    .
    "STEP 1 - VERIFY THE RESET LINK\n"
    .
    "{$verifyUrl}\n\n"
    .
    "STEP 2 - VERIFICATION CODE\n"
    .
    "{$verificationCode}\n\n"
    .
    "The link and verification code expire in 15 minutes.\n\n"
    .
    "If you did not request this reset, ignore this email.\n\n"
    .
    "LOVEMI\n"
    .
    "Discover • Connect • Meet";


/* ============================================================
   SEND EMAIL
============================================================ */

try {

    $emailSent =
        sendLovemiEmail(
            $email,
            (string)$user['full_names'],
            'LOVEMI - Password Reset Verification',
            $emailHtml,
            $emailPlain
        );


    /*
     * IMPORTANT:
     *
     * The existing email service returns FALSE when sending
     * fails. Therefore we must explicitly check the result.
     */

    if (
        $emailSent !== true
    ) {

        throw new RuntimeException(
            'LOVEMI email service returned false.'
        );

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI RESET EMAIL] '
        .
        $e->getMessage()
    );


    /*
     * Remove the newly-created request when email delivery failed.
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
        'We could not send the password recovery email. Please try again later.',
        [
            'code' =>
                'RESET_EMAIL_FAILED'
        ],
        503
    );

}


/* ============================================================
   FINAL RESPONSE
============================================================ */

forgotResponse(
    true,
    'Your account details were verified. A verification link and a 6-digit reset code have been sent to your registered email.',
    [
        'expires_in_minutes' =>
            15
    ]
);