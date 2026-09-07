<?php

declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI - SECURE ACCOUNT DELETION API
 * ============================================================
 *
 * ACTIONS
 *
 * request
 *     User enters DELETE.
 *     Server creates:
 *         - 6 digit email verification code
 *         - secure email verification token
 *     Server sends both by email.
 *
 * verify_link
 *     User opens the secure verification link.
 *
 * verify_email
 *     User enters the 6 digit email code.
 *
 * verify_2fa
 *     User enters the current Google Authenticator code.
 *
 * finalize
 *     Server checks ALL factors again and soft deletes account.
 *
 * SECURITY
 *
 *     Email link required
 *     Email code required
 *     Google Authenticator 2FA required
 *     Verification expires
 *     Incorrect attempts limited
 *     Previous requests invalidated
 *     Database is checked again before deletion
 *
 * ============================================================
 */


/* ============================================================
   LOAD APPLICATION FILES
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


require_once
    __DIR__
    . '/../../config/app.php';


require_once
    __DIR__
    . '/../../services/email/email-service.php';


/* ============================================================
   GOOGLE AUTHENTICATOR
============================================================ */

$googleAutoload =
    __DIR__
    . '/../auth/vendor/autoload.php';


if (
    !is_file(
        $googleAutoload
    )
) {

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    http_response_code(
        500
    );

    echo json_encode(
        [
            'success' => false,

            'message' =>
                'Google Authenticator library is not installed.',

            'code' =>
                '2FA_LIBRARY_MISSING'
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


require_once $googleAutoload;


use Sonata\GoogleAuthenticator\GoogleAuthenticator;


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
   SESSION
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_set_cookie_params(
        [
            'lifetime' =>
                0,

            'path' =>
                '/',

            'secure' =>
                $isHttps,

            'httponly' =>
                true,

            'samesite' =>
                'Lax'
        ]
    );


    session_start();

}


/* ============================================================
   RESPONSE HELPER
============================================================ */

function deleteAccountResponse(
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
        JSON_UNESCAPED_UNICODE
        |
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

    deleteAccountResponse(
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
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$action =
    strtolower(
        trim(
            (string)
            (
                $input['action']
                ??
                ''
            )
        )
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
        '[LOVEMI DELETE DB CONNECTION] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
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
   SELF-HEALING DATABASE TABLE
============================================================ */

try {

    /*
     * The previous version depended on migration 024.
     *
     * This API now makes the deletion verification table
     * automatically when it does not exist.
     */

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS account_deletion_verifications (

            id
                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            user_id
                BIGINT UNSIGNED NOT NULL,

            code_hash
                CHAR(64) NOT NULL,

            link_token_hash
                CHAR(64) NOT NULL,

            code_expires_at
                DATETIME NOT NULL,

            link_expires_at
                DATETIME NOT NULL,

            code_attempts
                INT UNSIGNED NOT NULL DEFAULT 0,

            link_attempts
                INT UNSIGNED NOT NULL DEFAULT 0,

            link_verified
                TINYINT(1) NOT NULL DEFAULT 0,

            email_verified
                TINYINT(1) NOT NULL DEFAULT 0,

            two_factor_verified
                TINYINT(1) NOT NULL DEFAULT 0,

            created_at
                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            updated_at
                DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            used_at
                DATETIME DEFAULT NULL,

            PRIMARY KEY (id),

            KEY idx_account_delete_user
                (user_id),

            KEY idx_account_delete_link
                (link_token_hash)

        ) ENGINE=InnoDB
          DEFAULT CHARSET=utf8mb4
          COLLATE=utf8mb4_unicode_ci
        "
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE TABLE CREATE] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
        false,
        'Unable to prepare the account deletion verification service.',
        [
            'code' =>
                'VERIFICATION_TABLE_ERROR'
        ],
        500
    );

}


/* ============================================================
   AUTHENTICATED USER
============================================================ */

function authenticatedUserId(): int
{

    return isset(
        $_SESSION[
            'lovemi_user_id'
        ]
    )
        ?
        (int)
        $_SESSION[
            'lovemi_user_id'
        ]
        :
        0;

}


/* ============================================================
   DELETION SESSION USER
============================================================ */

function deletionUserId(): int
{

    $authenticated =
        authenticatedUserId();


    if (
        $authenticated > 0
    ) {

        return $authenticated;

    }


    return isset(
        $_SESSION[
            'lovemi_delete_user_id'
        ]
    )
        ?
        (int)
        $_SESSION[
            'lovemi_delete_user_id'
        ]
        :
        0;

}


/* ============================================================
   RANDOM EMAIL CODE
============================================================ */

function generateDeletionCode(): string
{

    return str_pad(
        (string)
        random_int(
            0,
            999999
        ),
        6,
        '0',
        STR_PAD_LEFT
    );

}


/* ============================================================
   RANDOM SECURE TOKEN
============================================================ */

function generateDeletionToken(): string
{

    return bin2hex(
        random_bytes(
            32
        )
    );

}


/* ============================================================
   SITE ROOT URL
============================================================ */

function lovemiRootUrl(): string
{

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
        $_SERVER[
            'HTTP_HOST'
        ]
        ??
        'localhost';


    $scriptName =
        $_SERVER[
            'SCRIPT_NAME'
        ]
        ??
        '/LOVEMI/api/users/delete-account.php';


    /*
     * SCRIPT:
     *
     * /LOVEMI/api/users/delete-account.php
     *
     * dirname #1:
     * /LOVEMI/api/users
     *
     * dirname #2:
     * /LOVEMI/api
     *
     * dirname #3:
     * /LOVEMI
     */

    $root =
        dirname(
            dirname(
                dirname(
                    $scriptName
                )
            )
        );


    $root =
        str_replace(
            '\\',
            '/',
            $root
        );


    $root =
        rtrim(
            $root,
            '/'
        );


    return
        $scheme
        .
        '://'
        .
        $host
        .
        $root;

}


/* ============================================================
   EMAIL HTML
============================================================ */

function buildDeletionEmail(
    string $fullName,
    string $code,
    string $link
): string
{

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


    $safeLink =
        htmlspecialchars(
            $link,
            ENT_QUOTES,
            'UTF-8'
        );


    return <<<HTML
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <title>
        LOVEMI Account Deletion Verification
    </title>

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
        width:100%;
        padding:30px 10px;
    "
>

    <div
        style="
            max-width:600px;
            margin:0 auto;
            background:#ffffff;
            border-radius:18px;
            padding:32px;
            box-shadow:0 12px 35px rgba(0,0,0,.08);
        "
    >

        <h1
            style="
                margin:0 0 20px;
                color:#6d28d9;
            "
        >
            LOVEMI
        </h1>


        <p>
            Hello {$safeName},
        </p>


        <p>
            A request was made to delete your LOVEMI account.
        </p>


        <p>
            For your protection, LOVEMI requires the following
            verification steps before your account can be deleted.
        </p>


        <h3>
            Step 1 — Verify the request
        </h3>


        <p>
            Click the secure verification button below.
        </p>


        <p>

            <a
                href="{$safeLink}"
                style="
                    display:inline-block;
                    padding:13px 20px;
                    background:#7c3aed;
                    color:#ffffff;
                    text-decoration:none;
                    border-radius:10px;
                    font-weight:bold;
                "
            >
                Verify Account Deletion
            </a>

        </p>


        <h3>
            Step 2 — Enter the email code
        </h3>


        <p>
            Enter this six-digit code on the LOVEMI settings page:
        </p>


        <div
            style="
                text-align:center;
                margin:25px 0;
                padding:20px;
                border-radius:14px;
                background:#f3e8ff;
                color:#6d28d9;
                font-size:30px;
                font-weight:bold;
                letter-spacing:8px;
            "
        >
            {$safeCode}
        </div>


        <p>
            The email code expires in 10 minutes.
        </p>


        <h3>
            Step 3 — Google Authenticator
        </h3>


        <p>
            After the email verification succeeds, LOVEMI will
            request your current six-digit Google Authenticator code.
        </p>


        <p
            style="
                color:#991b1b;
                font-weight:bold;
            "
        >
            If you did not request account deletion, do not continue.
            Secure your account immediately.
        </p>


        <p
            style="
                margin-top:28px;
                color:#777777;
            "
        >
            LOVEMI<br>
            Discover • Connect • Meet
        </p>

    </div>

</div>

</body>

</html>
HTML;

}


/* ============================================================
   ACTION: REQUEST
============================================================ */

if (
    $action ===
    'request'
) {

    $userId =
        authenticatedUserId();


    if (
        $userId <= 0
    ) {

        deleteAccountResponse(
            false,
            'Please log in first.',
            [
                'code' =>
                    'AUTHENTICATION_REQUIRED'
            ],
            401
        );

    }


    $confirmation =
        strtoupper(
            trim(
                (string)
                (
                    $input[
                        'confirmation'
                    ]
                    ??
                    ''
                )
            )
        );


    if (
        $confirmation !==
        'DELETE'
    ) {

        deleteAccountResponse(
            false,
            'Type DELETE exactly to continue.',
            [
                'code' =>
                    'CONFIRMATION_REQUIRED'
            ],
            422
        );

    }


    /* ========================================================
       LOAD ACCOUNT
    ======================================================== */

    try {

        $stmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    username,
                    full_names,
                    email,
                    email_verified,
                    two_factor_enabled,
                    is_active,
                    is_suspended,
                    is_deleted,
                    account_status

                FROM users

                WHERE id =
                    :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
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
            '[LOVEMI DELETE USER LOOKUP] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to load your account.',
            [
                'code' =>
                    'USER_LOOKUP_FAILED'
            ],
            500
        );

    }


    if (!$user) {

        deleteAccountResponse(
            false,
            'Your account could not be found.',
            [
                'code' =>
                    'USER_NOT_FOUND'
            ],
            404
        );

    }


    if (
        (int)$user[
            'is_deleted'
        ]
        ===
        1
    ) {

        deleteAccountResponse(
            false,
            'Your account has already been deleted.',
            [
                'code' =>
                    'ACCOUNT_DELETED'
            ],
            403
        );

    }


    if (
        (int)$user[
            'is_active'
        ]
        !==
        1
        ||
        (int)$user[
            'is_suspended'
        ]
        ===
        1
    ) {

        deleteAccountResponse(
            false,
            'Your account is currently unavailable.',
            [
                'code' =>
                    'ACCOUNT_UNAVAILABLE'
            ],
            403
        );

    }


    if (
        (int)$user[
            'email_verified'
        ]
        !==
        1
    ) {

        deleteAccountResponse(
            false,
            'Your email address must be verified before account deletion.',
            [
                'code' =>
                    'EMAIL_NOT_VERIFIED'
            ],
            403
        );

    }


    if (
        (int)$user[
            'two_factor_enabled'
        ]
        !==
        1
    ) {

        deleteAccountResponse(
            false,
            'Google Authenticator 2FA must be enabled before account deletion.',
            [
                'code' =>
                    '2FA_REQUIRED'
            ],
            403
        );

    }


    /* ========================================================
       GENERATE FACTORS
    ======================================================== */

    $emailCode =
        generateDeletionCode();


    $linkToken =
        generateDeletionToken();


    $codeHash =
        hash(
            'sha256',
            $emailCode
        );


    $linkTokenHash =
        hash(
            'sha256',
            $linkToken
        );


    $codeExpiresAt =
        date(
            'Y-m-d H:i:s',
            time()
            +
            (10 * 60)
        );


    $linkExpiresAt =
        date(
            'Y-m-d H:i:s',
            time()
            +
            (15 * 60)
        );


    /* ========================================================
       INVALIDATE OLD REQUESTS
    ======================================================== */

    try {

        $invalidateStmt =
            $pdo->prepare(
                "
                UPDATE
                    account_deletion_verifications

                SET
                    used_at =
                        CURRENT_TIMESTAMP,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE user_id =
                    :user_id

                  AND used_at IS NULL
                "
            );


        $invalidateStmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE INVALIDATE OLD] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to prepare a new deletion verification request.',
            [
                'code' =>
                    'OLD_VERIFICATION_CLEANUP_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       CREATE NEW VERIFICATION
    ======================================================== */

    try {

        $insertStmt =
            $pdo->prepare(
                "
                INSERT INTO
                    account_deletion_verifications
                (

                    user_id,

                    code_hash,

                    link_token_hash,

                    code_expires_at,

                    link_expires_at,

                    code_attempts,

                    link_attempts,

                    link_verified,

                    email_verified,

                    two_factor_verified

                )

                VALUES
                (

                    :user_id,

                    :code_hash,

                    :link_token_hash,

                    :code_expires_at,

                    :link_expires_at,

                    0,

                    0,

                    0,

                    0,

                    0

                )
                "
            );


        $insertStmt->execute(
            [
                ':user_id' =>
                    $userId,

                ':code_hash' =>
                    $codeHash,

                ':link_token_hash' =>
                    $linkTokenHash,

                ':code_expires_at' =>
                    $codeExpiresAt,

                ':link_expires_at' =>
                    $linkExpiresAt
            ]
        );


        $verificationId =
            (int)
            $pdo->lastInsertId();


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE INSERT ERROR] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to create the deletion verification request.',
            [
                'code' =>
                    'VERIFICATION_INSERT_FAILED'
            ],
            500
        );

    }


    if (
        $verificationId <= 0
    ) {

        deleteAccountResponse(
            false,
            'Unable to create the deletion verification request.',
            [
                'code' =>
                    'VERIFICATION_ID_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       SAVE SESSION STATE
    ======================================================== */

    $_SESSION[
        'lovemi_delete_user_id'
    ] =
        $userId;


    $_SESSION[
        'lovemi_delete_verification_id'
    ] =
        $verificationId;


    $_SESSION[
        'lovemi_delete_link_verified'
    ] =
        false;


    $_SESSION[
        'lovemi_delete_email_verified'
    ] =
        false;


    $_SESSION[
        'lovemi_delete_2fa_verified'
    ] =
        false;


    /* ========================================================
       CREATE LINK
    ======================================================== */

    $verificationLink =
        lovemiRootUrl()
        .
        '/settings.html?delete_verify='
        .
        rawurlencode(
            $linkToken
        );


    /* ========================================================
       RECIPIENT NAME
    ======================================================== */

    $recipientName =
        trim(
            (string)
            (
                $user['full_names']
                ??
                ''
            )
        );


    if (
        $recipientName === ''
    ) {

        $recipientName =
            trim(
                (string)
                (
                    $user['username']
                    ??
                    'LOVEMI Member'
                )
            );

    }


    /* ========================================================
       BUILD EMAIL
    ======================================================== */

    $html =
        buildDeletionEmail(
            $recipientName,
            $emailCode,
            $verificationLink
        );


    $plain =
        "LOVEMI Account Deletion Verification\n\n"
        .
        "Hello {$recipientName},\n\n"
        .
        "A request was made to delete your LOVEMI account.\n\n"
        .
        "Verification link:\n"
        .
        $verificationLink
        .
        "\n\n"
        .
        "Email verification code: "
        .
        $emailCode
        .
        "\n\n"
        .
        "The email code expires in 10 minutes.\n"
        .
        "The verification link expires in 15 minutes.\n\n"
        .
        "After email verification, Google Authenticator 2FA is required.";

    
    /* ========================================================
       SEND EMAIL
    ======================================================== */

    try {

        $sent =
            sendLovemiEmail(
                (string)
                $user['email'],

                $recipientName,

                'LOVEMI Account Deletion Verification',

                $html,

                $plain
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE EMAIL EXCEPTION] '
            .
            $e->getMessage()
        );


        $sent =
            false;

    }


    if (!$sent) {

        try {

            $cleanup =
                $pdo->prepare(
                    "
                    UPDATE
                        account_deletion_verifications

                    SET
                        used_at =
                            CURRENT_TIMESTAMP,

                        updated_at =
                            CURRENT_TIMESTAMP

                    WHERE id =
                        :id

                    LIMIT 1
                    "
                );


            $cleanup->execute(
                [
                    ':id' =>
                        $verificationId
                ]
            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI DELETE EMAIL CLEANUP] '
                .
                $e->getMessage()
            );

        }


        unset(
            $_SESSION[
                'lovemi_delete_user_id'
            ],

            $_SESSION[
                'lovemi_delete_verification_id'
            ],

            $_SESSION[
                'lovemi_delete_link_verified'
            ],

            $_SESSION[
                'lovemi_delete_email_verified'
            ],

            $_SESSION[
                'lovemi_delete_2fa_verified'
            ]
        );


        deleteAccountResponse(
            false,
            'The verification request was created, but the email could not be sent. Your account has NOT been deleted.',
            [
                'code' =>
                    'EMAIL_SEND_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       SUCCESS
    ======================================================== */

    deleteAccountResponse(
        true,
        'A deletion verification link and six-digit code have been sent to your email.',
        [

            'verification_id' =>
                $verificationId,

            'code_expires_in' =>
                600,

            'link_expires_in' =>
                900

        ]
    );

}


/* ============================================================
   PENDING USER
============================================================ */

$deleteUserId =
    deletionUserId();


if (
    $deleteUserId <= 0
) {

    deleteAccountResponse(
        false,
        'Your deletion verification session has expired. Please start again.',
        [
            'code' =>
                'DELETE_SESSION_EXPIRED'
        ],
        401
    );

}


/* ============================================================
   VERIFICATION ID
============================================================ */

$verificationId =
    isset(
        $_SESSION[
            'lovemi_delete_verification_id'
        ]
    )
        ?
        (int)
        $_SESSION[
            'lovemi_delete_verification_id'
        ]
        :
        0;


/* ============================================================
   LOAD VERIFICATION
============================================================ */

try {

    if (
        $verificationId > 0
    ) {

        $verificationStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    user_id,
                    code_hash,
                    link_token_hash,
                    code_expires_at,
                    link_expires_at,
                    code_attempts,
                    link_attempts,
                    link_verified,
                    email_verified,
                    two_factor_verified,
                    used_at

                FROM
                    account_deletion_verifications

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $verificationStmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


    } else {

        $verificationStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    user_id,
                    code_hash,
                    link_token_hash,
                    code_expires_at,
                    link_expires_at,
                    code_attempts,
                    link_attempts,
                    link_verified,
                    email_verified,
                    two_factor_verified,
                    used_at

                FROM
                    account_deletion_verifications

                WHERE user_id =
                    :user_id

                  AND used_at IS NULL

                ORDER BY
                    id DESC

                LIMIT 1
                "
            );


        $verificationStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );

    }


    $verification =
        $verificationStmt->fetch(
            PDO::FETCH_ASSOC
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE VERIFICATION LOAD] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
        false,
        'Unable to load your deletion verification request.',
        [
            'code' =>
                'VERIFICATION_LOOKUP_FAILED'
        ],
        500
    );

}


if (
    !$verification
) {

    deleteAccountResponse(
        false,
        'No active deletion verification request exists. Please start again.',
        [
            'code' =>
                'VERIFICATION_NOT_FOUND'
        ],
        404
    );

}


$verificationId =
    (int)
    $verification[
        'id'
    ];


/* ============================================================
   ACTION: VERIFY LINK
============================================================ */

if (
    $action ===
    'verify_link'
) {

    $token =
        trim(
            (string)
            (
                $input[
                    'token'
                ]
                ??
                ''
            )
        );


    if (
        !preg_match(
            '/^[a-f0-9]{64}$/',
            $token
        )
    ) {

        deleteAccountResponse(
            false,
            'The verification link is invalid.',
            [
                'code' =>
                    'INVALID_LINK'
            ],
            422
        );

    }


    if (
        $verification[
            'used_at'
        ]
        !==
        null
    ) {

        deleteAccountResponse(
            false,
            'This verification link is no longer active.',
            [
                'code' =>
                    'LINK_ALREADY_USED'
            ],
            410
        );

    }


    if (
        strtotime(
            (string)
            $verification[
                'link_expires_at'
            ]
        )
        <
        time()
    ) {

        deleteAccountResponse(
            false,
            'The verification link has expired. Start a new deletion request.',
            [
                'code' =>
                    'LINK_EXPIRED'
            ],
            410
        );

    }


    $incomingHash =
        hash(
            'sha256',
            $token
        );


    $storedHash =
        (string)
        $verification[
            'link_token_hash'
        ];


    if (
        $storedHash === ''
        ||
        !hash_equals(
            $storedHash,
            $incomingHash
        )
    ) {

        try {

            $attemptStmt =
                $pdo->prepare(
                    "
                    UPDATE
                        account_deletion_verifications

                    SET
                        link_attempts =
                            link_attempts + 1

                    WHERE id =
                        :id

                    LIMIT 1
                    "
                );


            $attemptStmt->execute(
                [
                    ':id' =>
                        $verificationId
                ]
            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI DELETE LINK ATTEMPT] '
                .
                $e->getMessage()
            );

        }


        deleteAccountResponse(
            false,
            'The verification link is invalid.',
            [
                'code' =>
                    'INVALID_LINK'
            ],
            422
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                UPDATE
                    account_deletion_verifications

                SET
                    link_verified =
                        1,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE LINK SAVE] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to save the link verification.',
            [
                'code' =>
                    'LINK_SAVE_FAILED'
            ],
            500
        );

    }


    $_SESSION[
        'lovemi_delete_link_verified'
    ] =
        true;


    deleteAccountResponse(
        true,
        'Your deletion verification link has been accepted. Enter the six-digit email code.',
        [
            'link_verified' =>
                true
        ]
    );

}


/* ============================================================
   ACTION: VERIFY EMAIL
============================================================ */

if (
    $action ===
    'verify_email'
) {

    if (
        !(
            $_SESSION[
                'lovemi_delete_link_verified'
            ]
            ??
            false
        )
    ) {

        deleteAccountResponse(
            false,
            'Please open the verification link in your email first.',
            [
                'code' =>
                    'LINK_VERIFICATION_REQUIRED'
            ],
            403
        );

    }


    $code =
        preg_replace(
            '/[^0-9]/',
            '',
            (string)
            (
                $input[
                    'code'
                ]
                ??
                ''
            )
        );


    if (
        !preg_match(
            '/^\d{6}$/',
            $code
        )
    ) {

        deleteAccountResponse(
            false,
            'Enter the six-digit email verification code.',
            [
                'code' =>
                    'INVALID_EMAIL_CODE_FORMAT'
            ],
            422
        );

    }


    if (
        strtotime(
            (string)
            $verification[
                'code_expires_at'
            ]
        )
        <
        time()
    ) {

        deleteAccountResponse(
            false,
            'The email verification code has expired. Start a new deletion request.',
            [
                'code' =>
                    'EMAIL_CODE_EXPIRED'
            ],
            410
        );

    }


    $attempts =
        (int)
        $verification[
            'code_attempts'
        ];


    if (
        $attempts >= 5
    ) {

        deleteAccountResponse(
            false,
            'Too many incorrect email-code attempts. Start a new deletion request.',
            [
                'code' =>
                    'TOO_MANY_EMAIL_ATTEMPTS'
            ],
            429
        );

    }


    $incomingHash =
        hash(
            'sha256',
            $code
        );


    $storedHash =
        (string)
        $verification[
            'code_hash'
        ];


    if (
        $storedHash === ''
        ||
        !hash_equals(
            $storedHash,
            $incomingHash
        )
    ) {

        try {

            $attemptStmt =
                $pdo->prepare(
                    "
                    UPDATE
                        account_deletion_verifications

                    SET
                        code_attempts =
                            code_attempts + 1

                    WHERE id =
                        :id

                    LIMIT 1
                    "
                );


            $attemptStmt->execute(
                [
                    ':id' =>
                        $verificationId
                ]
            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI DELETE EMAIL ATTEMPT] '
                .
                $e->getMessage()
            );

        }


        $remaining =
            max(
                0,
                4 - $attempts
            );


        deleteAccountResponse(
            false,
            "The email verification code is incorrect. {$remaining} attempt(s) remaining.",
            [
                'code' =>
                    'INVALID_EMAIL_CODE',

                'remaining_attempts' =>
                    $remaining
            ],
            422
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                UPDATE
                    account_deletion_verifications

                SET
                    email_verified =
                        1,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE EMAIL VERIFY SAVE] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to save the email verification.',
            [
                'code' =>
                    'EMAIL_VERIFY_SAVE_FAILED'
            ],
            500
        );

    }


    $_SESSION[
        'lovemi_delete_email_verified'
    ] =
        true;


    deleteAccountResponse(
        true,
        'Email verification was successful. Enter your Google Authenticator 2FA code.',
        [
            'email_verified' =>
                true
        ]
    );

}


/* ============================================================
   ACTION: VERIFY 2FA
============================================================ */

if (
    $action ===
    'verify_2fa'
) {

    if (
        !(
            $_SESSION[
                'lovemi_delete_link_verified'
            ]
            ??
            false
        )
        ||
        !(
            $_SESSION[
                'lovemi_delete_email_verified'
            ]
            ??
            false
        )
    ) {

        deleteAccountResponse(
            false,
            'Complete the email verification steps first.',
            [
                'code' =>
                    'EMAIL_VERIFICATION_REQUIRED'
            ],
            403
        );

    }


    $code =
        preg_replace(
            '/[^0-9]/',
            '',
            (string)
            (
                $input[
                    'code'
                ]
                ??
                ''
            )
        );


    if (
        !preg_match(
            '/^\d{6}$/',
            $code
        )
    ) {

        deleteAccountResponse(
            false,
            'Enter the six-digit Google Authenticator code.',
            [
                'code' =>
                    'INVALID_2FA_CODE_FORMAT'
            ],
            422
        );

    }


    /* ========================================================
       LOAD USER 2FA SECRET
    ======================================================== */

    try {

        $userStmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    email_verified,

                    two_factor_enabled,

                    two_factor_secret_encrypted,

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
                    $deleteUserId
            ]
        );


        $user =
            $userStmt->fetch(
                PDO::FETCH_ASSOC
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE 2FA USER] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to load your account security information.',
            [
                'code' =>
                    '2FA_USER_LOOKUP_FAILED'
            ],
            500
        );

    }


    if (!$user) {

        deleteAccountResponse(
            false,
            'Your account could not be found.',
            [
                'code' =>
                    'USER_NOT_FOUND'
            ],
            404
        );

    }


    if (
        (int)$user[
            'is_deleted'
        ]
        ===
        1
        ||
        (int)$user[
            'is_active'
        ]
        !==
        1
        ||
        (int)$user[
            'is_suspended'
        ]
        ===
        1
    ) {

        deleteAccountResponse(
            false,
            'This account is currently unavailable.',
            [
                'code' =>
                    'ACCOUNT_UNAVAILABLE'
            ],
            403
        );

    }


    if (
        (int)$user[
            'email_verified'
        ]
        !==
        1
    ) {

        deleteAccountResponse(
            false,
            'Your email address is not verified.',
            [
                'code' =>
                    'EMAIL_NOT_VERIFIED'
            ],
            403
        );

    }


    if (
        (int)$user[
            'two_factor_enabled'
        ]
        !==
        1
    ) {

        deleteAccountResponse(
            false,
            'Google Authenticator 2FA is not enabled.',
            [
                'code' =>
                    '2FA_NOT_CONFIGURED'
            ],
            409
        );

    }


    if (
        trim(
            (string)
            (
                $user[
                    'two_factor_secret_encrypted'
                ]
                ??
                ''
            )
        )
        ===
        ''
    ) {

        deleteAccountResponse(
            false,
            'Your Google Authenticator configuration could not be found.',
            [
                'code' =>
                    '2FA_SECRET_MISSING'
            ],
            409
        );

    }


    /* ========================================================
       DECRYPT SECRET
    ======================================================== */

    try {

        $parts =
            explode(
                ':',
                (string)
                $user[
                    'two_factor_secret_encrypted'
                ],
                2
            );


        if (
            count(
                $parts
            )
            !==
            2
        ) {

            throw new RuntimeException(
                'INVALID_ENCRYPTED_SECRET'
            );

        }


        $iv =
            base64_decode(
                $parts[0],
                true
            );


        $encrypted =
            base64_decode(
                $parts[1],
                true
            );


        if (
            $iv === false
            ||
            $encrypted === false
        ) {

            throw new RuntimeException(
                'INVALID_BASE64_DATA'
            );

        }


        $secret =
            openssl_decrypt(
                $encrypted,
                'aes-256-cbc',
                getApplicationEncryptionKey(),
                OPENSSL_RAW_DATA,
                $iv
            );


        if (
            $secret === false
            ||
            trim(
                $secret
            )
            ===
            ''
        ) {

            throw new RuntimeException(
                'DECRYPTION_FAILED'
            );

        }


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE 2FA DECRYPT] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to access your Google Authenticator configuration.',
            [
                'code' =>
                    '2FA_DECRYPT_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       CHECK TOTP
    ======================================================== */

    try {

        $google =
            new GoogleAuthenticator();


        $valid =
            $google->checkCode(
                $secret,
                $code
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE 2FA CHECK] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to verify your Google Authenticator code.',
            [
                'code' =>
                    '2FA_CHECK_FAILED'
            ],
            500
        );

    }


    if (!$valid) {

        deleteAccountResponse(
            false,
            'The Google Authenticator code is incorrect or expired.',
            [
                'code' =>
                    'INVALID_2FA_CODE'
            ],
            422
        );

    }


    /* ========================================================
       SAVE 2FA FACTOR
    ======================================================== */

    try {

        $stmt =
            $pdo->prepare(
                "
                UPDATE
                    account_deletion_verifications

                SET
                    two_factor_verified =
                        1,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE 2FA SAVE] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to save the two-factor verification.',
            [
                'code' =>
                    '2FA_SAVE_FAILED'
            ],
            500
        );

    }


    $_SESSION[
        'lovemi_delete_2fa_verified'
    ] =
        true;


    deleteAccountResponse(
        true,
        'Two-factor verification was successful. Your account is ready for final deletion.',
        [
            'two_factor_verified' =>
                true
        ]
    );

}


/* ============================================================
   ACTION: FINALIZE
============================================================ */

if (
    $action ===
    'finalize'
) {

    $confirmation =
        strtoupper(
            trim(
                (string)
                (
                    $input[
                        'confirmation'
                    ]
                    ??
                    ''
                )
            )
        );


    if (
        $confirmation !==
        'DELETE'
    ) {

        deleteAccountResponse(
            false,
            'Final deletion confirmation is required.',
            [
                'code' =>
                    'CONFIRMATION_REQUIRED'
            ],
            422
        );

    }


    /*
     * First check session factors.
     */

    $linkVerified =
        (bool)
        (
            $_SESSION[
                'lovemi_delete_link_verified'
            ]
            ??
            false
        );


    $emailVerified =
        (bool)
        (
            $_SESSION[
                'lovemi_delete_email_verified'
            ]
            ??
            false
        );


    $twoFactorVerified =
        (bool)
        (
            $_SESSION[
                'lovemi_delete_2fa_verified'
            ]
            ??
            false
        );


    if (
        !$linkVerified
        ||
        !$emailVerified
        ||
        !$twoFactorVerified
    ) {

        deleteAccountResponse(
            false,
            'All account-deletion security checks must be completed first.',
            [
                'code' =>
                    'SECURITY_CHECKS_INCOMPLETE',

                'link_verified' =>
                    $linkVerified,

                'email_verified' =>
                    $emailVerified,

                'two_factor_verified' =>
                    $twoFactorVerified
            ],
            403
        );

    }


    /* ========================================================
       START FINAL TRANSACTION
    ======================================================== */

    try {

        $pdo->beginTransaction();


        /*
         * Lock and reload verification.
         * This prevents deletion using stale session state.
         */

        $verifyStmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    link_verified,

                    email_verified,

                    two_factor_verified,

                    used_at

                FROM
                    account_deletion_verifications

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1

                FOR UPDATE
                "
            );


        $verifyStmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


        $verification =
            $verifyStmt->fetch(
                PDO::FETCH_ASSOC
            );


        if (
            !$verification
            ||
            $verification[
                'used_at'
            ]
            !==
            null
            ||
            (int)$verification[
                'link_verified'
            ]
            !==
            1
            ||
            (int)$verification[
                'email_verified'
            ]
            !==
            1
            ||
            (int)$verification[
                'two_factor_verified'
            ]
            !==
            1
        ) {

            throw new RuntimeException(
                'DELETE_VERIFICATION_INCOMPLETE'
            );

        }


        /* ====================================================
           RECHECK USER
        ==================================================== */

        $userStmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    is_active,

                    is_suspended,

                    is_deleted

                FROM users

                WHERE id =
                    :user_id

                LIMIT 1

                FOR UPDATE
                "
            );


        $userStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );


        $user =
            $userStmt->fetch(
                PDO::FETCH_ASSOC
            );


        if (!$user) {

            throw new RuntimeException(
                'USER_NOT_FOUND'
            );

        }


        if (
            (int)$user[
                'is_deleted'
            ]
            ===
            1
        ) {

            throw new RuntimeException(
                'ACCOUNT_ALREADY_DELETED'
            );

        }


        /* ====================================================
           SOFT DELETE USER
        ==================================================== */

        $deleteStmt =
            $pdo->prepare(
                "
                UPDATE users

                SET

                    account_status =
                        'deleted',

                    is_active =
                        0,

                    is_suspended =
                        0,

                    is_deleted =
                        1,

                    last_seen_at =
                        NULL

                WHERE id =
                    :user_id

                LIMIT 1
                "
            );


        $deleteStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );


        /* ====================================================
           HIDE PROFILE
        ==================================================== */

        $profileStmt =
            $pdo->prepare(
                "
                UPDATE profiles

                SET

                    profile_visibility =
                        'private',

                    show_online_status =
                        0,

                    allow_messages =
                        0

                WHERE user_id =
                    :user_id
                "
            );


        $profileStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );


        /* ====================================================
           OFFLINE
        ==================================================== */

        $presenceStmt =
            $pdo->prepare(
                "
                UPDATE user_presence

                SET

                    is_online =
                        0,

                    last_seen_at =
                        CURRENT_TIMESTAMP,

                    is_typing =
                        0,

                    typing_conversation_id =
                        NULL

                WHERE user_id =
                    :user_id
                "
            );


        $presenceStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );


        /* ====================================================
           REVOKE ALL DB SESSIONS
        ==================================================== */

        $sessionStmt =
            $pdo->prepare(
                "
                UPDATE user_sessions

                SET

                    revoked_at =
                        CURRENT_TIMESTAMP

                WHERE user_id =
                    :user_id

                  AND revoked_at IS NULL
                "
            );


        $sessionStmt->execute(
            [
                ':user_id' =>
                    $deleteUserId
            ]
        );


        /* ====================================================
           CLOSE VERIFICATION REQUEST
        ==================================================== */

        $closeStmt =
            $pdo->prepare(
                "
                UPDATE
                    account_deletion_verifications

                SET

                    used_at =
                        CURRENT_TIMESTAMP,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :id

                  AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $closeStmt->execute(
            [
                ':id' =>
                    $verificationId,

                ':user_id' =>
                    $deleteUserId
            ]
        );


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
            '[LOVEMI FINAL DELETE] '
            .
            $e->getMessage()
        );


        deleteAccountResponse(
            false,
            'Unable to delete your account. No deletion was completed.',
            [
                'code' =>
                    'DELETE_ACCOUNT_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       DESTROY SESSION
    ======================================================== */

    $_SESSION = [];


    if (
        ini_get(
            'session.use_cookies'
        )
    ) {

        $params =
            session_get_cookie_params();


        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params[
                'path'
            ],
            $params[
                'domain'
            ],
            $params[
                'secure'
            ],
            $params[
                'httponly'
            ]
        );

    }


    session_destroy();


    deleteAccountResponse(
        true,
        'Your LOVEMI account has been deleted successfully.',
        [
            'deleted' =>
                true,

            'redirect' =>
                'index.html'
        ]
    );

}


/* ============================================================
   INVALID ACTION
============================================================ */

deleteAccountResponse(
    false,
    'Invalid account deletion action.',
    [
        'code' =>
            'INVALID_ACTION'
    ],
    422
);