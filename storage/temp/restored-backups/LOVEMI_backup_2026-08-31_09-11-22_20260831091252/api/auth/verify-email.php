<?php
/**
 * ============================================================
 * LOVEMI - VERIFY EMAIL
 * ============================================================
 *
 * Email verification is the ONLY registration verification.
 *
 * Successful email verification:
 *
 *   email_verified = TRUE
 *   account_status = approved
 *
 * Then:
 *
 *   temporary 2FA setup session
 *
 * The user is sent to Google Authenticator setup.
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


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
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


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

function verifyEmailResponse(
    bool $success,
    string $message,
    array $extra = [],
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
            $extra
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

    verifyEmailResponse(
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

$data =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data = [];

}


$userId =
    isset(
        $data['user_id']
    )
        ? (int)
          $data['user_id']
        : 0;


$code =
    preg_replace(
        '/[^0-9]/',
        '',
        (string)
        (
            $data['code']
            ??
            ''
        )
    );


/* ============================================================
   USER ID
============================================================ */

if (
    $userId <= 0
) {

    verifyEmailResponse(
        false,
        'Invalid account.',
        [
            'code' =>
                'INVALID_USER'
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
        '[LOVEMI VERIFY EMAIL DATABASE ERROR] '
        .
        $e->getMessage()
    );


    verifyEmailResponse(
        false,
        'Email verification is temporarily unavailable.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   LOAD USER
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                username,
                full_names,
                email,
                phone_e164,

                email_verified,

                account_status,

                two_factor_enabled,

                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY EMAIL USER ERROR] '
        .
        $e->getMessage()
    );


    verifyEmailResponse(
        false,
        'Unable to load the account.',
        [],
        500
    );

}


if (
    !$user
) {

    verifyEmailResponse(
        false,
        'Account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   SAFE ACCOUNT
============================================================ */

function verificationAccount(
    array $user
): array {

    return [

        'id' =>
            (int)
            $user['id'],

        'full_name' =>
            (string)
            $user['full_names'],

        'email' =>
            (string)
            $user['email'],

        'phone_last4' =>
            !empty(
                $user['phone_e164']
            )
                ?
                substr(
                    (string)
                    $user['phone_e164'],
                    -4
                )
                :
                null

    ];

}


/* ============================================================
   STATUS REQUEST
============================================================ */

if (
    $code === ''
) {

    verifyEmailResponse(
        true,
        'Verification status loaded.',
        [
            'email_verified' =>
                (bool)
                $user['email_verified'],

            'account_status' =>
                (string)
                $user['account_status'],

            'two_factor_enabled' =>
                (bool)
                $user['two_factor_enabled'],

            'two_factor_required' =>
                true,

            'account' =>
                verificationAccount(
                    $user
                )
        ]
    );

}


/* ============================================================
   ACCOUNT STATE
============================================================ */

if (
    (bool)
    $user['is_deleted']
    ||
    (bool)
    $user['is_suspended']
    ||
    !(bool)
    $user['is_active']
) {

    verifyEmailResponse(
        false,
        'This account is currently unavailable.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );

}


/* ============================================================
   ALREADY VERIFIED
============================================================ */

if (
    (bool)
    $user['email_verified']
) {

    /*
     * Ensure setup can continue even if the user is returning
     * later before completing Google Authenticator.
     */

    if (
        !(bool)
        $user['two_factor_enabled']
    ) {

        $_SESSION[
            'lovemi_2fa_setup_user_id'
        ] =
            $userId;


        $_SESSION[
            'lovemi_2fa_setup_created_at'
        ] =
            time();

    }


    verifyEmailResponse(
        true,
        'Your email is already verified. Continue to Google Authenticator.',
        [
            'email_verified' =>
                true,

            'two_factor_enabled' =>
                (bool)
                $user['two_factor_enabled'],

            'account_status' =>
                (string)
                $user['account_status'],

            'two_factor_required' =>
                true,

            'redirect' =>
                (
                    (bool)
                    $user['two_factor_enabled']
                )
                    ?
                    'login.html'
                    :
                    'verify-account.html?user='
                    .
                    rawurlencode(
                        (string)
                        $userId
                    )
                    .
                    '&step=2fa',

            'account' =>
                verificationAccount(
                    $user
                )
        ]
    );

}


/* ============================================================
   CODE FORMAT
============================================================ */

if (
    !preg_match(
        '/^\d{6}$/',
        $code
    )
) {

    verifyEmailResponse(
        false,
        'Enter the six-digit email verification code.',
        [
            'code' =>
                'INVALID_CODE_FORMAT'
        ],
        422
    );

}


/* ============================================================
   LATEST VERIFICATION
============================================================ */

try {

    $verificationStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                code_hash,

                attempt_count,

                expires_at,

                blocked_at,

                verified_at

            FROM verifications

            WHERE user_id = :user_id

              AND verification_type =
                  'email_registration'

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $verificationStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $verification =
        $verificationStmt->fetch();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY EMAIL CODE QUERY ERROR] '
        .
        $e->getMessage()
    );


    verifyEmailResponse(
        false,
        'Unable to load the verification code.',
        [],
        500
    );

}


if (
    !$verification
) {

    verifyEmailResponse(
        false,
        'No verification code exists. Please request a new code.',
        [
            'code' =>
                'NO_CODE'
        ],
        422
    );

}


/* ============================================================
   BLOCKED
============================================================ */

if (
    $verification['blocked_at']
    !==
    null
) {

    verifyEmailResponse(
        false,
        'This verification attempt has been blocked. Request a new code.',
        [
            'code' =>
                'CODE_BLOCKED'
        ],
        429
    );

}


/* ============================================================
   EXPIRATION
============================================================ */

$expires =
    strtotime(
        (string)
        $verification['expires_at']
    );


if (
    $expires === false
    ||
    $expires <= time()
) {

    verifyEmailResponse(
        false,
        'This verification code has expired. Request a new code.',
        [
            'code' =>
                'CODE_EXPIRED'
        ],
        422
    );

}


/* ============================================================
   ATTEMPT LIMIT
============================================================ */

$attempts =
    (int)
    $verification['attempt_count'];


$maxAttempts =
    5;


if (
    $attempts >=
    $maxAttempts
) {

    verifyEmailResponse(
        false,
        'Too many incorrect attempts. Request a new code.',
        [
            'code' =>
                'TOO_MANY_ATTEMPTS'
        ],
        429
    );

}


/* ============================================================
   HASH
============================================================ */

$submittedHash =
    hash(
        'sha256',
        $code
    );


if (
    !hash_equals(
        (string)
        $verification['code_hash'],
        $submittedHash
    )
) {

    $newAttempts =
        $attempts + 1;


    try {

        $updateAttempt =
            $pdo->prepare(
                "
                UPDATE verifications

                SET attempt_count =
                    :attempts

                WHERE id = :id

                LIMIT 1
                "
            );


        $updateAttempt->execute(
            [
                ':attempts' =>
                    $newAttempts,

                ':id' =>
                    (int)
                    $verification['id']
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI EMAIL ATTEMPT UPDATE ERROR] '
            .
            $e->getMessage()
        );

    }


    if (
        $newAttempts >=
        $maxAttempts
    ) {

        try {

            $block =
                $pdo->prepare(
                    "
                    UPDATE verifications

                    SET blocked_at =
                        CURRENT_TIMESTAMP

                    WHERE id = :id

                    LIMIT 1
                    "
                );


            $block->execute(
                [
                    ':id' =>
                        (int)
                        $verification['id']
                ]
            );

        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI EMAIL CODE BLOCK ERROR] '
                .
                $e->getMessage()
            );

        }


        verifyEmailResponse(
            false,
            'Too many incorrect attempts. Request a new code.',
            [
                'code' =>
                    'TOO_MANY_ATTEMPTS'
            ],
            429
        );

    }


    verifyEmailResponse(
        false,
        'The email verification code is incorrect.',
        [
            'code' =>
                'INCORRECT_CODE',

            'attempts_remaining' =>
                $maxAttempts
                -
                $newAttempts
        ],
        422
    );

}


/* ============================================================
   SUCCESSFUL EMAIL VERIFICATION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       MARK VERIFICATION COMPLETE
    ===================================================== */

    $markCode =
        $pdo->prepare(
            "
            UPDATE verifications

            SET verified_at =
                CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $markCode->execute(
        [
            ':id' =>
                (int)
                $verification['id']
        ]
    );


    /* ========================================================
       APPROVE ACCOUNT
    ===================================================== */

    $updateUser =
        $pdo->prepare(
            "
            UPDATE users

            SET

                email_verified = TRUE,

                account_status = 'approved'

            WHERE id = :user_id

            LIMIT 1
            "
        );


    $updateUser->execute(
        [
            ':user_id' =>
                $userId
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
        '[LOVEMI EMAIL VERIFICATION TRANSACTION ERROR] '
        .
        $e->getMessage()
    );


    verifyEmailResponse(
        false,
        'Unable to complete email verification.',
        [],
        500
    );

}


/* ============================================================
   TEMPORARY 2FA SETUP SESSION
============================================================ */

/*
 * The user has proved ownership of their email.
 *
 * They are now allowed to configure their Google Authenticator
 * without becoming fully logged in.
 *
 * This is NOT the normal authenticated session.
 */

$_SESSION[
    'lovemi_2fa_setup_user_id'
] =
    $userId;


$_SESSION[
    'lovemi_2fa_setup_created_at'
] =
    time();


/*
 * Remove any stale login-2FA state.
 */

unset(
    $_SESSION[
        'lovemi_2fa_pending_user_id'
    ]
);


/* ============================================================
   FINAL RESPONSE
============================================================ */

verifyEmailResponse(
    true,
    'Your email has been verified successfully. Continue to Google Authenticator.',
    [
        'email_verified' =>
            true,

        'account_status' =>
            'approved',

        'two_factor_enabled' =>
            false,

        'two_factor_required' =>
            true,

        'redirect' =>
            'verify-account.html?user='
            .
            rawurlencode(
                (string)
                $userId
            )
            .
            '&step=2fa',

        'account' =>
            verificationAccount(
                array_merge(
                    $user,
                    [
                        'email_verified' =>
                            true
                    ]
                )
            )
    ]
);