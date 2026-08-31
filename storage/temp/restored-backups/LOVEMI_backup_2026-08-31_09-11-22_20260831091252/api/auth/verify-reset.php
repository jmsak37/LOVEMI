<?php
/**
 * ============================================================
 * LOVEMI - VERIFY PASSWORD RESET TOKEN
 * ============================================================
 *
 * GET:
 *
 *   api/auth/verify-reset.php?email=...&token=...
 *
 * The endpoint:
 *
 *   - Finds the active reset request.
 *   - Checks expiry.
 *   - Checks blocked/used state.
 *   - Hashes incoming token.
 *   - Compares it securely.
 *   - Records failed attempts.
 *   - Marks the reset request verified in session.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


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

function verifyResetResponse(
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
    'GET'
    &&
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    verifyResetResponse(
        false,
        'Only GET and POST requests are allowed.',
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

$email =
    trim(
        (string)
        (
            $_GET['email']
            ??
            $_POST['email']
            ??
            ''
        )
    );


$token =
    trim(
        (string)
        (
            $_GET['token']
            ??
            $_POST['token']
            ??
            $_POST['reset_token']
            ??
            ''
        )
    );


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    verifyResetResponse(
        false,
        'The reset email address is invalid.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


if (
    $token === ''
) {

    verifyResetResponse(
        false,
        'The password reset token is missing.',
        [
            'code' =>
                'TOKEN_REQUIRED'
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFY RESET DB] '
        .
        $e->getMessage()
    );


    verifyResetResponse(
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
   TOKEN HASH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $token
    );


/* ============================================================
   LOAD RESET REQUEST
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                email,
                phone_e164,
                id_number_hash,

                reset_token_hash,

                attempt_count,
                max_attempts,

                expires_at,
                used_at,
                blocked_at,

                created_at

            FROM password_resets

            WHERE email = :email

              AND used_at IS NULL

              AND blocked_at IS NULL

            ORDER BY
                id DESC

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':email' =>
                $email
        ]
    );


    $reset =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFY RESET QUERY] '
        .
        $e->getMessage()
    );


    verifyResetResponse(
        false,
        'Unable to verify the password reset request.',
        [
            'code' =>
                'RESET_LOOKUP_FAILED'
        ],
        500
    );

}


/* ============================================================
   NOT FOUND
============================================================ */

if (
    !$reset
) {

    verifyResetResponse(
        false,
        'This password reset link is invalid or has already been used.',
        [
            'code' =>
                'RESET_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   BLOCKED
============================================================ */

$attemptCount =
    (int)
    $reset['attempt_count'];


$maxAttempts =
    max(
        1,
        (int)
        $reset['max_attempts']
    );


if (
    $attemptCount
    >=
    $maxAttempts
) {

    verifyResetResponse(
        false,
        'This password reset request has been blocked because the maximum number of attempts was reached.',
        [
            'code' =>
                'RESET_ATTEMPTS_EXCEEDED'
        ],
        403
    );

}


/* ============================================================
   EXPIRY
============================================================ */

$expiresTimestamp =
    strtotime(
        (string)
        $reset['expires_at']
    );


if (
    $expiresTimestamp === false
    ||
    $expiresTimestamp < time()
) {

    /*
     * Mark it used/invalid so it cannot be reused.
     */

    try {

        $expireStmt =
            $pdo->prepare(
                "
                UPDATE password_resets

                SET
                    blocked_at =
                        CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );


        $expireStmt->execute(
            [
                ':id' =>
                    (int)
                    $reset['id']
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI VERIFY RESET EXPIRE] '
            .
            $e->getMessage()
        );

    }


    verifyResetResponse(
        false,
        'This password reset link has expired. Please request a new one.',
        [
            'code' =>
                'RESET_EXPIRED'
        ],
        410
    );

}


/* ============================================================
   USER STILL VALID
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                email,
                account_status,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :user_id

              AND email = :email

            LIMIT 1
            "
        );


    $userStmt->execute(
        [

            ':user_id' =>
                (int)
                $reset['user_id'],

            ':email' =>
                $email

        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY RESET USER] '
        .
        $e->getMessage()
    );


    verifyResetResponse(
        false,
        'Unable to verify the account.',
        [
            'code' =>
                'USER_LOOKUP_FAILED'
        ],
        500
    );

}


if (
    !$user
) {

    verifyResetResponse(
        false,
        'The account associated with this reset request could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );

}


if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    verifyResetResponse(
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

    verifyResetResponse(
        false,
        'This account is suspended.',
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

    verifyResetResponse(
        false,
        'This account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );

}


/* ============================================================
   VERIFY TOKEN
============================================================ */

$storedHash =
    (string)
    $reset['reset_token_hash'];


if (
    $storedHash === ''
    ||
    !hash_equals(
        $storedHash,
        $tokenHash
    )
) {

    $newAttemptCount =
        $attemptCount
        +
        1;


    $blocked =
        $newAttemptCount
        >=
        $maxAttempts;


    try {

        $attemptStmt =
            $pdo->prepare(
                "
                UPDATE password_resets

                SET

                    attempt_count =
                        :attempt_count,

                    blocked_at =
                        CASE

                            WHEN :blocked = 1
                            THEN CURRENT_TIMESTAMP

                            ELSE blocked_at

                        END

                WHERE id = :id

                LIMIT 1
                "
            );


        $attemptStmt->execute(
            [

                ':attempt_count' =>
                    $newAttemptCount,

                ':blocked' =>
                    $blocked
                    ?
                    1
                    :
                    0,

                ':id' =>
                    (int)
                    $reset['id']

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


    if (
        $blocked
    ) {

        verifyResetResponse(
            false,
            'This password reset request has been blocked.',
            [
                'code' =>
                    'RESET_BLOCKED'
            ],
            403
        );

    }


    $remaining =
        max(
            0,
            $maxAttempts
            -
            $newAttemptCount
        );


    verifyResetResponse(
        false,
        'The password reset link is invalid.',
        [

            'code' =>
                'INVALID_RESET_TOKEN',

            'attempts_remaining' =>
                $remaining

        ],
        403
    );

}


/* ============================================================
   SESSION
============================================================ */

/*
 * The original token is intentionally kept only in the current
 * server session long enough for reset-password.php to verify
 * the reset request.
 */

$_SESSION[
    'lovemi_password_reset'
] = [

    'reset_id' =>
        (int)
        $reset['id'],

    'user_id' =>
        (int)
        $reset['user_id'],

    'email' =>
        $email,

    'verified' =>
        true,

    'verified_at' =>
        time(),

    'expires_at' =>
        $expiresTimestamp

];


/* ============================================================
   RESPONSE
============================================================ */

verifyResetResponse(
    true,
    'Password reset link verified successfully.',
    [

        'verified' =>
            true,

        'email' =>
            $email,

        'expires_at' =>
            date(
                'c',
                $expiresTimestamp
            )

    ]
);