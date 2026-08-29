<?php
/**
 * ============================================================
 * LOVEMI - RESET PASSWORD API
 * ============================================================
 *
 * Completes password recovery after:
 *
 *   forgot-password.php
 *   verify-reset.php
 *
 * Input JSON:
 *
 * {
 *     "email": "user@example.com",
 *     "reset_token": "...",
 *     "new_password": "...",
 *     "confirm_password": "..."
 * }
 *
 * Security:
 *   - reset token is never stored in plain text
 *   - reset request must still be valid
 *   - reset request must belong to the same email
 *   - request must not be expired
 *   - request must not be used
 *   - request must not be blocked
 *   - token is compared with SHA-256 + hash_equals()
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

date_default_timezone_set('Africa/Nairobi');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function resetPasswordResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    resetPasswordResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents('php://input');

$input =
    json_decode(
        (string) $raw,
        true
    );

if (!is_array($input)) {
    $input = $_POST;
}


$email =
    trim(
        (string)
        (
            $input['email']
            ?? ''
        )
    );


$token =
    trim(
        (string)
        (
            $input['reset_token']
            ??
            $input['token']
            ??
            ''
        )
    );


$newPassword =
    (string)
    (
        $input['new_password']
        ??
        ''
    );


$confirmPassword =
    (string)
    (
        $input['confirm_password']
        ??
        ''
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    resetPasswordResponse(
        false,
        'Invalid email address.',
        [
            'code' => 'INVALID_EMAIL'
        ],
        422
    );
}


if (
    $token === ''
) {

    resetPasswordResponse(
        false,
        'Password reset token is required.',
        [
            'code' => 'TOKEN_REQUIRED'
        ],
        422
    );
}


if (
    strlen($newPassword) < 8
) {

    resetPasswordResponse(
        false,
        'Your new password must contain at least 8 characters.',
        [
            'code' => 'PASSWORD_TOO_SHORT'
        ],
        422
    );
}


if (
    strlen($newPassword) > 255
) {

    resetPasswordResponse(
        false,
        'Your new password is too long.',
        [
            'code' => 'PASSWORD_TOO_LONG'
        ],
        422
    );
}


if (
    !hash_equals(
        $newPassword,
        $confirmPassword
    )
) {

    resetPasswordResponse(
        false,
        'The two passwords do not match.',
        [
            'code' => 'PASSWORD_MISMATCH'
        ],
        422
    );
}


/* ============================================================
   PASSWORD QUALITY
============================================================ */

$hasLetter =
    preg_match(
        '/[A-Za-z]/',
        $newPassword
    );


$hasNumber =
    preg_match(
        '/[0-9]/',
        $newPassword
    );


if (
    !$hasLetter
    ||
    !$hasNumber
) {

    resetPasswordResponse(
        false,
        'Use a password containing both letters and numbers.',
        [
            'code' => 'PASSWORD_WEAK'
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
        '[LOVEMI RESET PASSWORD DB] '
        .
        $e->getMessage()
    );

    resetPasswordResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   LOAD REQUEST
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $token
    );


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                pr.id,
                pr.user_id,
                pr.email,

                pr.reset_token_hash,

                pr.attempt_count,
                pr.max_attempts,

                pr.expires_at,
                pr.used_at,
                pr.blocked_at,

                u.account_status,
                u.is_active,
                u.is_suspended,
                u.is_deleted

            FROM password_resets pr

            INNER JOIN users u
                ON u.id = pr.user_id

            WHERE pr.email = :email

              AND pr.used_at IS NULL

              AND pr.blocked_at IS NULL

            ORDER BY
                pr.id DESC

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
        '[LOVEMI RESET REQUEST QUERY] '
        .
        $e->getMessage()
    );

    resetPasswordResponse(
        false,
        'Unable to verify your password reset request.',
        [
            'code' =>
                'RESET_LOOKUP_FAILED'
        ],
        500
    );
}


if (!$reset) {

    resetPasswordResponse(
        false,
        'This password reset request is invalid or has already been used.',
        [
            'code' =>
                'RESET_REQUEST_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   ACCOUNT STATUS
============================================================ */

if (
    (int) $reset['is_deleted'] === 1
) {

    resetPasswordResponse(
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
    (int) $reset['is_suspended'] === 1
) {

    resetPasswordResponse(
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
    (int) $reset['is_active'] !== 1
) {

    resetPasswordResponse(
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
   SESSION VERIFICATION
============================================================ */

$sessionReset =
    $_SESSION['lovemi_password_reset']
    ??
    null;


/*
 * The direct token validation below remains authoritative.
 * The session is an additional protection.
 */

if (
    is_array($sessionReset)
) {

    if (
        isset(
            $sessionReset['reset_id']
        )
        &&
        (int)
        $sessionReset['reset_id']
        !==
        (int)
        $reset['id']
    ) {

        resetPasswordResponse(
            false,
            'Your password reset session is no longer valid. Please start again.',
            [
                'code' =>
                    'RESET_SESSION_INVALID'
            ],
            403
        );
    }

}


/* ============================================================
   EXPIRY
============================================================ */

$expiresAt =
    strtotime(
        (string)
        $reset['expires_at']
    );


if (
    $expiresAt === false
    ||
    $expiresAt < time()
) {

    try {

        $stmt =
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


        $stmt->execute(
            [
                ':id' =>
                    (int)
                    $reset['id']
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI RESET EXPIRE] '
            .
            $e->getMessage()
        );
    }


    resetPasswordResponse(
        false,
        'This password reset request has expired. Please request a new one.',
        [
            'code' =>
                'RESET_EXPIRED'
        ],
        410
    );
}


/* ============================================================
   TOKEN MATCH
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

    $attempts =
        (int)
        $reset['attempt_count']
        +
        1;


    $maxAttempts =
        max(
            1,
            (int)
            $reset['max_attempts']
        );


    $blocked =
        $attempts >= $maxAttempts;


    try {

        $stmt =
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


        $stmt->execute(
            [

                ':attempt_count' =>
                    $attempts,

                ':blocked' =>
                    $blocked ? 1 : 0,

                ':id' =>
                    (int)
                    $reset['id']

            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI RESET TOKEN ATTEMPT] '
            .
            $e->getMessage()
        );
    }


    if ($blocked) {

        resetPasswordResponse(
            false,
            'This password reset request has been blocked.',
            [
                'code' =>
                    'RESET_BLOCKED'
            ],
            403
        );
    }


    resetPasswordResponse(
        false,
        'The password reset token is invalid.',
        [
            'code' =>
                'INVALID_RESET_TOKEN',

            'attempts_remaining' =>
                max(
                    0,
                    $maxAttempts - $attempts
                )
        ],
        403
    );
}


/* ============================================================
   PASSWORD HASH
============================================================ */

$passwordHash =
    password_hash(
        $newPassword,
        PASSWORD_DEFAULT
    );


if (
    $passwordHash === false
) {

    resetPasswordResponse(
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
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Update password.
     */

    $passwordStmt =
        $pdo->prepare(
            "
            UPDATE users

            SET

                password_hash =
                    :password_hash,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id = :user_id

              AND email = :email

            LIMIT 1
            "
        );


    $passwordStmt->execute(
        [

            ':password_hash' =>
                $passwordHash,

            ':user_id' =>
                (int)
                $reset['user_id'],

            ':email' =>
                $email

        ]
    );


    if (
        $passwordStmt->rowCount() < 1
    ) {

        throw new RuntimeException(
            'Password update failed.'
        );

    }


    /*
     * Consume reset request.
     */

    $consumeStmt =
        $pdo->prepare(
            "
            UPDATE password_resets

            SET
                used_at =
                    CURRENT_TIMESTAMP

            WHERE id = :id

              AND used_at IS NULL

            LIMIT 1
            "
        );


    $consumeStmt->execute(
        [
            ':id' =>
                (int)
                $reset['id']
        ]
    );


    if (
        $consumeStmt->rowCount() < 1
    ) {

        throw new RuntimeException(
            'Reset request could not be consumed.'
        );

    }


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI PASSWORD RESET COMMIT] '
        .
        $e->getMessage()
    );


    resetPasswordResponse(
        false,
        'Unable to reset your password. Please try again.',
        [
            'code' =>
                'PASSWORD_RESET_FAILED'
        ],
        500
    );
}


/* ============================================================
   INVALIDATE RESET SESSION
============================================================ */

unset(
    $_SESSION['lovemi_password_reset']
);

unset(
    $_SESSION['lovemi_password_reset_request_id']
);


/* ============================================================
   LOG USER OUT
============================================================ */

unset(
    $_SESSION['lovemi_user_id']
);

unset(
    $_SESSION['lovemi_user_role']
);

unset(
    $_SESSION['lovemi_login_complete']
);


/* ============================================================
   RESPONSE
============================================================ */

resetPasswordResponse(
    true,
    'Your password has been changed successfully. Please log in with your new password.',
    [
        'redirect' =>
            'login.html',

        'password_reset' =>
            true
    ]
);