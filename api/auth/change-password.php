<?php
/**
 * ============================================================
 * LOVEMI - CHANGE PASSWORD API
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function changePasswordResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

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
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'POST'
) {

    changePasswordResponse(
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
   AUTHENTICATION
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    changePasswordResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
        ],
        401
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


$currentPassword =
    (string)
    (
        $input['current_password']
        ??
        ''
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


if (
    $currentPassword === ''
    ||
    $newPassword === ''
    ||
    $confirmPassword === ''
) {

    changePasswordResponse(
        false,
        'All password fields are required.',
        [
            'code' =>
                'MISSING_FIELDS'
        ],
        422
    );

}


/* ============================================================
   PASSWORD VALIDATION
============================================================ */

if (
    strlen(
        $newPassword
    )
    <
    8
) {

    changePasswordResponse(
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
    strlen(
        $newPassword
    )
    >
    255
) {

    changePasswordResponse(
        false,
        'Your new password is too long.',
        [
            'code' =>
                'PASSWORD_TOO_LONG'
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

    changePasswordResponse(
        false,
        'The new passwords do not match.',
        [
            'code' =>
                'PASSWORD_MISMATCH'
        ],
        422
    );

}


if (
    hash_equals(
        $currentPassword,
        $newPassword
    )
) {

    changePasswordResponse(
        false,
        'Your new password must be different from the current password.',
        [
            'code' =>
                'PASSWORD_UNCHANGED'
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
        '[LOVEMI CHANGE PASSWORD DB] '
        .
        $e->getMessage()
    );


    changePasswordResponse(
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
   USER
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                password_hash,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHANGE PASSWORD USER] '
        .
        $e->getMessage()
    );


    changePasswordResponse(
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

    changePasswordResponse(
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
    (int)
    $user['is_deleted']
    ===
    1
) {

    changePasswordResponse(
        false,
        'Your account is no longer available.',
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

    changePasswordResponse(
        false,
        'Your account is suspended.',
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

    changePasswordResponse(
        false,
        'Your account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );

}


/* ============================================================
   VERIFY CURRENT PASSWORD
============================================================ */

if (
    !password_verify(
        $currentPassword,
        (string)
        $user['password_hash']
    )
) {

    changePasswordResponse(
        false,
        'The current password is incorrect.',
        [
            'code' =>
                'CURRENT_PASSWORD_INCORRECT'
        ],
        403
    );

}


/* ============================================================
   NEW PASSWORD HASH
============================================================ */

$newHash =
    password_hash(
        $newPassword,
        PASSWORD_DEFAULT
    );


if (
    $newHash === false
) {

    changePasswordResponse(
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
   UPDATE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            UPDATE users

            SET
                password_hash = :password_hash,
                updated_at = CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':password_hash' =>
                $newHash,

            ':id' =>
                $userId

        ]
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHANGE PASSWORD UPDATE] '
        .
        $e->getMessage()
    );


    changePasswordResponse(
        false,
        'Unable to change your password.',
        [
            'code' =>
                'PASSWORD_UPDATE_FAILED'
        ],
        500
    );

}


/* ============================================================
   SECURITY
============================================================ */

/*
 * Change the session identifier after a credential change.
 */

try {

    session_regenerate_id(
        true
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SESSION REGENERATE] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

changePasswordResponse(
    true,
    'Your password has been changed successfully.',
    [
        'password_changed' =>
            true
    ]
);