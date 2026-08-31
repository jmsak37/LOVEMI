<?php
/**
 * ============================================================
 * LOVEMI - AUTH SESSION API
 * ============================================================
 */

declare(strict_types=1);


require_once __DIR__ . '/../../config/database.php';


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
    && $_SERVER['HTTPS'] !== 'off';


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

function sessionResponse(
    bool $success,
    string $message,
    array $extra = [],
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
            $extra
        ),
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );


    exit;
}


/* ============================================================
   SESSION VALUES
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


$token =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ? trim(
            (string)
            $_SESSION['lovemi_session_token']
        )
        : '';


if (
    $userId <= 0
    ||
    $token === ''
) {

    sessionResponse(
        true,
        'No authenticated session.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'two_factor_passed' =>
                false
        ]
    );

}


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


    $stmt =
        $pdo->prepare(
            "
            SELECT

                us.id AS session_id,

                us.user_id,

                us.expires_at,

                us.revoked_at,

                us.two_factor_passed,

                u.username,
                u.full_names,
                u.gender,
                u.email,
                u.country_id,

                u.account_status,

                u.email_verified,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                u.two_factor_enabled,

                c.name AS country_name,
                c.iso2 AS country_iso2

            FROM user_sessions us

            INNER JOIN users u
                ON u.id = us.user_id

            LEFT JOIN countries c
                ON c.id = u.country_id

            WHERE

                us.session_token_hash =
                    :token_hash

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':token_hash' =>
                $tokenHash
        ]
    );


    $session =
        $stmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI SESSION ERROR] '
        . $e->getMessage()
    );


    sessionResponse(
        false,
        'Unable to validate your session.',
        [],
        500
    );

}


/* ============================================================
   INVALID SESSION
============================================================ */

if (!$session) {

    unset(
        $_SESSION['lovemi_user_id'],
        $_SESSION['lovemi_session_token'],
        $_SESSION['lovemi_database_session_id'],
        $_SESSION['lovemi_2fa_pending_user_id']
    );


    sessionResponse(
        true,
        'Session is not authenticated.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'two_factor_passed' =>
                false
        ]
    );

}


/* ============================================================
   USER MATCH
============================================================ */

if (
    (int)
    $session['user_id']
    !==
    $userId
) {

    sessionResponse(
        true,
        'Invalid session.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false
        ]
    );

}


/* ============================================================
   REVOKED
============================================================ */

if (
    $session['revoked_at'] !== null
) {

    sessionResponse(
        true,
        'Session revoked.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false
        ]
    );

}


/* ============================================================
   EXPIRY
============================================================ */

$expiry =
    strtotime(
        (string)
        $session['expires_at']
    );


if (
    $expiry === false
    ||
    $expiry <= time()
) {

    try {

        $revoke =
            $pdo->prepare(
                "
                UPDATE user_sessions

                SET revoked_at =
                    CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );


        $revoke->execute(
            [
                ':id' =>
                    (int)
                    $session['session_id']
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI SESSION EXPIRE ERROR] '
            . $e->getMessage()
        );

    }


    unset(
        $_SESSION['lovemi_user_id'],
        $_SESSION['lovemi_session_token'],
        $_SESSION['lovemi_database_session_id'],
        $_SESSION['lovemi_2fa_pending_user_id']
    );


    sessionResponse(
        true,
        'Session expired.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false
        ]
    );

}


/* ============================================================
   ACCOUNT STATUS
============================================================ */

if (
    (bool) $session['is_deleted']
    ||
    !(bool) $session['is_active']
    ||
    (bool) $session['is_suspended']
) {

    sessionResponse(
        true,
        'Account unavailable.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false
        ]
    );

}


/* ============================================================
   EMAIL
============================================================ */

if (
    !(bool)
    $session['email_verified']
) {

    sessionResponse(
        true,
        'Email verification required.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'verification_required' =>
                true
        ]
    );

}


/* ============================================================
   2FA
============================================================ */

$twoFactorPassed =
    (bool)
    $session['two_factor_passed'];


$twoFactorEnabled =
    (bool)
    $session['two_factor_enabled'];


/*
 * A user can NEVER be fully authenticated until the
 * Google Authenticator step has succeeded.
 */

if (
    !$twoFactorPassed
) {

    sessionResponse(
        true,
        $twoFactorEnabled
            ?
            'Google Authenticator verification required.'
            :
            'Google Authenticator setup required.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'two_factor_required' =>
                true,

            'two_factor_enabled' =>
                $twoFactorEnabled,

            'two_factor_passed' =>
                false
        ]
    );

}


/* ============================================================
   REFRESH ACTIVITY
============================================================ */

try {

    $updateSession =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET last_activity_at =
                CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $updateSession->execute(
        [
            ':id' =>
                (int)
                $session['session_id']
        ]
    );


    $updateUser =
        $pdo->prepare(
            "
            UPDATE users

            SET last_seen_at =
                CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $updateUser->execute(
        [
            ':id' =>
                $userId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SESSION ACTIVITY ERROR] '
        . $e->getMessage()
    );

}


/* ============================================================
   FULLY AUTHENTICATED
============================================================ */

sessionResponse(
    true,
    'Authenticated session.',
    [
        'authenticated' =>
            true,

        'logged_in' =>
            true,

        'two_factor_required' =>
            true,

        'two_factor_enabled' =>
            true,

        'two_factor_passed' =>
            true,

        'user' =>
            [
                'id' =>
                    (int)
                    $session['user_id'],

                'username' =>
                    (string)
                    $session['username'],

                'full_name' =>
                    (string)
                    $session['full_names'],

                'gender' =>
                    (string)
                    $session['gender'],

                'email' =>
                    (string)
                    $session['email'],

                'country_id' =>
                    (int)
                    $session['country_id'],

                'country_name' =>
                    $session['country_name'],

                'country_iso2' =>
                    $session['country_iso2']
            ]
    ]
);