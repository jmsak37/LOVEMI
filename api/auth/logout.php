<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');

$isHttps =
    !empty($_SERVER['HTTPS'])
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
   RESPONSE
============================================================ */

function logoutJson(
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

    logoutJson(
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
   SESSION VALUES
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


$sessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ?
        (string)
        $_SESSION['lovemi_session_token']
        :
        '';


/* ============================================================
   REVOKE DATABASE SESSION
============================================================ */

try {

    $pdo =
        db();


    if (
        $sessionId > 0
    ) {

        if (
            $sessionToken !== ''
        ) {

            $tokenHash =
                hash(
                    'sha256',
                    $sessionToken
                );


            $stmt =
                $pdo->prepare(
                    '
                    UPDATE user_sessions
                    SET revoked_at = CURRENT_TIMESTAMP
                    WHERE id = :session_id
                      AND user_id = :user_id
                      AND session_token_hash = :token_hash
                      AND revoked_at IS NULL
                    LIMIT 1
                    '
                );


            $stmt->execute(
                [
                    ':session_id' =>
                        $sessionId,

                    ':user_id' =>
                        $userId,

                    ':token_hash' =>
                        $tokenHash
                ]
            );

        } else {

            $stmt =
                $pdo->prepare(
                    '
                    UPDATE user_sessions
                    SET revoked_at = CURRENT_TIMESTAMP
                    WHERE id = :session_id
                      AND user_id = :user_id
                      AND revoked_at IS NULL
                    LIMIT 1
                    '
                );


            $stmt->execute(
                [
                    ':session_id' =>
                        $sessionId,

                    ':user_id' =>
                        $userId
                ]
            );

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOGOUT] '
        .
        $e->getMessage()
        .
        ' | FILE='
        .
        $e->getFile()
        .
        ' | LINE='
        .
        $e->getLine()
    );

    /*
     * Continue destroying the browser PHP session even if the
     * database session could not be revoked.
     */

}


/* ============================================================
   CLEAR PHP SESSION
============================================================ */

$_SESSION = [];


if (
    ini_get('session.use_cookies')
) {

    $params =
        session_get_cookie_params();


    setcookie(
        session_name(),
        '',
        [
            'expires' =>
                time() - 42000,

            'path' =>
                $params['path']
                ?:
                '/',

            'domain' =>
                $params['domain']
                ??
                '',

            'secure' =>
                (bool)(
                    $params['secure']
                    ??
                    $isHttps
                ),

            'httponly' =>
                (bool)(
                    $params['httponly']
                    ??
                    true
                ),

            'samesite' =>
                $params['samesite']
                ??
                'Lax'
        ]
    );

}


session_destroy();


/* ============================================================
   RESPONSE
============================================================ */

logoutJson(
    true,
    'You have been logged out successfully.',
    [
        'logged_out' =>
            true
    ]
);