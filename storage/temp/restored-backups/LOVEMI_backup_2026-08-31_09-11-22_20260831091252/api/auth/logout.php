<?php

declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI - COMPLETE LOGOUT
 * ============================================================
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/../../config/database.php';


header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header('Pragma: no-cache');
header('Expires: 0');


function logoutResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   IDENTIFY USER
============================================================ */

$userId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        $_SESSION['user_id']
        ??
        $_SESSION['userID']
        ??
        0
    );


/* ============================================================
   DATABASE SESSION CLEANUP
============================================================ */

if (
    $userId > 0
) {

    try {

        $pdo =
            db();


        /*
         * Delete server-side sessions belonging to this user.
         */

        $stmt =
            $pdo->prepare(
                "
                DELETE FROM user_sessions

                WHERE user_id = ?
                "
            );


        $stmt->execute(
            [
                $userId
            ]
        );


    } catch (Throwable $e) {

        /*
         * We still continue with PHP session destruction.
         */

        error_log(
            '[LOVEMI LOGOUT USER SESSION] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   DESTROY PHP SESSION
============================================================ */

$_SESSION = [];


/*
 * Remove session cookie.
 */

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
                $params['path'],

            'domain' =>
                $params['domain'],

            'secure' =>
                (bool)$params['secure'],

            'httponly' =>
                (bool)$params['httponly'],

            'samesite' =>
                $params['samesite']
                ??
                'Lax'
        ]
    );

}


if (
    session_status() ===
    PHP_SESSION_ACTIVE
) {

    session_destroy();

}


/* ============================================================
   RESPONSE
============================================================ */

logoutResponse(
    true,
    'You have been completely logged out.',
    [
        'logged_out' => true,
        'redirect' => 'login.html'
    ]
);