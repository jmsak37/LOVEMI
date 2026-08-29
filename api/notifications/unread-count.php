<?php
/**
 * ============================================================
 * LOVEMI - UNREAD NOTIFICATION COUNT API
 * ============================================================
 *
 * Returns the number of unread notifications belonging to the
 * authenticated user.
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

function unreadCountResponse(
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
) {

    unreadCountResponse(
        false,
        'Only GET requests are allowed.',
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

    unreadCountResponse(
        false,
        'Please log in.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'unread_count' =>
                0

        ],
        401
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
        '[LOVEMI UNREAD COUNT DB] '
        .
        $e->getMessage()
    );


    unreadCountResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR',

            'unread_count' =>
                0

        ],
        500
    );
}


/* ============================================================
   COUNT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM notifications

            WHERE user_id = :user_id

              AND is_read = 0
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $count =
        (int)
        $stmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UNREAD COUNT QUERY] '
        .
        $e->getMessage()
    );


    unreadCountResponse(
        false,
        'Unable to read notification count.',
        [
            'code' =>
                'COUNT_QUERY_ERROR',

            'unread_count' =>
                0

        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

unreadCountResponse(
    true,
    'Unread notification count loaded.',
    [

        'unread_count' =>
            $count,

        'has_unread' =>
            $count > 0

    ]
);