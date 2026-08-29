<?php
/**
 * ============================================================
 * LOVEMI - REJECT CONNECTION API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "connection_id": 123
 * }
 *
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


function rejectConnectionResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'POST'
) {

    rejectConnectionResponse(
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
   AUTH
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
        $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    rejectConnectionResponse(
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


$connectionId =
    (int)
    (
        $input['connection_id']
        ??
        0
    );


if (
    $connectionId <= 0
) {

    rejectConnectionResponse(
        false,
        'Connection ID is required.',
        [
            'code' =>
                'CONNECTION_ID_REQUIRED'
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
        '[LOVEMI REJECT CONNECTION DB] '
        .
        $e->getMessage()
    );


    rejectConnectionResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/* ============================================================
   LOAD REQUEST
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                connected_user_id,
                initiated_by,
                status

            FROM connections

            WHERE id =
                :id

              AND connected_user_id =
                  :connected_user_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':id' =>
                $connectionId,

            ':connected_user_id' =>
                $userId

        ]
    );


    $connection =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REJECT CONNECTION LOOKUP] '
        .
        $e->getMessage()
    );


    rejectConnectionResponse(
        false,
        'Unable to find the connection request.',
        [
            'code' =>
                'CONNECTION_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$connection
) {

    rejectConnectionResponse(
        false,
        'Connection request not found or access denied.',
        [
            'code' =>
                'CONNECTION_NOT_FOUND'
        ],
        404
    );
}


$status =
    strtolower(
        (string)
        $connection['status']
    );


if (
    $status !==
    'pending'
) {

    if (
        $status ===
        'rejected'
    ) {

        rejectConnectionResponse(
            true,
            'This request has already been rejected.',
            [
                'already_rejected' =>
                    true
            ]
        );

    }


    rejectConnectionResponse(
        false,
        'Only pending requests can be rejected.',
        [
            'code' =>
                'INVALID_CONNECTION_STATUS',

            'status' =>
                $status
        ],
        409
    );
}


/* ============================================================
   REJECT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            UPDATE connections

            SET
                status = 'rejected'

            WHERE id =
                :id

              AND connected_user_id =
                  :user_id

              AND status =
                  'pending'

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':id' =>
                $connectionId,

            ':user_id' =>
                $userId

        ]
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI REJECT CONNECTION UPDATE] '
        .
        $e->getMessage()
    );


    rejectConnectionResponse(
        false,
        'Unable to reject the connection request.',
        [
            'code' =>
                'REJECT_FAILED'
        ],
        500
    );
}


if (
    $stmt->rowCount() !==
    1
) {

    rejectConnectionResponse(
        false,
        'The request could not be rejected. It may have already changed.',
        [
            'code' =>
                'REJECT_NOT_UPDATED'
        ],
        409
    );
}


/* ============================================================
   OPTIONAL NOTIFICATION
============================================================ */

try {

    $typeStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM notification_types

            WHERE slug =
                'connection_rejected'

               OR slug =
                'new_connection'

            ORDER BY
                CASE
                    WHEN slug =
                        'connection_rejected'
                    THEN 0
                    ELSE 1
                END

            LIMIT 1
            "
        );


    $typeStmt->execute();


    $notificationTypeId =
        $typeStmt->fetchColumn();


    /*
     * Only send rejection notification when there is a
     * dedicated notification type. This avoids incorrectly
     * labeling it as a new connection.
     */

    if (
        $notificationTypeId
    ) {

        $message =
            'Your LOVEMI connection request was not accepted.';


        $notificationStmt =
            $pdo->prepare(
                "
                INSERT INTO notifications
                (
                    user_id,
                    notification_type_id,
                    sender_id,
                    title,
                    message,
                    reference_type,
                    reference_id
                )
                VALUES
                (
                    :user_id,
                    :notification_type_id,
                    :sender_id,
                    'Connection Update',
                    :message,
                    'connection',
                    :reference_id
                )
                "
            );


        $notificationStmt->execute(
            [

                ':user_id' =>
                    (int)
                    $connection['user_id'],

                ':notification_type_id' =>
                    (int)
                    $notificationTypeId,

                ':sender_id' =>
                    $userId,

                ':message' =>
                    $message,

                ':reference_id' =>
                    $connectionId

            ]
        );
    }

} catch (Throwable $e) {

    /*
     * Connection rejection already succeeded.
     * Notification failure should not undo it.
     */

    error_log(
        '[LOVEMI REJECT CONNECTION NOTIFICATION] '
        .
        $e->getMessage()
    );
}


/* ============================================================
   RESPONSE
============================================================ */

rejectConnectionResponse(
    true,
    'Connection request rejected.',
    [

        'connection_id' =>
            $connectionId,

        'status' =>
            'rejected'

    ]
);