<?php
/**
 * ============================================================
 * LOVEMI - CANCEL CONNECTION REQUEST API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "connection_id": 123
 * }
 *
 * Only the original requester can cancel a pending request.
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


function cancelConnectionResponse(
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

    cancelConnectionResponse(
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

    cancelConnectionResponse(
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

    cancelConnectionResponse(
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
        '[LOVEMI CANCEL CONNECTION DB] '
        .
        $e->getMessage()
    );


    cancelConnectionResponse(
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

              AND user_id =
                  :user_id

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


    $connection =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CANCEL CONNECTION LOOKUP] '
        .
        $e->getMessage()
    );


    cancelConnectionResponse(
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

    cancelConnectionResponse(
        false,
        'Connection request not found or access denied.',
        [
            'code' =>
                'CONNECTION_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   INITIATOR CHECK
============================================================ */

if (
    (int)
    $connection['initiated_by']
    !==
    $userId
) {

    cancelConnectionResponse(
        false,
        'Only the person who sent this request can cancel it.',
        [
            'code' =>
                'NOT_REQUEST_INITIATOR'
        ],
        403
    );
}


/* ============================================================
   STATUS
============================================================ */

$status =
    strtolower(
        (string)
        $connection['status']
    );


if (
    $status ===
    'cancelled'
) {

    cancelConnectionResponse(
        true,
        'This connection request has already been cancelled.',
        [
            'already_cancelled' =>
                true
        ]
    );
}


if (
    $status !==
    'pending'
) {

    cancelConnectionResponse(
        false,
        'Only pending requests can be cancelled.',
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
   CANCEL
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            UPDATE connections

            SET
                status = 'cancelled'

            WHERE id =
                :id

              AND user_id =
                  :user_id

              AND initiated_by =
                  :initiated_by

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
                $userId,

            ':initiated_by' =>
                $userId

        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CANCEL CONNECTION UPDATE] '
        .
        $e->getMessage()
    );


    cancelConnectionResponse(
        false,
        'Unable to cancel the connection request.',
        [
            'code' =>
                'CANCEL_FAILED'
        ],
        500
    );
}


if (
    $stmt->rowCount() !==
    1
) {

    cancelConnectionResponse(
        false,
        'The request could not be cancelled. It may have already changed.',
        [
            'code' =>
                'CANCEL_NOT_UPDATED'
        ],
        409
    );
}


/* ============================================================
   RESPONSE
============================================================ */

cancelConnectionResponse(
    true,
    'Connection request cancelled successfully.',
    [

        'connection_id' =>
            $connectionId,

        'status' =>
            'cancelled'

    ]
);