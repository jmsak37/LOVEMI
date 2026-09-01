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

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function actionResponse(
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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    actionResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {

    actionResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED'
        ],
        401
    );

}

$input =
    json_decode(
        file_get_contents('php://input') ?: '{}',
        true
    );

if (!is_array($input)) {
    $input = [];
}

$connectionId =
    isset($input['connection_id'])
        ? (int) $input['connection_id']
        : 0;

$action =
    strtolower(
        trim(
            (string)(
                $input['action']
                ??
                ''
            )
        )
    );

if ($connectionId <= 0) {

    actionResponse(
        false,
        'Invalid connection.',
        [],
        422
    );

}

if (
    !in_array(
        $action,
        [
            'accept',
            'decline',
            'deactivate'
        ],
        true
    )
) {

    actionResponse(
        false,
        'Invalid connection action.',
        [],
        422
    );

}

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION ACTION DB] '
        .
        $e->getMessage()
    );

    actionResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}

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

            WHERE id = :id

              AND
              (
                    user_id = :current_user_one

                    OR

                    connected_user_id = :current_user_two
              )

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':id' =>
                $connectionId,

            ':current_user_one' =>
                $currentUserId,

            ':current_user_two' =>
                $currentUserId
        ]
    );

    $connection =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION ACTION LOAD] '
        .
        $e->getMessage()
    );

    actionResponse(
        false,
        'Unable to load the connection.',
        [],
        500
    );

}

if (!$connection) {

    actionResponse(
        false,
        'The connection was not found.',
        [],
        404
    );

}

$status =
    strtolower(
        (string)
        $connection['status']
    );

$requesterId =
    (int)
    $connection['initiated_by'];

$receiverId =
    $requesterId ===
    (int)$connection['user_id']
        ?
        (int)$connection['connected_user_id']
        :
        (int)$connection['user_id'];

$otherUserId =
    (int)
    $connection['user_id']
    ===
    $currentUserId
        ?
        (int)$connection['connected_user_id']
        :
        (int)$connection['user_id'];


/* ============================================================
   ACCEPT
============================================================ */

if (
    $action === 'accept'
) {

    if (
        $status !== 'pending'
    ) {

        actionResponse(
            false,
            'This request is no longer pending.',
            [
                'code' =>
                    'REQUEST_NOT_PENDING'
            ],
            409
        );

    }


    if (
        $receiverId
        !==
        $currentUserId
    ) {

        actionResponse(
            false,
            'Only the receiving member can accept this request.',
            [
                'code' =>
                    'NOT_REQUEST_RECEIVER'
            ],
            403
        );

    }


    try {

        $pdo->beginTransaction();


        $update =
            $pdo->prepare(
                "
                UPDATE connections

                SET

                    status = 'accepted',

                    connected_at =
                        COALESCE(
                            connected_at,
                            CURRENT_TIMESTAMP
                        ),

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id = :id

                  AND status = 'pending'

                LIMIT 1
                "
            );


        $update->execute(
            [
                ':id' =>
                    $connectionId
            ]
        );


        /*
         * The existing trigger creates conversations only
         * after an INSERT with accepted status.
         *
         * Requests are inserted as pending, so we ensure the
         * conversation exists here after acceptance.
         */

        $conversationTable =
            $pdo->prepare(
                "
                INSERT INTO conversations
                (
                    connection_id,
                    user_one_id,
                    user_two_id,
                    status,
                    created_at,
                    updated_at
                )

                VALUES
                (
                    :connection_id,
                    :user_one_id,
                    :user_two_id,
                    'active',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )

                ON DUPLICATE KEY UPDATE

                    status = 'active',

                    updated_at =
                        CURRENT_TIMESTAMP
                "
            );


        $conversationTable->execute(
            [
                ':connection_id' =>
                    $connectionId,

                ':user_one_id' =>
                    (int)
                    $connection['user_id'],

                ':user_two_id' =>
                    (int)
                    $connection['connected_user_id']
            ]
        );


        $pdo->commit();

    } catch (Throwable $e) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }

        error_log(
            '[LOVEMI CONNECTION ACCEPT] '
            .
            $e->getMessage()
        );

        actionResponse(
            false,
            'The connection could not be accepted.',
            [],
            500
        );

    }


    /*
     * Make sure notification sound 14 exists.
     */

    $audioId =
        null;

    try {

        $audio =
            $pdo->prepare(
                "
                SELECT id

                FROM notification_audio

                WHERE file_name =
                    'notification14.mp3'

                  AND is_active = 1

                LIMIT 1
                "
            );

        $audio->execute();

        $audioId =
            $audio->fetchColumn();


        if (
            !$audioId
        ) {

            $insertAudio =
                $pdo->prepare(
                    "
                    INSERT INTO notification_audio
                    (
                        notification_type_id,
                        name,
                        file_name,
                        file_path,
                        mime_type,
                        sort_order,
                        is_active
                    )

                    VALUES
                    (
                        1,
                        'Connection Accepted',
                        'notification14.mp3',
                        'assets/audio/notification14.mp3',
                        'audio/mpeg',
                        14,
                        1
                    )
                    "
                );

            $insertAudio->execute();

            $audioId =
                $pdo->lastInsertId();

        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CONNECTION ACCEPT AUDIO] '
            .
            $e->getMessage()
        );

    }


    /*
     * Notify the original sender.
     */

    try {

        $notification =
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
                    reference_id,
                    audio_id,
                    is_read,
                    created_at
                )

                VALUES
                (
                    :user_id,
                    1,
                    :sender_id,
                    'Connection Accepted',
                    'Your connection request was accepted.',
                    'connection_accepted',
                    :reference_id,
                    :audio_id,
                    0,
                    CURRENT_TIMESTAMP
                )
                "
            );

        $notification->execute(
            [
                ':user_id' =>
                    $requesterId,

                ':sender_id' =>
                    $currentUserId,

                ':reference_id' =>
                    $connectionId,

                ':audio_id' =>
                    $audioId
                    ?
                    (int)$audioId
                    :
                    null
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CONNECTION ACCEPT NOTIFICATION] '
            .
            $e->getMessage()
        );

    }


    actionResponse(
        true,
        'Connection accepted successfully.',
        [
            'connection_id' =>
                $connectionId,

            'status' =>
                'accepted',

            'other_user_id' =>
                $requesterId
        ]
    );

}


/* ============================================================
   DECLINE
============================================================ */

if (
    $action === 'decline'
) {

    if (
        $status !== 'pending'
    ) {

        actionResponse(
            false,
            'This request is no longer pending.',
            [],
            409
        );

    }


    if (
        $receiverId
        !==
        $currentUserId
    ) {

        actionResponse(
            false,
            'Only the receiving member can decline this request.',
            [
                'code' =>
                    'NOT_REQUEST_RECEIVER'
            ],
            403
        );

    }


    try {

        $update =
            $pdo->prepare(
                "
                UPDATE connections

                SET

                    status = 'rejected',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );

        $update->execute(
            [
                ':id' =>
                    $connectionId
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CONNECTION DECLINE] '
            .
            $e->getMessage()
        );

        actionResponse(
            false,
            'The request could not be declined.',
            [],
            500
        );

    }


    actionResponse(
        true,
        'Connection request declined.',
        [
            'connection_id' =>
                $connectionId,

            'status' =>
                'rejected'
        ]
    );

}


/* ============================================================
   DEACTIVATE / CANCEL
============================================================ */

if (
    $action === 'deactivate'
) {

    if (
        !in_array(
            $status,
            [
                'accepted',
                'connected',
                'pending'
            ],
            true
        )
    ) {

        actionResponse(
            false,
            'This connection is no longer active.',
            [],
            409
        );

    }


    try {

        $pdo->beginTransaction();


        $update =
            $pdo->prepare(
                "
                UPDATE connections

                SET

                    status = 'cancelled',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );

        $update->execute(
            [
                ':id' =>
                    $connectionId
            ]
        );


        /*
         * Deactivate the related conversation if it exists.
         */

        $conversation =
            $pdo->prepare(
                "
                UPDATE conversations

                SET

                    status = 'inactive',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE connection_id = :connection_id

                LIMIT 1
                "
            );

        $conversation->execute(
            [
                ':connection_id' =>
                    $connectionId
            ]
        );


        $pdo->commit();

    } catch (Throwable $e) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }

        error_log(
            '[LOVEMI CONNECTION DEACTIVATE] '
            .
            $e->getMessage()
        );

        actionResponse(
            false,
            'The connection could not be deactivated.',
            [],
            500
        );

    }


    actionResponse(
        true,
        'Connection deactivated successfully.',
        [
            'connection_id' =>
                $connectionId,

            'status' =>
                'cancelled'
        ]
    );

}