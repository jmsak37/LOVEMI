<?php
/**
 * ============================================================
 * LOVEMI - ACCEPT CONNECTION API
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


function acceptConnectionResponse(
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

    acceptConnectionResponse(
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

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($currentUserId <= 0) {

    acceptConnectionResponse(
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
        (string) $raw,
        true
    );

if (!is_array($input)) {
    $input = $_POST;
}

$connectionId =
    (int)
    (
        $input['connection_id']
        ??
        0
    );


if ($connectionId <= 0) {

    acceptConnectionResponse(
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

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ACCEPT CONNECTION DB] ' .
        $e->getMessage()
    );

    acceptConnectionResponse(
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

                c.id,

                c.user_id,
                c.connected_user_id,
                c.initiated_by,

                c.status,

                sender.username
                    AS sender_username,

                sender.full_names
                    AS sender_full_names,

                receiver.username
                    AS receiver_username,

                receiver.full_names
                    AS receiver_full_names

            FROM connections c

            INNER JOIN users sender
                ON sender.id =
                   c.user_id

            INNER JOIN users receiver
                ON receiver.id =
                   c.connected_user_id

            WHERE c.id =
                  :connection_id

              AND c.connected_user_id =
                  :current_user_id

            LIMIT 1
            "
        );

    $stmt->execute(
        [

            ':connection_id' =>
                $connectionId,

            ':current_user_id' =>
                $currentUserId

        ]
    );

    $connection =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ACCEPT CONNECTION LOOKUP] ' .
        $e->getMessage()
    );

    acceptConnectionResponse(
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

    acceptConnectionResponse(
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
   STATUS CHECK
============================================================ */

$currentStatus =
    strtolower(
        (string)
        $connection['status']
    );


if (
    $currentStatus ===
    'connected'
    ||
    $currentStatus ===
    'accepted'
) {

    /*
     * Already connected. Return the existing conversation.
     */

    try {

        $conversationStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM conversations

                WHERE user_low_id =
                      LEAST(
                          :user_one,
                          :user_two
                      )

                  AND user_high_id =
                      GREATEST(
                          :user_three,
                          :user_four
                      )

                LIMIT 1
                "
            );

        $conversationStmt->execute(
            [

                ':user_one' =>
                    $currentUserId,

                ':user_two' =>
                    (int)
                    $connection['user_id'],

                ':user_three' =>
                    $currentUserId,

                ':user_four' =>
                    (int)
                    $connection['user_id']

            ]
        );

        $conversationId =
            $conversationStmt->fetchColumn();

    } catch (Throwable $e) {

        $conversationId =
            null;
    }


    acceptConnectionResponse(
        true,
        'This connection is already active.',
        [

            'connection_id' =>
                $connectionId,

            'conversation_id' =>
                $conversationId
                ?
                (int)
                $conversationId
                :
                null,

            'already_connected' =>
                true

        ]
    );
}


if (
    $currentStatus !==
    'pending'
) {

    acceptConnectionResponse(
        false,
        'This connection request cannot be accepted because its current status is not pending.',
        [
            'code' =>
                'INVALID_CONNECTION_STATUS',

            'status' =>
                $currentStatus
        ],
        409
    );
}


/* ============================================================
   ACCEPT TRANSACTION
============================================================ */

$otherUserId =
    (int)
    $connection['user_id'];


try {

    $pdo->beginTransaction();


    /*
     * Update the connection.
     *
     * The database trigger will set connected_at.
     */

    $updateStmt =
        $pdo->prepare(
            "
            UPDATE connections

            SET
                status = 'connected'

            WHERE id =
                :id

              AND connected_user_id =
                  :current_user_id

              AND status =
                  'pending'

            LIMIT 1
            "
        );


    $updateStmt->execute(
        [

            ':id' =>
                $connectionId,

            ':current_user_id' =>
                $currentUserId

        ]
    );


    if (
        $updateStmt->rowCount() !==
        1
    ) {

        throw new RuntimeException(
            'Connection could not be accepted.'
        );

    }


    /*
     * The INSERT trigger does not run for UPDATE, so ensure that
     * a conversation exists.
     */

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM conversations

            WHERE user_low_id =
                  LEAST(
                      :user_one,
                      :user_two
                  )

              AND user_high_id =
                  GREATEST(
                      :user_three,
                      :user_four
                  )

            LIMIT 1
            "
        );


    $conversationStmt->execute(
        [

            ':user_one' =>
                $currentUserId,

            ':user_two' =>
                $otherUserId,

            ':user_three' =>
                $currentUserId,

            ':user_four' =>
                $otherUserId

        ]
    );


    $conversationId =
        $conversationStmt->fetchColumn();


    if (
        !$conversationId
    ) {

        $insertConversation =
            $pdo->prepare(
                "
                INSERT INTO conversations
                (
                    connection_id,
                    user_one_id,
                    user_two_id,
                    status
                )
                VALUES
                (
                    :connection_id,
                    :user_one_id,
                    :user_two_id,
                    'active'
                )
                "
            );


        $insertConversation->execute(
            [

                ':connection_id' =>
                    $connectionId,

                ':user_one_id' =>
                    $currentUserId,

                ':user_two_id' =>
                    $otherUserId

            ]
        );


        $conversationId =
            $pdo->lastInsertId();

    } else {

        $conversationUpdate =
            $pdo->prepare(
                "
                UPDATE conversations

                SET

                    connection_id =
                        :connection_id,

                    status =
                        'active',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :id

                LIMIT 1
                "
            );


        $conversationUpdate->execute(
            [

                ':connection_id' =>
                    $connectionId,

                ':id' =>
                    (int)
                    $conversationId

            ]
        );
    }


    /*
     * Notification type.
     */

    $typeStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM notification_types

            WHERE slug =
                'connection_accepted'

               OR slug =
                'new_connection'

            ORDER BY
                CASE
                    WHEN slug =
                        'connection_accepted'
                    THEN 0
                    ELSE 1
                END

            LIMIT 1
            "
        );


    $typeStmt->execute();


    $notificationTypeId =
        $typeStmt->fetchColumn();


    if (
        $notificationTypeId
    ) {

        /*
         * Notify requester.
         */

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
                    reference_id,
                    audio_id
                )
                VALUES
                (
                    :user_id,
                    :notification_type_id,
                    :sender_id,
                    'Connection Accepted',
                    :message,
                    'connection',
                    :reference_id,
                    :audio_id
                )
                "
            );


        $audioStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM notification_audio

                WHERE notification_type_id =
                    :notification_type_id

                  AND is_active = 1

                ORDER BY
                    sort_order ASC,
                    id ASC

                LIMIT 1
                "
            );


        $audioStmt->execute(
            [
                ':notification_type_id' =>
                    (int)
                    $notificationTypeId
            ]
        );


        $audioId =
            $audioStmt->fetchColumn();


        $notificationStmt->execute(
            [

                ':user_id' =>
                    $otherUserId,

                ':notification_type_id' =>
                    (int)
                    $notificationTypeId,

                ':sender_id' =>
                    $currentUserId,

                ':message' =>
                    'Your LOVEMI connection request has been accepted.',

                ':reference_id' =>
                    $connectionId,

                ':audio_id' =>
                    $audioId
                    ?
                    (int)
                    $audioId
                    :
                    null

            ]
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
        '[LOVEMI ACCEPT CONNECTION TRANSACTION] ' .
        $e->getMessage()
    );


    acceptConnectionResponse(
        false,
        'Unable to accept the connection request.',
        [
            'code' =>
                'ACCEPT_CONNECTION_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

acceptConnectionResponse(
    true,
    'Connection accepted successfully.',
    [

        'connection_id' =>
            $connectionId,

        'conversation_id' =>
            (int)
            $conversationId,

        'connected_user' => [

            'id' =>
                $otherUserId,

            'username' =>
                $connection['sender_username'],

            'full_names' =>
                $connection['sender_full_names']

        ],

        'connected' =>
            true,

        'redirect' =>
            'messages.html?conversation_id='
            .
            (int)
            $conversationId

    ],
    200
);