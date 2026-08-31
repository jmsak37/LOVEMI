<?php
/**
 * ============================================================
 * LOVEMI - DELETE MESSAGE API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "message_id": 45
 * }
 *
 * The message is hidden from the authenticated user's
 * conversation only.
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


/* ============================================================
   RESPONSE
============================================================ */

function deleteMessageResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    deleteMessageResponse(
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
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    deleteMessageResponse(
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


$messageId =
    isset(
        $input['message_id']
    )
        ?
        (int)
        $input['message_id']
        :
        0;


if (
    $messageId <= 0
) {

    deleteMessageResponse(
        false,
        'Message ID is required.',
        [
            'code' =>
                'MESSAGE_ID_REQUIRED'
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
        '[LOVEMI DELETE MESSAGE DB] '
        .
        $e->getMessage()
    );


    deleteMessageResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   LOAD MESSAGE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                conversation_id,
                sender_id,
                receiver_id,

                deleted_by_sender,
                deleted_by_receiver

            FROM messages

            WHERE id =
                :message_id

              AND
              (
                  sender_id =
                      :user_one

                  OR

                  receiver_id =
                      :user_two
              )

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':message_id' =>
                $messageId,

            ':user_one' =>
                $userId,

            ':user_two' =>
                $userId

        ]
    );


    $message =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DELETE MESSAGE LOOKUP] '
        .
        $e->getMessage()
    );


    deleteMessageResponse(
        false,
        'Unable to find the message.',
        [
            'code' =>
                'MESSAGE_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$message
) {

    deleteMessageResponse(
        false,
        'Message not found or access denied.',
        [
            'code' =>
                'MESSAGE_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   DETERMINE SIDE
============================================================ */

$isSender =
    (int)
    $message['sender_id']
    ===
    $userId;


$isReceiver =
    (int)
    $message['receiver_id']
    ===
    $userId;


/* ============================================================
   UPDATE
============================================================ */

try {

    if (
        $isSender
    ) {

        $stmt =
            $pdo->prepare(
                "
                UPDATE messages

                SET
                    deleted_by_sender = 1

                WHERE id =
                    :message_id

                  AND sender_id =
                    :sender_id

                  AND deleted_by_sender = 0

                LIMIT 1
                "
            );


        $stmt->execute(
            [

                ':message_id' =>
                    $messageId,

                ':sender_id' =>
                    $userId

            ]
        );


        $deletedFor =
            'sender';


    } elseif (
        $isReceiver
    ) {

        $stmt =
            $pdo->prepare(
                "
                UPDATE messages

                SET
                    deleted_by_receiver = 1

                WHERE id =
                    :message_id

                  AND receiver_id =
                    :receiver_id

                  AND deleted_by_receiver = 0

                LIMIT 1
                "
            );


        $stmt->execute(
            [

                ':message_id' =>
                    $messageId,

                ':receiver_id' =>
                    $userId

            ]
        );


        $deletedFor =
            'receiver';


    } else {

        deleteMessageResponse(
            false,
            'You cannot delete this message.',
            [
                'code' =>
                    'DELETE_NOT_ALLOWED'
            ],
            403
        );

    }


    $updated =
        $stmt->rowCount();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DELETE MESSAGE UPDATE] '
        .
        $e->getMessage()
    );


    deleteMessageResponse(
        false,
        'Unable to delete the message.',
        [
            'code' =>
                'MESSAGE_DELETE_FAILED'
        ],
        500
    );
}


/* ============================================================
   FULL CLEANUP
============================================================ */

/*
 * If both sides have deleted their copy, physically remove the
 * row. This preserves the per-user delete behavior while
 * preventing unnecessary permanent storage forever.
 */

if (
    (
        (
            $isSender
            &&
            (int)
            $message['deleted_by_receiver']
            ===
            1
        )
        ||
        (
            $isReceiver
            &&
            (int)
            $message['deleted_by_sender']
            ===
            1
        )
    )
) {

    try {

        $cleanupStmt =
            $pdo->prepare(
                "
                DELETE FROM messages

                WHERE id =
                    :message_id

                  AND deleted_by_sender = 1

                  AND deleted_by_receiver = 1

                LIMIT 1
                "
            );


        $cleanupStmt->execute(
            [
                ':message_id' =>
                    $messageId
            ]
        );

    } catch (Throwable $e) {

        /*
         * Cleanup failure does not invalidate the user's delete.
         */

        error_log(
            '[LOVEMI DELETE MESSAGE CLEANUP] '
            .
            $e->getMessage()
        );
    }
}


/* ============================================================
   RESPONSE
============================================================ */

deleteMessageResponse(
    true,
    $updated > 0
        ?
        'Message deleted successfully.'
        :
        'Message was already deleted.',
    [

        'message_id' =>
            $messageId,

        'deleted_for' =>
            $deletedFor

    ]
);