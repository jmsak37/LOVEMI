<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function deleteJson(
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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    deleteJson(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    deleteJson(
        false,
        'Please log in first.',
        [],
        401
    );

}

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );

if (
    !is_array(
        $input
    )
) {

    $input =
        [];

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

    deleteJson(
        false,
        'Message ID is required.',
        [],
        422
    );

}

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE MESSAGE DB] '
        .
        $e->getMessage()
    );

    deleteJson(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   FIND MESSAGE
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
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE MESSAGE LOOKUP] '
        .
        $e->getMessage()
    );

    deleteJson(
        false,
        'Unable to load the message.',
        [],
        500
    );

}

if (
    !$message
) {

    deleteJson(
        false,
        'Message not found or access denied.',
        [],
        404
    );

}


/* ============================================================
   ONLY DELETE OWN COPY
============================================================ */

if (
    (int)
    $message['sender_id']
    ===
    $userId
) {

    try {

        $update =
            $pdo->prepare(
                "
                UPDATE messages

                SET deleted_by_sender = 1

                WHERE id =
                    :message_id

                  AND sender_id =
                    :sender_id

                  AND deleted_by_sender = 0

                LIMIT 1
                "
            );

        $update->execute(
            [
                ':message_id' =>
                    $messageId,

                ':sender_id' =>
                    $userId
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE MESSAGE SENDER] '
            .
            $e->getMessage()
        );

        deleteJson(
            false,
            'Unable to delete the message.',
            [],
            500
        );

    }

} elseif (
    (int)
    $message['receiver_id']
    ===
    $userId
) {

    try {

        $update =
            $pdo->prepare(
                "
                UPDATE messages

                SET deleted_by_receiver = 1

                WHERE id =
                    :message_id

                  AND receiver_id =
                    :receiver_id

                  AND deleted_by_receiver = 0

                LIMIT 1
                "
            );

        $update->execute(
            [
                ':message_id' =>
                    $messageId,

                ':receiver_id' =>
                    $userId
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI DELETE MESSAGE RECEIVER] '
            .
            $e->getMessage()
        );

        deleteJson(
            false,
            'Unable to delete the message.',
            [],
            500
        );

    }

} else {

    deleteJson(
        false,
        'You cannot delete this message.',
        [
            'code' =>
                'DELETE_NOT_ALLOWED'
        ],
        403
    );

}


/* ============================================================
   RESPONSE
============================================================ */

deleteJson(
    true,
    'Message deleted for you.',
    [
        'message_id' =>
            $messageId
    ]
);