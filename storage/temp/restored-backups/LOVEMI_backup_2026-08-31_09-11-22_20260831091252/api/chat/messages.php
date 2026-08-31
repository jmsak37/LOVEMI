<?php
/**
 * ============================================================
 * LOVEMI - CONVERSATION MESSAGES API
 * ============================================================
 *
 * GET:
 *
 *   messages.php?conversation_id=123
 *
 * Optional:
 *
 *   &limit=50
 *   &before_id=500
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

function messagesResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    messagesResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );
}

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    messagesResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}

$conversationId =
    isset($_GET['conversation_id'])
        ? (int) $_GET['conversation_id']
        : 0;

if ($conversationId <= 0) {

    messagesResponse(
        false,
        'Conversation ID is required.',
        [
            'code' => 'CONVERSATION_ID_REQUIRED'
        ],
        422
    );
}

$limit =
    max(
        1,
        min(
            100,
            (int)
            (
                $_GET['limit']
                ??
                50
            )
        )
    );

$beforeId =
    max(
        0,
        (int)
        (
            $_GET['before_id']
            ??
            0
        )
    );

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MESSAGES DB] ' .
        $e->getMessage()
    );

    messagesResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}

/* ============================================================
   VERIFY CONVERSATION PARTICIPATION
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                c.id,
                c.connection_id,
                c.user_one_id,
                c.user_two_id,
                c.status,

                CASE
                    WHEN c.user_one_id = :viewer_one
                    THEN c.user_two_id
                    ELSE c.user_one_id
                END AS other_user_id,

                ou.username AS other_username,
                ou.full_names AS other_full_names,
                ou.gender AS other_gender,

                p.display_name,
                p.allow_messages,

                up.is_online,
                up.last_seen_at

            FROM conversations c

            INNER JOIN users ou
                ON ou.id =
                    CASE
                        WHEN c.user_one_id = :viewer_two
                        THEN c.user_two_id
                        ELSE c.user_one_id
                    END

            LEFT JOIN profiles p
                ON p.user_id = ou.id

            LEFT JOIN user_presence up
                ON up.user_id = ou.id

            WHERE c.id = :conversation_id

              AND
              (
                  c.user_one_id = :viewer_three
                  OR
                  c.user_two_id = :viewer_four
              )

            LIMIT 1
            "
        );

    $conversationStmt->execute(
        [

            ':viewer_one' =>
                $userId,

            ':viewer_two' =>
                $userId,

            ':viewer_three' =>
                $userId,

            ':viewer_four' =>
                $userId,

            ':conversation_id' =>
                $conversationId

        ]
    );

    $conversation =
        $conversationStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MESSAGES CONVERSATION] ' .
        $e->getMessage()
    );

    messagesResponse(
        false,
        'Unable to verify the conversation.',
        [],
        500
    );
}

if (!$conversation) {

    messagesResponse(
        false,
        'Conversation not found or access denied.',
        [
            'code' => 'CONVERSATION_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   MESSAGES
============================================================ */

try {

    if ($beforeId > 0) {

        $messageStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    conversation_id,
                    sender_id,
                    receiver_id,
                    message_type,
                    message_text,
                    attachment_path,
                    attachment_name,
                    attachment_mime,
                    is_read,
                    read_at,
                    created_at

                FROM messages

                WHERE conversation_id =
                    :conversation_id

                  AND id < :before_id

                  AND
                  (
                      (
                          sender_id = :sender_id_1
                          AND
                          deleted_by_sender = 0
                      )
                      OR
                      (
                          receiver_id = :receiver_id_1
                          AND
                          deleted_by_receiver = 0
                      )
                  )

                ORDER BY
                    id DESC

                LIMIT {$limit}
                "
            );

        $messageStmt->execute(
            [

                ':conversation_id' =>
                    $conversationId,

                ':before_id' =>
                    $beforeId,

                ':sender_id_1' =>
                    $userId,

                ':receiver_id_1' =>
                    $userId

            ]
        );

    } else {

        $messageStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    conversation_id,
                    sender_id,
                    receiver_id,
                    message_type,
                    message_text,
                    attachment_path,
                    attachment_name,
                    attachment_mime,
                    is_read,
                    read_at,
                    created_at

                FROM messages

                WHERE conversation_id =
                    :conversation_id

                  AND
                  (
                      (
                          sender_id = :sender_id_2
                          AND
                          deleted_by_sender = 0
                      )
                      OR
                      (
                          receiver_id = :receiver_id_2
                          AND
                          deleted_by_receiver = 0
                      )
                  )

                ORDER BY
                    id DESC

                LIMIT {$limit}
                "
            );

        $messageStmt->execute(
            [

                ':conversation_id' =>
                    $conversationId,

                ':sender_id_2' =>
                    $userId,

                ':receiver_id_2' =>
                    $userId

            ]
        );

    }

    $rows =
        $messageStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MESSAGES QUERY] ' .
        $e->getMessage()
    );

    messagesResponse(
        false,
        'Unable to load messages.',
        [
            'code' =>
                'MESSAGES_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   CHRONOLOGICAL ORDER
============================================================ */

$rows =
    array_reverse(
        $rows
    );


$messages =
    [];


foreach (
    $rows
    as $row
) {

    $messages[] = [

        'id' =>
            (int)
            $row['id'],

        'conversation_id' =>
            (int)
            $row['conversation_id'],

        'sender_id' =>
            (int)
            $row['sender_id'],

        'receiver_id' =>
            (int)
            $row['receiver_id'],

        'from_me' =>
            (int)
            $row['sender_id']
            ===
            $userId,

        'message_type' =>
            $row['message_type'],

        'message_text' =>
            $row['message_text'],

        'attachment' => [

            'path' =>
                $row['attachment_path'],

            'name' =>
                $row['attachment_name'],

            'mime_type' =>
                $row['attachment_mime']

        ],

        'is_read' =>
            (bool)
            $row['is_read'],

        'read_at' =>
            $row['read_at'],

        'created_at' =>
            $row['created_at']

    ];

}


/* ============================================================
   UNREAD COUNT
============================================================ */

try {

    $unreadStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM messages

            WHERE conversation_id =
                :conversation_id

              AND receiver_id =
                :receiver_id

              AND is_read = 0

              AND deleted_by_receiver = 0
            "
        );

    $unreadStmt->execute(
        [

            ':conversation_id' =>
                $conversationId,

            ':receiver_id' =>
                $userId

        ]
    );

    $unreadCount =
        (int)
        $unreadStmt->fetchColumn();

} catch (Throwable $e) {

    $unreadCount =
        0;
}


/* ============================================================
   RESPONSE
============================================================ */

$isOtherOnline =
    (bool)
    $conversation['is_online'];


if (
    !empty(
        $conversation['last_seen_at']
    )
) {

    $lastSeen =
        strtotime(
            (string)
            $conversation['last_seen_at']
        );

    if (
        $lastSeen !== false
        &&
        (
            time()
            -
            $lastSeen
        )
        <= 300
    ) {

        $isOtherOnline =
            true;

    }

}


messagesResponse(
    true,
    'Messages loaded successfully.',
    [

        'conversation' => [

            'id' =>
                (int)
                $conversation['id'],

            'connection_id' =>
                $conversation['connection_id'] !== null
                    ?
                    (int)
                    $conversation['connection_id']
                    :
                    null,

            'status' =>
                $conversation['status']

        ],

        'other_user' => [

            'id' =>
                (int)
                $conversation['other_user_id'],

            'username' =>
                $conversation['other_username'],

            'full_names' =>
                $conversation['other_full_names'],

            'display_name' =>
                $conversation['display_name']
                ??
                $conversation['other_full_names'],

            'gender' =>
                $conversation['other_gender'],

            'online' =>
                $isOtherOnline,

            'last_seen_at' =>
                $conversation['last_seen_at']

        ],

        'messages' =>
            $messages,

        'unread_count' =>
            $unreadCount,

        'pagination' => [

            'limit' =>
                $limit,

            'before_id' =>
                $beforeId,

            'has_more' =>
                count($rows) >= $limit

        ]

    ]
);