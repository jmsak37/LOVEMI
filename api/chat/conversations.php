<?php
/**
 * ============================================================
 * LOVEMI - CONVERSATIONS LIST API
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

function conversationsResponse(
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

    conversationsResponse(
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

    conversationsResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONVERSATIONS DB] ' .
        $e->getMessage()
    );

    conversationsResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}

/* ============================================================
   PAGINATION
============================================================ */

$limit =
    max(
        1,
        min(
            100,
            (int)
            (
                $_GET['limit']
                ??
                30
            )
        )
    );

$offset =
    max(
        0,
        (int)
        (
            $_GET['offset']
            ??
            0
        )
    );

/* ============================================================
   CONVERSATIONS
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                c.id AS conversation_id,
                c.connection_id,
                c.status,
                c.created_at,
                c.updated_at,

                CASE
                    WHEN c.user_one_id = :user_one
                    THEN c.user_two_id
                    ELSE c.user_one_id
                END AS other_user_id,

                ou.username AS other_username,
                ou.full_names AS other_full_names,
                ou.gender AS other_gender,

                op.display_name AS other_display_name,
                op.show_online_status AS other_show_online_status,

                up.is_online AS other_is_online,
                up.last_seen_at AS other_last_seen_at

            FROM conversations c

            INNER JOIN users ou
                ON ou.id =
                   CASE
                       WHEN c.user_one_id = :user_two
                       THEN c.user_two_id
                       ELSE c.user_one_id
                   END

            LEFT JOIN profiles op
                ON op.user_id =
                   ou.id

            LEFT JOIN user_presence up
                ON up.user_id =
                   ou.id

            WHERE
                (
                    c.user_one_id = :user_three
                    OR
                    c.user_two_id = :user_four
                )

                AND c.status = 'active'

                AND ou.is_deleted = 0

            ORDER BY
                c.updated_at DESC,
                c.id DESC

            LIMIT {$limit}
            OFFSET {$offset}
            "
        );

    $stmt->execute(
        [

            ':user_one' =>
                $userId,

            ':user_two' =>
                $userId,

            ':user_three' =>
                $userId,

            ':user_four' =>
                $userId

        ]
    );

    $rows =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONVERSATIONS QUERY] ' .
        $e->getMessage()
    );

    conversationsResponse(
        false,
        'Unable to load conversations.',
        [
            'code' =>
                'CONVERSATIONS_QUERY_FAILED'
        ],
        500
    );
}

/* ============================================================
   FORMAT
============================================================ */

$conversations =
    [];


foreach (
    $rows
    as $row
) {

    $conversationId =
        (int)
        $row['conversation_id'];

    $otherUserId =
        (int)
        $row['other_user_id'];


    /* ========================================================
       LAST MESSAGE
    ======================================================== */

    try {

        $lastStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    sender_id,
                    receiver_id,
                    message_type,
                    message_text,
                    attachment_name,
                    is_read,
                    created_at

                FROM messages

                WHERE conversation_id =
                    :conversation_id

                  AND
                  (
                      (
                          sender_id = :owner_sender
                          AND
                          deleted_by_sender = 0
                      )
                      OR
                      (
                          receiver_id = :owner_receiver
                          AND
                          deleted_by_receiver = 0
                      )
                  )

                ORDER BY
                    created_at DESC,
                    id DESC

                LIMIT 1
                "
            );

        $lastStmt->execute(
            [

                ':conversation_id' =>
                    $conversationId,

                ':owner_sender' =>
                    $userId,

                ':owner_receiver' =>
                    $userId

            ]
        );

        $lastMessage =
            $lastStmt->fetch();

    } catch (Throwable $e) {

        $lastMessage =
            false;
    }


    /* ========================================================
       UNREAD
    ======================================================== */

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

        $unread =
            (int)
            $unreadStmt->fetchColumn();

    } catch (Throwable $e) {

        $unread =
            0;
    }


    $isOnline =
        (bool)
        $row['other_is_online'];


    if (
        !empty(
            $row['other_last_seen_at']
        )
    ) {

        $lastSeen =
            strtotime(
                (string)
                $row['other_last_seen_at']
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

            $isOnline =
                true;

        }

    }


    /*
     * Do not expose phone number, ID number, or other private
     * account information here.
     */

    $conversations[] = [

        'conversation_id' =>
            $conversationId,

        'connection_id' =>
            $row['connection_id'] !== null
                ?
                (int)
                $row['connection_id']
                :
                null,

        'status' =>
            $row['status'],

        'other_user' => [

            'id' =>
                $otherUserId,

            'username' =>
                $row['other_username'],

            'full_names' =>
                $row['other_full_names'],

            'display_name' =>
                $row['other_display_name']
                ??
                $row['other_full_names'],

            'gender' =>
                $row['other_gender'],

            'online' =>
                $isOnline,

            'last_seen_at' =>
                $row['other_last_seen_at']

        ],

        'unread_count' =>
            $unread,

        'last_message' =>
            $lastMessage
                ?
                [

                    'id' =>
                        (int)
                        $lastMessage['id'],

                    'sender_id' =>
                        (int)
                        $lastMessage['sender_id'],

                    'message_type' =>
                        $lastMessage['message_type'],

                    'message_text' =>
                        $lastMessage['message_text'],

                    'attachment_name' =>
                        $lastMessage['attachment_name'],

                    'is_read' =>
                        (bool)
                        $lastMessage['is_read'],

                    'created_at' =>
                        $lastMessage['created_at']

                ]
                :
                null,

        'created_at' =>
            $row['created_at'],

        'updated_at' =>
            $row['updated_at']

    ];
}


/* ============================================================
   TOTAL
============================================================ */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM conversations c

            WHERE
                (
                    c.user_one_id = :user_one
                    OR
                    c.user_two_id = :user_two
                )

              AND c.status = 'active'
            "
        );

    $countStmt->execute(
        [

            ':user_one' =>
                $userId,

            ':user_two' =>
                $userId

        ]
    );

    $total =
        (int)
        $countStmt->fetchColumn();

} catch (Throwable $e) {

    $total =
        count($conversations);
}

conversationsResponse(
    true,
    'Conversations loaded successfully.',
    [

        'conversations' =>
            $conversations,

        'pagination' => [

            'total' =>
                $total,

            'limit' =>
                $limit,

            'offset' =>
                $offset,

            'has_more' =>
                (
                    $offset
                    +
                    count($conversations)
                )
                <
                $total

        ]

    ]
);