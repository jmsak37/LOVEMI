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

function chatResponse(
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

    chatResponse(
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

    chatResponse(
        false,
        'Please log in first.',
        [],
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

$targetUserId =
    isset($input['user_id'])
        ? (int) $input['user_id']
        : 0;

if ($targetUserId <= 0) {

    chatResponse(
        false,
        'Invalid member.',
        [],
        422
    );

}

if (
    $targetUserId ===
    $currentUserId
) {

    chatResponse(
        false,
        'You cannot chat with yourself.',
        [],
        422
    );

}

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT DB] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ACCEPTED CONNECTION
============================================================ */

try {

    $connectionStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                connected_user_id,

                status

            FROM connections

            WHERE

                (
                    user_id = :user_one
                    AND
                    connected_user_id = :user_two
                )

                OR

                (
                    user_id = :user_two_b
                    AND
                    connected_user_id = :user_one_b
                )

            ORDER BY id DESC

            LIMIT 1
            "
        );

    $connectionStmt->execute(
        [
            ':user_one' =>
                $currentUserId,

            ':user_two' =>
                $targetUserId,

            ':user_two_b' =>
                $targetUserId,

            ':user_one_b' =>
                $currentUserId
        ]
    );

    $connection =
        $connectionStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT CONNECTION] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to verify the connection.',
        [],
        500
    );

}

if (
    !$connection
    ||
    !in_array(
        strtolower(
            (string)
            $connection['status']
        ),
        [
            'accepted',
            'connected'
        ],
        true
    )
) {

    chatResponse(
        false,
        'You can chat only after the connection has been accepted.',
        [
            'code' =>
                'CONNECTION_REQUIRED'
        ],
        403
    );

}

$connectionId =
    (int)
    $connection['id'];


/* ============================================================
   FIND OR CREATE CONVERSATION
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                connection_id,

                status

            FROM conversations

            WHERE connection_id = :connection_id

            LIMIT 1
            "
        );

    $conversationStmt->execute(
        [
            ':connection_id' =>
                $connectionId
        ]
    );

    $conversation =
        $conversationStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$conversation
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
                    (int)
                    $connection['user_id'],

                ':user_two_id' =>
                    (int)
                    $connection['connected_user_id']
            ]
        );


        $conversation =
            [
                'id' =>
                    (int)
                    $pdo->lastInsertId(),

                'connection_id' =>
                    $connectionId,

                'status' =>
                    'active'
            ];

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT CONVERSATION] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to open the conversation.',
        [],
        500
    );

}

$conversationId =
    (int)
    $conversation['id'];


/* ============================================================
   SUPPORT TABLE
============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS conversation_access_codes
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            conversation_id BIGINT UNSIGNED NOT NULL,

            access_code CHAR(64) NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_used_at DATETIME NULL,

            PRIMARY KEY(id),

            UNIQUE KEY uq_conversation_code
                (access_code),

            UNIQUE KEY uq_conversation_id
                (conversation_id),

            KEY idx_conversation_access_code
                (conversation_id)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT CODE TABLE] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to prepare secure chat codes.',
        [],
        500
    );

}


/* ============================================================
   EXISTING CODE
============================================================ */

try {

    $existingStmt =
        $pdo->prepare(
            "
            SELECT access_code

            FROM conversation_access_codes

            WHERE conversation_id = :conversation_id

            LIMIT 1
            "
        );

    $existingStmt->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );

    $chatCode =
        $existingStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT CODE LOOKUP] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to load the chat code.',
        [],
        500
    );

}


/* ============================================================
   CREATE CODE
============================================================ */

if (
    !is_string($chatCode)
    ||
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $chatCode
    )
) {

    try {

        $chatCode =
            bin2hex(
                random_bytes(
                    32
                )
            );


        $insertCode =
            $pdo->prepare(
                "
                INSERT INTO conversation_access_codes
                (
                    conversation_id,
                    access_code
                )

                VALUES
                (
                    :conversation_id,
                    :access_code
                )
                "
            );

        $insertCode->execute(
            [
                ':conversation_id' =>
                    $conversationId,

                ':access_code' =>
                    $chatCode
            ]
        );

    } catch (Throwable $e) {

        /*
         * Another request may have generated the code first.
         */

        try {

            $retry =
                $pdo->prepare(
                    "
                    SELECT access_code

                    FROM conversation_access_codes

                    WHERE conversation_id =
                        :conversation_id

                    LIMIT 1
                    "
                );

            $retry->execute(
                [
                    ':conversation_id' =>
                        $conversationId
                ]
            );

            $chatCode =
                $retry->fetchColumn();

        } catch (Throwable $retryError) {

            error_log(
                '[LOVEMI CHAT CODE RETRY] '
                .
                $retryError->getMessage()
            );

        }

    }

}


/* ============================================================
   TOUCH CODE
============================================================ */

try {

    $touch =
        $pdo->prepare(
            "
            UPDATE conversation_access_codes

            SET last_used_at =
                CURRENT_TIMESTAMP

            WHERE conversation_id =
                :conversation_id

            LIMIT 1
            "
        );

    $touch->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT CODE TOUCH] '
        .
        $e->getMessage()
    );

}


if (
    !is_string($chatCode)
    ||
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $chatCode
    )
) {

    chatResponse(
        false,
        'A secure chat code could not be created.',
        [],
        500
    );

}


chatResponse(
    true,
    'Conversation ready.',
    [

        'conversation_id' =>
            $conversationId,

        'chat_code' =>
            $chatCode,

        'chat_url' =>
            'messages.html?chat='
            .
            rawurlencode(
                $chatCode
            )

    ]
);