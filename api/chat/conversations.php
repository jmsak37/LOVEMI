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

function jsonResponse(
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
    'GET'
) {

    jsonResponse(
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

    jsonResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED'
        ],
        401
    );

}

$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                50
            )
        )
    );

$offset =
    max(
        0,
        (int)(
            $_GET['offset']
            ??
            0
        )
    );

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONVERSATIONS DB] '
        .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   CREATE CHAT CODE TABLE
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

            PRIMARY KEY (id),

            UNIQUE KEY uq_conversation_access_code
                (access_code),

            UNIQUE KEY uq_conversation_access_conversation
                (conversation_id)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONVERSATIONS CODE TABLE] '
        .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to prepare conversation access codes.',
        [],
        500
    );

}


/* ============================================================
   LOAD CONVERSATIONS
============================================================ */

try {

    $sql = "
        SELECT

            c.id AS conversation_id,

            c.connection_id,

            c.status,

            c.created_at,

            c.updated_at,

            CASE
                WHEN c.user_one_id = :viewer_one
                    THEN c.user_two_id

                ELSE
                    c.user_one_id

            END AS other_user_id,

            u.username,
            u.full_names,
            u.gender,

            p.display_name,
            p.bio,

            co.name AS country_name

        FROM conversations c

        INNER JOIN users u

            ON u.id =
                CASE
                    WHEN c.user_one_id = :viewer_two
                        THEN c.user_two_id

                    ELSE
                        c.user_one_id

                END

        LEFT JOIN profiles p
            ON p.user_id = u.id

        LEFT JOIN countries co
            ON co.id = u.country_id

        WHERE

            (
                c.user_one_id = :viewer_three

                OR

                c.user_two_id = :viewer_four
            )

            AND c.status = 'active'

            AND u.is_active = 1

            AND u.is_suspended = 0

            AND u.is_deleted = 0

        ORDER BY

            c.updated_at DESC,

            c.id DESC

        LIMIT {$limit}

        OFFSET {$offset}
    ";

    $stmt =
        $pdo->prepare(
            $sql
        );

    $stmt->execute(
        [
            ':viewer_one' =>
                $userId,

            ':viewer_two' =>
                $userId,

            ':viewer_three' =>
                $userId,

            ':viewer_four' =>
                $userId
        ]
    );

    $rows =
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONVERSATIONS QUERY] '
        .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to load conversations.',
        [],
        500
    );

}


$conversations = [];


/* ============================================================
   HELPERS
============================================================ */

function createChatCode(
    PDO $pdo,
    int $conversationId
): string {

    $existing =
        $pdo->prepare(
            "
            SELECT access_code

            FROM conversation_access_codes

            WHERE conversation_id =
                :conversation_id

            LIMIT 1
            "
        );

    $existing->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );

    $code =
        $existing->fetchColumn();


    if (
        is_string($code)
        &&
        preg_match(
            '/^[a-f0-9]{64}$/',
            $code
        )
    ) {

        return $code;

    }


    for (
        $attempt = 0;
        $attempt < 5;
        $attempt++
    ) {

        try {

            $code =
                bin2hex(
                    random_bytes(32)
                );

            $insert =
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

            $insert->execute(
                [
                    ':conversation_id' =>
                        $conversationId,

                    ':access_code' =>
                        $code
                ]
            );

            return $code;

        } catch (
            Throwable $e
        ) {

            /*
             * Another request may have generated it.
             */

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

            $retryCode =
                $retry->fetchColumn();


            if (
                is_string($retryCode)
                &&
                preg_match(
                    '/^[a-f0-9]{64}$/',
                    $retryCode
                )
            ) {

                return $retryCode;

            }

        }

    }

    throw new RuntimeException(
        'Unable to create chat access code.'
    );

}


/* ============================================================
   BUILD CONVERSATIONS
============================================================ */

foreach (
    $rows as $row
) {

    $conversationId =
        (int)
        $row['conversation_id'];

    $otherUserId =
        (int)
        $row['other_user_id'];


    try {

        $chatCode =
            createChatCode(
                $pdo,
                $conversationId
            );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI CONVERSATIONS CHAT CODE] '
            .
            $e->getMessage()
        );

        continue;

    }


    /* ========================================================
       PROFILE PHOTO
    ======================================================== */

    try {

        $photoStmt =
            $pdo->prepare(
                "
                SELECT file_path

                FROM photos

                WHERE user_id =
                    :user_id

                  AND photo_type = 'profile'

                  AND approval_status = 'approved'

                ORDER BY

                    is_primary DESC,

                    uploaded_at DESC,

                    id DESC

                LIMIT 1
                "
            );

        $photoStmt->execute(
            [
                ':user_id' =>
                    $otherUserId
            ]
        );

        $profilePhoto =
            $photoStmt->fetchColumn();

    } catch (
        Throwable $e
    ) {

        $profilePhoto =
            null;

    }


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
                        sender_id = :viewer_sender

                        AND deleted_by_sender = 0
                    )

                    OR

                    (
                        receiver_id = :viewer_receiver

                        AND deleted_by_receiver = 0
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

                ':viewer_sender' =>
                    $userId,

                ':viewer_receiver' =>
                    $userId
            ]
        );

        $last =
            $lastStmt->fetch(
                PDO::FETCH_ASSOC
            );

    } catch (
        Throwable $e
    ) {

        $last =
            null;

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

    } catch (
        Throwable $e
    ) {

        $unread =
            0;

    }


    /* ========================================================
       ONLINE
    ======================================================== */

    $online =
        false;

    try {

        $presence =
            $pdo->prepare(
                "
                SELECT is_online

                FROM user_presence

                WHERE user_id =
                    :user_id

                LIMIT 1
                "
            );

        $presence->execute(
            [
                ':user_id' =>
                    $otherUserId
            ]
        );

        $online =
            (bool)
            $presence->fetchColumn();

    } catch (
        Throwable $e
    ) {

        $online =
            false;

    }


    /* ========================================================
       WHATSAPP EXISTS
    ======================================================== */

    $hasWhatsapp =
        false;

    try {

        $waStmt =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM user_whatsapp_numbers

                WHERE user_id =
                    :user_id

                  AND is_active = 1
                "
            );

        $waStmt->execute(
            [
                ':user_id' =>
                    $otherUserId
            ]
        );

        $hasWhatsapp =
            (int)
            $waStmt->fetchColumn()
            >
            0;

    } catch (
        Throwable $e
    ) {

        /*
         * Table may not have been created yet.
         * The whatsapp API will create it.
         */

        $hasWhatsapp =
            false;

    }


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

        'chat_code' =>
            $chatCode,

        'status' =>
            (string)
            $row['status'],

        'other_user' => [

            'id' =>
                $otherUserId,

            'username' =>
                (string)
                $row['username'],

            'full_names' =>
                (string)
                $row['full_names'],

            'display_name' =>
                $row['display_name']
                ??
                $row['full_names'],

            'gender' =>
                (string)
                $row['gender'],

            'country_name' =>
                $row['country_name'],

            'profile_photo' =>
                $profilePhoto,

            'online' =>
                $online,

            'whatsapp_available' =>
                $hasWhatsapp

        ],

        'unread_count' =>
            $unread,

        'last_message' =>
            $last
                ?
                [
                    'id' =>
                        (int)
                        $last['id'],

                    'sender_id' =>
                        (int)
                        $last['sender_id'],

                    'receiver_id' =>
                        (int)
                        $last['receiver_id'],

                    'message_type' =>
                        $last['message_type'],

                    'message_text' =>
                        $last['message_text'],

                    'attachment_name' =>
                        $last['attachment_name'],

                    'is_read' =>
                        (bool)
                        $last['is_read'],

                    'created_at' =>
                        $last['created_at']
                ]
                :
                null,

        'created_at' =>
            $row['created_at'],

        'updated_at' =>
            $row['updated_at']

    ];

}


jsonResponse(
    true,
    'Conversations loaded successfully.',
    [

        'count' =>
            count(
                $conversations
            ),

        'conversations' =>
            $conversations

    ]
);