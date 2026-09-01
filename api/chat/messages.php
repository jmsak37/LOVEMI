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


/* ============================================================
   RESPONSE
============================================================ */

function messagesJson(
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
    'GET'
) {

    messagesJson(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

}


/* ============================================================
   AUTH
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    messagesJson(
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
   CHAT CODE
============================================================ */

$chatCode =
    strtolower(
        trim(
            (string)(
                $_GET['chat']
                ??
                ''
            )
        )
    );


if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $chatCode
    )
) {

    messagesJson(
        false,
        'A valid chat code is required.',
        [
            'code' =>
                'INVALID_CHAT_CODE'
        ],
        422
    );

}


/* ============================================================
   LIMIT
============================================================ */

$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                100
            )
        )
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGES DB] '
        .
        $e->getMessage()
    );

    messagesJson(
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
   RESOLVE CHAT CODE
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                cac.access_code,

                c.id AS conversation_id,

                c.connection_id,

                c.user_one_id,

                c.user_two_id,

                c.status,

                CASE

                    WHEN c.user_one_id = :current_user_one

                        THEN c.user_two_id

                    ELSE

                        c.user_one_id

                END AS other_user_id

            FROM conversation_access_codes cac

            INNER JOIN conversations c

                ON c.id =
                    cac.conversation_id

            WHERE

                cac.access_code =
                    :access_code

              AND

                (
                    c.user_one_id =
                        :current_user_two

                    OR

                    c.user_two_id =
                        :current_user_three
                )

              AND c.status = 'active'

            LIMIT 1
            "
        );


    $conversationStmt->execute(
        [

            ':current_user_one' =>
                $currentUserId,

            ':access_code' =>
                $chatCode,

            ':current_user_two' =>
                $currentUserId,

            ':current_user_three' =>
                $currentUserId

        ]
    );


    $conversation =
        $conversationStmt->fetch(
            PDO::FETCH_ASSOC
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGES CHAT LOOKUP] '
        .
        $e->getMessage()
    );

    messagesJson(
        false,
        'Unable to verify this conversation.',
        [
            'code' =>
                'CONVERSATION_LOOKUP_FAILED'
        ],
        500
    );

}


if (
    !$conversation
) {

    messagesJson(
        false,
        'Conversation not found or access denied.',
        [
            'code' =>
                'CONVERSATION_NOT_FOUND'
        ],
        404
    );

}


$conversationId =
    (int)
    $conversation['conversation_id'];


$otherUserId =
    (int)
    $conversation['other_user_id'];


/* ============================================================
   UPDATE CHAT CODE USAGE
============================================================ */

try {

    $touch =
        $pdo->prepare(
            "
            UPDATE conversation_access_codes

            SET last_used_at =
                CURRENT_TIMESTAMP

            WHERE access_code =
                :access_code

            LIMIT 1
            "
        );


    $touch->execute(
        [
            ':access_code' =>
                $chatCode
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CODE TOUCH] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   OTHER USER
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.gender,

                p.display_name,

                p.bio,

                up.is_online,

                up.last_seen_at,

                (
                    SELECT
                        ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id =
                            u.id

                      AND ph.photo_type =
                            'profile'

                      AND ph.approval_status =
                            'approved'

                    ORDER BY

                        ph.is_primary DESC,

                        ph.uploaded_at DESC,

                        ph.id DESC

                    LIMIT 1

                ) AS profile_photo

            FROM users u

            LEFT JOIN profiles p

                ON p.user_id =
                    u.id

            LEFT JOIN user_presence up

                ON up.user_id =
                    u.id

            WHERE

                u.id =
                    :user_id

              AND u.is_active = 1

              AND u.is_suspended = 0

              AND u.is_deleted = 0

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $otherUserId
        ]
    );


    $otherUser =
        $userStmt->fetch(
            PDO::FETCH_ASSOC
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGES USER] '
        .
        $e->getMessage()
    );

    messagesJson(
        false,
        'Unable to load member information.',
        [
            'code' =>
                'OTHER_USER_LOAD_FAILED'
        ],
        500
    );

}


if (
    !$otherUser
) {

    messagesJson(
        false,
        'The connected member is no longer available.',
        [
            'code' =>
                'OTHER_USER_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   PROFILE PHOTO
============================================================ */

$profilePhoto =
    $otherUser['profile_photo']
        ??
        null;


/* ============================================================
   WHATSAPP AVAILABLE
============================================================ */

$whatsappAvailable =
    false;


try {

    $waTable =
        $pdo->query(
            "
            SHOW TABLES LIKE
                'user_whatsapp_numbers'
            "
        );


    if (
        $waTable
        &&
        $waTable->fetch()
    ) {

        $waStmt =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM user_whatsapp_numbers

                WHERE

                    user_id =
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


        $whatsappAvailable =
            (int)
            $waStmt->fetchColumn()
            >
            0;

    }

} catch (
    Throwable $e
) {

    $whatsappAvailable =
        false;

}


/* ============================================================
   LOAD MESSAGES
============================================================ */

try {

    $messageStmt =
        $pdo->prepare(
            "
            SELECT

                m.id,

                m.conversation_id,

                m.sender_id,

                m.receiver_id,

                m.message_type,

                m.message_text,

                m.attachment_path,

                m.attachment_name,

                m.attachment_mime,

                m.is_read,

                m.read_at,

                m.created_at

            FROM messages m

            WHERE

                m.conversation_id =
                    :conversation_id

              AND

                (
                    (
                        m.sender_id =
                            :viewer_sender

                        AND

                        m.deleted_by_sender = 0
                    )

                    OR

                    (
                        m.receiver_id =
                            :viewer_receiver

                        AND

                        m.deleted_by_receiver = 0
                    )
                )

            ORDER BY

                m.id DESC

            LIMIT {$limit}
            "
        );


    $messageStmt->execute(
        [

            ':conversation_id' =>
                $conversationId,

            ':viewer_sender' =>
                $currentUserId,

            ':viewer_receiver' =>
                $currentUserId

        ]
    );


    $rows =
        $messageStmt->fetchAll(
            PDO::FETCH_ASSOC
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGES QUERY] '
        .
        $e->getMessage()
    );

    messagesJson(
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
   REVERSE TO CHRONOLOGICAL ORDER
============================================================ */

$rows =
    array_reverse(
        $rows
    );


/* ============================================================
   LOAD REPLY INFORMATION WHEN TABLE EXISTS
============================================================ */

$replyMap = [];


try {

    $replyTable =
        $pdo->query(
            "
            SHOW TABLES LIKE
                'message_replies'
            "
        );


    if (
        $replyTable
        &&
        $replyTable->fetch()
        &&
        count($rows) > 0
    ) {

        $messageIds =
            array_map(
                static function (
                    array $row
                ): int {

                    return (int)
                        $row['id'];

                },
                $rows
            );


        $placeholders =
            implode(
                ',',
                array_fill(
                    0,
                    count($messageIds),
                    '?'
                )
            );


        $replyStmt =
            $pdo->prepare(
                "
                SELECT

                    mr.message_id,

                    mr.reply_to_message_id,

                    replied.message_text,

                    replied.attachment_name

                FROM message_replies mr

                LEFT JOIN messages replied

                    ON replied.id =
                        mr.reply_to_message_id

                WHERE

                    mr.message_id IN
                    (
                        {$placeholders}
                    )
                "
            );


        $replyStmt->execute(
            $messageIds
        );


        while (
            $replyRow =
                $replyStmt->fetch(
                    PDO::FETCH_ASSOC
                )
        ) {

            $replyMap[
                (int)
                $replyRow['message_id']
            ] =
                [

                    'id' =>
                        (int)
                        $replyRow[
                            'reply_to_message_id'
                        ],

                    'message_text' =>
                        $replyRow[
                            'message_text'
                        ],

                    'attachment_name' =>
                        $replyRow[
                            'attachment_name'
                        ]

                ];

        }

    }

} catch (
    Throwable $e
) {

    /*
     * Replies are optional.
     * Message loading must continue.
     */

    error_log(
        '[LOVEMI REPLY LOAD] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   FORMAT MESSAGES
============================================================ */

$messages =
    [];


foreach (
    $rows as $row
) {

    $attachment =
        null;


    if (
        !empty(
            $row['attachment_path']
        )
    ) {

        $attachment =
            [

                'path' =>
                    (string)
                    $row['attachment_path'],

                'name' =>
                    $row['attachment_name']
                    !==
                    null
                        ?
                        (string)
                        $row['attachment_name']
                        :
                        'Attachment',

                'mime_type' =>
                    $row['attachment_mime']
                    !==
                    null
                        ?
                        (string)
                        $row['attachment_mime']
                        :
                        'application/octet-stream'

            ];

    }


    $messageId =
        (int)
        $row['id'];


    $messages[] =
        [

            'id' =>
                $messageId,

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
                $currentUserId,

            'message_type' =>
                (string)
                $row['message_type'],

            'message_text' =>
                $row['message_text'],

            'attachment' =>
                $attachment,

            'reply_to' =>
                $replyMap[
                    $messageId
                ]
                ??
                null,

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

            WHERE

                conversation_id =
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
                $currentUserId

        ]
    );


    $unreadCount =
        (int)
        $unreadStmt->fetchColumn();

} catch (
    Throwable $e
) {

    $unreadCount =
        0;

}


/* ============================================================
   IMPORTANT PREMIUM CHECK
============================================================ */

/*
 * LOVEMI messaging rule:
 *
 *     CURRENT USER PREMIUM
 *              OR
 *     OTHER USER PREMIUM
 *              =
 *          CHAT ALLOWED
 *
 * Both users DO NOT need Premium.
 *
 * The subscription MUST:
 *
 *     service slug = lovemi-premium
 *     status       = active
 *     end_at       > current time
 *
 */

$currentUserPremium =
    false;


$otherUserPremium =
    false;


try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT

                s.user_id

            FROM subscriptions s

            INNER JOIN services sv

                ON sv.id =
                    s.service_id

            WHERE

                s.user_id IN
                (
                    :current_user,
                    :other_user
                )

              AND LOWER(
                    TRIM(
                        s.status
                    )
                  ) = 'active'

              AND s.end_at IS NOT NULL

              AND s.end_at >
                    CURRENT_TIMESTAMP

              AND LOWER(
                    TRIM(
                        sv.slug
                    )
                  ) = 'lovemi-premium'

              AND sv.is_premium = 1

              AND sv.is_active = 1

            GROUP BY

                s.user_id
            "
        );


    $premiumStmt->execute(
        [

            ':current_user' =>
                $currentUserId,

            ':other_user' =>
                $otherUserId

        ]
    );


    while (
        $premiumUserId =
            $premiumStmt->fetchColumn()
    ) {

        $premiumUserId =
            (int)
            $premiumUserId;


        if (
            $premiumUserId ===
            $currentUserId
        ) {

            $currentUserPremium =
                true;

        }


        if (
            $premiumUserId ===
            $otherUserId
        ) {

            $otherUserPremium =
                true;

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM ACCESS CHECK] '
        .
        $e->getMessage()
    );

}


/*
 * THIS IS THE IMPORTANT LINE:
 *
 * Either one having Premium is enough.
 */

$canSend =
    $currentUserPremium
    ||
    $otherUserPremium;


/* ============================================================
   ONLINE
============================================================ */

$isOtherOnline =
    (bool)
    (
        $otherUser['is_online']
        ??
        false
    );


if (
    !empty(
        $otherUser['last_seen_at']
    )
) {

    $lastSeenTimestamp =
        strtotime(
            (string)
            $otherUser['last_seen_at']
        );


    if (
        $lastSeenTimestamp !== false
        &&
        (
            time()
            -
            $lastSeenTimestamp
        )
        <=
        300
    ) {

        $isOtherOnline =
            true;

    }

}


/* ============================================================
   RESPONSE
============================================================ */

messagesJson(
    true,
    'Messages loaded successfully.',
    [

        'chat_code' =>
            $chatCode,

        'conversation' =>
            [

                'id' =>
                    $conversationId,

                'connection_id' =>
                    $conversation['connection_id']
                    !==
                    null
                        ?
                        (int)
                        $conversation['connection_id']
                        :
                        null,

                'status' =>
                    (string)
                    $conversation['status']

            ],

        'other_user' =>
            [

                'id' =>
                    $otherUserId,

                'username' =>
                    $otherUser['username'],

                'full_names' =>
                    $otherUser['full_names'],

                'display_name' =>
                    $otherUser['display_name']
                    ??
                    $otherUser['full_names'],

                'gender' =>
                    $otherUser['gender'],

                'bio' =>
                    $otherUser['bio'],

                'profile_photo' =>
                    $profilePhoto,

                'online' =>
                    $isOtherOnline,

                'last_seen_at' =>
                    $otherUser['last_seen_at'],

                'whatsapp_available' =>
                    $whatsappAvailable

            ],

        'premium_access' =>
            [

                'can_send' =>
                    $canSend,

                'current_user_premium' =>
                    $currentUserPremium,

                'other_user_premium' =>
                    $otherUserPremium,

                'rule' =>
                    'Either connected member having active LOVEMI Premium is enough to keep messaging active.',

                'reason' =>
                    $canSend
                        ?
                        null
                        :
                        'Messaging is paused because neither connected member currently has active LOVEMI Premium.'

            ],

        'messages' =>
            $messages,

        'unread_count' =>
            $unreadCount

    ]
);