<?php
/**
 * ============================================================
 * LOVEMI - SEND MESSAGE API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *   "conversation_id": 12,
 *   "message_text": "Hello"
 * }
 *
 * Normal members:
 *   - must be authenticated
 *   - must have active Premium
 *
 * Staff:
 *   - admin / moderator / support can message without Premium
 *
 * The receiver does NOT need Premium to receive messages.
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

function sendMessageResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
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

    sendMessageResponse(
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

    sendMessageResponse(
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


$conversationId =
    (int)
    (
        $input['conversation_id']
        ??
        0
    );


$messageText =
    trim(
        (string)
        (
            $input['message_text']
            ??
            $input['message']
            ??
            ''
        )
    );


$messageType =
    strtolower(
        trim(
            (string)
            (
                $input['message_type']
                ??
                'text'
            )
        )
    );


$allowedTypes = [

    'text'

];


if (
    !in_array(
        $messageType,
        $allowedTypes,
        true
    )
) {

    sendMessageResponse(
        false,
        'This message type is not currently supported.',
        [
            'code' =>
                'MESSAGE_TYPE_NOT_SUPPORTED'
        ],
        422
    );
}


if (
    $conversationId <= 0
) {

    sendMessageResponse(
        false,
        'Conversation ID is required.',
        [
            'code' =>
                'CONVERSATION_ID_REQUIRED'
        ],
        422
    );
}


if (
    $messageText === ''
) {

    sendMessageResponse(
        false,
        'Please enter a message.',
        [
            'code' =>
                'MESSAGE_REQUIRED'
        ],
        422
    );
}


if (
    mb_strlen(
        $messageText
    )
    >
    5000
) {

    sendMessageResponse(
        false,
        'Your message is too long. Maximum 5000 characters.',
        [
            'code' =>
                'MESSAGE_TOO_LONG'
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
        '[LOVEMI SEND MESSAGE DB] '
        .
        $e->getMessage()
    );


    sendMessageResponse(
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
   SENDER ROLE
============================================================ */

try {

    $senderStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.role_id,
                u.account_status,
                u.is_active,
                u.is_suspended,
                u.is_deleted,

                r.slug AS role_slug

            FROM users u

            LEFT JOIN roles r
                ON r.id =
                   u.role_id

            WHERE u.id = :id

            LIMIT 1
            "
        );


    $senderStmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $sender =
        $senderStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SEND MESSAGE SENDER] '
        .
        $e->getMessage()
    );


    sendMessageResponse(
        false,
        'Unable to verify your account.',
        [],
        500
    );
}


if (
    !$sender
) {

    sendMessageResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'SENDER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $sender['is_deleted']
    ===
    1
    ||
    (int)
    $sender['is_suspended']
    ===
    1
    ||
    (int)
    $sender['is_active']
    !==
    1
) {

    sendMessageResponse(
        false,
        'Your account cannot currently send messages.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


$roleSlug =
    strtolower(
        (string)
        (
            $sender['role_slug']
            ??
            ''
        )
    );


$isStaff =
    in_array(
        $roleSlug,
        [
            'admin',
            'moderator',
            'support'
        ],
        true
    );


/* ============================================================
   PREMIUM CHECK
============================================================ */

if (
    !$isStaff
) {

    try {

        $premiumStmt =
            $pdo->prepare(
                "
                SELECT s.id

                FROM subscriptions s

                INNER JOIN services sv
                    ON sv.id =
                       s.service_id

                WHERE s.user_id =
                    :user_id

                  AND s.status =
                    'active'

                  AND s.start_at <= CURRENT_TIMESTAMP

                  AND s.end_at > CURRENT_TIMESTAMP

                  AND sv.is_active = 1

                  AND sv.is_premium = 1

                ORDER BY
                    s.end_at DESC,
                    s.id DESC

                LIMIT 1
                "
            );


        $premiumStmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $premiumId =
            $premiumStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI SEND MESSAGE PREMIUM] '
            .
            $e->getMessage()
        );


        sendMessageResponse(
            false,
            'Unable to verify Premium access.',
            [
                'code' =>
                    'PREMIUM_LOOKUP_FAILED'
            ],
            500
        );
    }


    if (
        !$premiumId
    ) {

        sendMessageResponse(
            false,
            'Premium access is required to send messages.',
            [
                'code' =>
                    'PREMIUM_REQUIRED',

                'redirect' =>
                    'premium.html'
            ],
            403
        );
    }
}


/* ============================================================
   VERIFY CONVERSATION
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                c.id,
                c.status,
                c.user_one_id,
                c.user_two_id,

                CASE
                    WHEN c.user_one_id = :viewer_one
                    THEN c.user_two_id
                    ELSE c.user_one_id
                END AS receiver_id,

                receiver.username
                    AS receiver_username,

                receiver.full_names
                    AS receiver_full_names,

                receiver.is_active
                    AS receiver_active,

                receiver.is_suspended
                    AS receiver_suspended,

                receiver.is_deleted
                    AS receiver_deleted,

                rp.allow_messages

            FROM conversations c

            INNER JOIN users receiver

                ON receiver.id =
                    CASE

                        WHEN c.user_one_id = :viewer_two

                        THEN c.user_two_id

                        ELSE c.user_one_id

                    END

            LEFT JOIN profiles rp
                ON rp.user_id =
                    receiver.id

            WHERE c.id =
                :conversation_id

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
        '[LOVEMI SEND MESSAGE CONVERSATION] '
        .
        $e->getMessage()
    );


    sendMessageResponse(
        false,
        'Unable to verify conversation.',
        [],
        500
    );
}


if (
    !$conversation
) {

    sendMessageResponse(
        false,
        'Conversation not found or access denied.',
        [
            'code' =>
                'CONVERSATION_NOT_FOUND'
        ],
        404
    );
}


if (
    strtolower(
        (string)
        $conversation['status']
    )
    !==
    'active'
) {

    sendMessageResponse(
        false,
        'This conversation is not active.',
        [
            'code' =>
                'CONVERSATION_INACTIVE'
        ],
        403
    );
}


$receiverId =
    (int)
    $conversation['receiver_id'];


if (
    $receiverId <= 0
) {

    sendMessageResponse(
        false,
        'The message recipient could not be determined.',
        [
            'code' =>
                'RECEIVER_NOT_FOUND'
        ],
        500
    );
}


if (
    (int)
    $conversation['receiver_active']
    !==
    1
    ||
    (int)
    $conversation['receiver_suspended']
    ===
    1
    ||
    (int)
    $conversation['receiver_deleted']
    ===
    1
) {

    sendMessageResponse(
        false,
        'The recipient account is unavailable.',
        [
            'code' =>
                'RECEIVER_UNAVAILABLE'
        ],
        403
    );
}


if (
    isset(
        $conversation['allow_messages']
    )
    &&
    (int)
    $conversation['allow_messages']
    !==
    1
    &&
    !$isStaff
) {

    sendMessageResponse(
        false,
        'This member is not accepting messages.',
        [
            'code' =>
                'MESSAGES_DISABLED'
        ],
        403
    );
}


/* ============================================================
   BLOCK CHECK
============================================================ */

try {

    $blockStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM blocked_users

            WHERE
                (
                    user_id =
                        :sender_one

                    AND
                    blocked_user_id =
                        :receiver_one
                )

                OR

                (
                    user_id =
                        :receiver_two

                    AND
                    blocked_user_id =
                        :sender_two
                )

            LIMIT 1
            "
        );


    $blockStmt->execute(
        [

            ':sender_one' =>
                $userId,

            ':receiver_one' =>
                $receiverId,

            ':receiver_two' =>
                $receiverId,

            ':sender_two' =>
                $userId

        ]
    );


    $blocked =
        $blockStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SEND MESSAGE BLOCK] '
        .
        $e->getMessage()
    );


    sendMessageResponse(
        false,
        'Unable to verify messaging safety.',
        [],
        500
    );
}


if (
    $blocked
) {

    sendMessageResponse(
        false,
        'You cannot send messages in this conversation.',
        [
            'code' =>
                'USER_BLOCKED'
        ],
        403
    );
}


/* ============================================================
   INSERT MESSAGE
============================================================ */

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            INSERT INTO messages
            (
                conversation_id,
                sender_id,
                receiver_id,
                message_type,
                message_text
            )
            VALUES
            (
                :conversation_id,
                :sender_id,
                :receiver_id,
                :message_type,
                :message_text
            )
            "
        );


    $stmt->execute(
        [

            ':conversation_id' =>
                $conversationId,

            ':sender_id' =>
                $userId,

            ':receiver_id' =>
                $receiverId,

            ':message_type' =>
                $messageType,

            ':message_text' =>
                $messageText

        ]
    );


    $messageId =
        (int)
        $pdo->lastInsertId();


    /*
     * Touch conversation.
     */

    $touchStmt =
        $pdo->prepare(
            "
            UPDATE conversations

            SET
                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id =
                :conversation_id

            LIMIT 1
            "
        );


    $touchStmt->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );


    /* ========================================================
       MESSAGE NOTIFICATION
    ========================================================= */

    /*
     * Respect recipient's message notification preference.
     */

    $preferenceStmt =
        $pdo->prepare(
            "
            SELECT
                message_notifications

            FROM notification_preferences

            WHERE user_id =
                :user_id

            LIMIT 1
            "
        );


    $preferenceStmt->execute(
        [
            ':user_id' =>
                $receiverId
        ]
    );


    $messageNotifications =
        $preferenceStmt->fetchColumn();


    if (
        $messageNotifications === false
        ||
        (int)
        $messageNotifications
        ===
        1
    ) {

        $typeStmt =
            $pdo->prepare(
                "
                SELECT
                    id

                FROM notification_types

                WHERE slug =
                    'new_message'

                LIMIT 1
                "
            );


        $typeStmt->execute();


        $notificationTypeId =
            $typeStmt->fetchColumn();


        if (
            $notificationTypeId
        ) {

            $audioStmt =
                $pdo->prepare(
                    "
                    SELECT
                        id

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
                        'New Message',
                        :message,
                        'conversation',
                        :conversation_id,
                        :audio_id
                    )
                    "
                );


            $preview =
                mb_substr(
                    $messageText,
                    0,
                    180
                );


            $notificationStmt->execute(
                [

                    ':user_id' =>
                        $receiverId,

                    ':notification_type_id' =>
                        (int)
                        $notificationTypeId,

                    ':sender_id' =>
                        $userId,

                    ':message' =>
                        'You have a new message from '
                        .
                        (
                            $sender['role_slug'] ===
                            'admin'
                                ?
                                'LOVEMI Admin'
                                :
                                $preview
                        ),

                    ':conversation_id' =>
                        $conversationId,

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
    }


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI SEND MESSAGE TRANSACTION] '
        .
        $e->getMessage()
    );


    sendMessageResponse(
        false,
        'Unable to send your message.',
        [
            'code' =>
                'MESSAGE_SEND_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

sendMessageResponse(
    true,
    'Message sent successfully.',
    [

        'message' => [

            'id' =>
                $messageId,

            'conversation_id' =>
                $conversationId,

            'sender_id' =>
                $userId,

            'receiver_id' =>
                $receiverId,

            'message_type' =>
                $messageType,

            'message_text' =>
                $messageText,

            'is_read' =>
                false,

            'created_at' =>
                date(
                    'Y-m-d H:i:s'
                )

        ]

    ],
    201
);