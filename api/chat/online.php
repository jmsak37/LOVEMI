<?php
/**
 * ============================================================
 * LOVEMI - ONLINE / PRESENCE API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "action": "heartbeat"
 * }
 *
 * Supported:
 *
 *   heartbeat
 *   online
 *   offline
 *   typing
 *   stop_typing
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

function presenceResponse(
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

    presenceResponse(
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

    presenceResponse(
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


$action =
    strtolower(
        trim(
            (string)
            (
                $input['action']
                ??
                'heartbeat'
            )
        )
    );


$conversationId =
    isset(
        $input['conversation_id']
    )
        ?
        (int)
        $input['conversation_id']
        :
        0;


/* ============================================================
   ALLOWED ACTIONS
============================================================ */

$allowed =
    [

        'heartbeat',
        'online',
        'offline',
        'typing',
        'stop_typing'

    ];


if (
    !in_array(
        $action,
        $allowed,
        true
    )
) {

    presenceResponse(
        false,
        'Invalid presence action.',
        [
            'code' =>
                'INVALID_ACTION'
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
        '[LOVEMI PRESENCE DB] '
        .
        $e->getMessage()
    );


    presenceResponse(
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
   VERIFY ACCOUNT
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id =
                :id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PRESENCE USER] '
        .
        $e->getMessage()
    );


    presenceResponse(
        false,
        'Unable to verify your account.',
        [
            'code' =>
                'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$user
) {

    presenceResponse(
        false,
        'Account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $user['is_deleted']
    ===
    1
    ||
    (int)
    $user['is_suspended']
    ===
    1
    ||
    (int)
    $user['is_active']
    !==
    1
) {

    presenceResponse(
        false,
        'This account cannot update presence.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   CONVERSATION VALIDATION FOR TYPING
============================================================ */

if (
    in_array(
        $action,
        [
            'typing',
            'stop_typing'
        ],
        true
    )
) {

    if (
        $conversationId <= 0
    ) {

        presenceResponse(
            false,
            'Conversation ID is required for typing status.',
            [
                'code' =>
                    'CONVERSATION_ID_REQUIRED'
            ],
            422
        );
    }


    try {

        $conversationStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM conversations

                WHERE id =
                    :conversation_id

                  AND
                  (
                      user_one_id =
                          :user_one

                      OR

                      user_two_id =
                          :user_two
                  )

                  AND status =
                      'active'

                LIMIT 1
                "
            );


        $conversationStmt->execute(
            [

                ':conversation_id' =>
                    $conversationId,

                ':user_one' =>
                    $userId,

                ':user_two' =>
                    $userId

            ]
        );


        $conversationExists =
            $conversationStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PRESENCE CONVERSATION] '
            .
            $e->getMessage()
        );


        presenceResponse(
            false,
            'Unable to verify conversation.',
            [],
            500
        );
    }


    if (
        !$conversationExists
    ) {

        presenceResponse(
            false,
            'Conversation not found or access denied.',
            [
                'code' =>
                    'CONVERSATION_NOT_FOUND'
            ],
            404
        );
    }
}


/* ============================================================
   ACTION VALUES
============================================================ */

$isOnline =
    in_array(
        $action,
        [
            'heartbeat',
            'online',
            'typing'
        ],
        true
    );


$isTyping =
    in_array(
        $action,
        [
            'typing'
        ],
        true
    );


$typingConversation =
    $isTyping
        ? $conversationId
        : null;


/* ============================================================
   UPSERT PRESENCE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO user_presence
            (
                user_id,
                is_online,
                last_seen_at,
                is_typing,
                typing_conversation_id
            )
            VALUES
            (
                :user_id,
                :is_online,
                CURRENT_TIMESTAMP,
                :is_typing,
                :typing_conversation_id
            )

            ON DUPLICATE KEY UPDATE

                is_online =
                    VALUES(is_online),

                last_seen_at =
                    VALUES(last_seen_at),

                is_typing =
                    VALUES(is_typing),

                typing_conversation_id =
                    VALUES(typing_conversation_id)
            "
        );


    $stmt->execute(
        [

            ':user_id' =>
                $userId,

            ':is_online' =>
                $isOnline
                    ? 1
                    : 0,

            ':is_typing' =>
                $isTyping
                    ? 1
                    : 0,

            ':typing_conversation_id' =>
                $typingConversation

        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PRESENCE UPDATE] '
        .
        $e->getMessage()
    );


    presenceResponse(
        false,
        'Unable to update your online status.',
        [
            'code' =>
                'PRESENCE_UPDATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   UPDATE USERS LAST SEEN
============================================================ */

try {

    $userUpdate =
        $pdo->prepare(
            "
            UPDATE users

            SET
                last_seen_at =
                    CURRENT_TIMESTAMP,

                updated_at =
                    updated_at

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $userUpdate->execute(
        [
            ':user_id' =>
                $userId
        ]
    );

} catch (Throwable $e) {

    /*
     * Presence table remains authoritative for online state.
     */
    error_log(
        '[LOVEMI PRESENCE USER LAST SEEN] '
        .
        $e->getMessage()
    );
}


/* ============================================================
   RESPONSE
============================================================ */

presenceResponse(
    true,
    'Presence updated successfully.',
    [

        'user_id' =>
            $userId,

        'online' =>
            $isOnline,

        'typing' =>
            $isTyping,

        'typing_conversation_id' =>
            $typingConversation,

        'timestamp' =>
            date(
                'Y-m-d H:i:s'
            )

    ]
);