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


/* ============================================================
   RESPONSE
============================================================ */

function typingResponse(
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

    typingResponse(
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
        ? (int)
        $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    typingResponse(
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


$typingInput =
    $input['typing']
    ??
    $input['is_typing']
    ??
    true;


if (
    is_bool(
        $typingInput
    )
) {

    $isTyping =
        $typingInput
            ? 1
            : 0;

} else {

    $isTyping =
        in_array(
            strtolower(
                trim(
                    (string)
                    $typingInput
                )
            ),
            [
                '1',
                'true',
                'yes',
                'on'
            ],
            true
        )
            ? 1
            : 0;

}


if (
    $conversationId <= 0
) {

    typingResponse(
        false,
        'Conversation ID is required.',
        [
            'code' =>
                'CONVERSATION_ID_REQUIRED'
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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI TYPING DB] '
        .
        $e->getMessage()
    );


    typingResponse(
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
   VERIFY CONVERSATION PARTICIPANT
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_one_id,
                user_two_id,
                status

            FROM conversations

            WHERE id =
                :conversation_id

            LIMIT 1
            "
        );


    $conversationStmt->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );


    $conversation =
        $conversationStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI TYPING CONVERSATION] '
        .
        $e->getMessage()
    );


    typingResponse(
        false,
        'Unable to load the conversation.',
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

    typingResponse(
        false,
        'Conversation not found.',
        [
            'code' =>
                'CONVERSATION_NOT_FOUND'
        ],
        404
    );
}


$isParticipant =
    (
        (int)
        $conversation['user_one_id']
        ===
        $userId
    )
    ||
    (
        (int)
        $conversation['user_two_id']
        ===
        $userId
    );


if (
    !$isParticipant
) {

    typingResponse(
        false,
        'You are not a participant in this conversation.',
        [
            'code' =>
                'NOT_CONVERSATION_PARTICIPANT'
        ],
        403
    );
}


/* ============================================================
   CHECK CONVERSATION STATUS
============================================================ */

if (
    !in_array(
        $conversation['status'],
        [
            'active'
        ],
        true
    )
) {

    typingResponse(
        false,
        'Typing is unavailable for this conversation.',
        [
            'code' =>
                'CONVERSATION_NOT_ACTIVE'
        ],
        409
    );
}


/* ============================================================
   UPDATE PRESENCE
============================================================ */

try {

    /*
     * Ensure the presence row exists.
     */

    $ensureStmt =
        $pdo->prepare(
            "
            INSERT INTO user_presence
            (
                user_id,
                is_online,
                is_typing,
                typing_conversation_id
            )
            VALUES
            (
                :user_id,
                1,
                :is_typing,
                :conversation_id
            )

            ON DUPLICATE KEY UPDATE

                is_online = 1,

                is_typing =
                    VALUES(is_typing),

                typing_conversation_id =
                    VALUES(typing_conversation_id)
            "
        );


    $ensureStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':is_typing' =>
                $isTyping,

            ':conversation_id' =>
                $isTyping
                    ? $conversationId
                    : null

        ]
    );


    /*
     * Also refresh last-seen time while actively typing.
     */

    $presenceStmt =
        $pdo->prepare(
            "
            UPDATE user_presence

            SET

                is_online = 1,

                last_seen_at =
                    CURRENT_TIMESTAMP,

                is_typing =
                    :is_typing,

                typing_conversation_id =
                    :typing_conversation_id

            WHERE user_id =
                :user_id

            LIMIT 1
            "
        );


    $presenceStmt->execute(
        [

            ':is_typing' =>
                $isTyping,

            ':typing_conversation_id' =>
                $isTyping
                    ? $conversationId
                    : null,

            ':user_id' =>
                $userId

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI TYPING UPDATE] '
        .
        $e->getMessage()
    );


    typingResponse(
        false,
        'Unable to update typing status.',
        [
            'code' =>
                'TYPING_UPDATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

typingResponse(
    true,
    $isTyping
        ? 'Typing status enabled.'
        : 'Typing status cleared.',
    [

        'conversation_id' =>
            $conversationId,

        'is_typing' =>
            (bool)
            $isTyping,

        'updated_at' =>
            date(
                'Y-m-d H:i:s'
            )

    ]
);