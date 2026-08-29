<?php
/**
 * ============================================================
 * LOVEMI - MARK CONVERSATION / MESSAGE AS READ
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "conversation_id": 12
 * }
 *
 * OR:
 *
 * {
 *     "message_id": 45
 * }
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

function markReadResponse(
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

    markReadResponse(
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

    markReadResponse(
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
    isset(
        $input['conversation_id']
    )
        ?
        (int)
        $input['conversation_id']
        :
        0;


$messageId =
    isset(
        $input['message_id']
    )
        ?
        (int)
        $input['message_id']
        :
        0;


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MARK READ DB] '
        .
        $e->getMessage()
    );


    markReadResponse(
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
   MESSAGE MODE
============================================================ */

if (
    $messageId > 0
) {

    try {

        $stmt =
            $pdo->prepare(
                "
                UPDATE messages

                SET

                    is_read = 1,

                    read_at =
                        CURRENT_TIMESTAMP

                WHERE id =
                    :message_id

                  AND receiver_id =
                    :receiver_id

                  AND is_read = 0

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


        markReadResponse(
            true,
            'Message marked as read.',
            [
                'message_id' =>
                    $messageId,

                'updated' =>
                    $stmt->rowCount()
            ]
        );


    } catch (Throwable $e) {

        error_log(
            '[LOVEMI MARK MESSAGE READ] '
            .
            $e->getMessage()
        );


        markReadResponse(
            false,
            'Unable to mark the message as read.',
            [
                'code' =>
                    'MESSAGE_READ_FAILED'
            ],
            500
        );

    }
}


/* ============================================================
   CONVERSATION MODE
============================================================ */

if (
    $conversationId <= 0
) {

    markReadResponse(
        false,
        'Conversation ID or message ID is required.',
        [
            'code' =>
                'TARGET_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   VERIFY PARTICIPATION
============================================================ */

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
        '[LOVEMI MARK CONVERSATION VERIFY] '
        .
        $e->getMessage()
    );


    markReadResponse(
        false,
        'Unable to verify the conversation.',
        [
            'code' =>
                'CONVERSATION_VERIFY_FAILED'
        ],
        500
    );
}


if (
    !$conversationExists
) {

    markReadResponse(
        false,
        'Conversation not found or access denied.',
        [
            'code' =>
                'CONVERSATION_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   MARK RECEIVED MESSAGES
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            UPDATE messages

            SET

                is_read = 1,

                read_at =
                    CURRENT_TIMESTAMP

            WHERE conversation_id =
                :conversation_id

              AND receiver_id =
                :receiver_id

              AND is_read = 0

              AND deleted_by_receiver = 0
            "
        );


    $stmt->execute(
        [

            ':conversation_id' =>
                $conversationId,

            ':receiver_id' =>
                $userId

        ]
    );


    $updated =
        $stmt->rowCount();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MARK CONVERSATION READ] '
        .
        $e->getMessage()
    );


    markReadResponse(
        false,
        'Unable to mark conversation messages as read.',
        [
            'code' =>
                'CONVERSATION_READ_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

markReadResponse(
    true,
    'Conversation marked as read.',
    [

        'conversation_id' =>
            $conversationId,

        'updated_messages' =>
            $updated

    ]
);