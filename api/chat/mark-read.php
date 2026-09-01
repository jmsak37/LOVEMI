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

function markReadJson(
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

    markReadJson(
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

    markReadJson(
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

$chatCode =
    strtolower(
        trim(
            (string)(
                $input['chat']
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

    markReadJson(
        false,
        'A valid chat code is required.',
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

    markReadJson(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   VERIFY CHAT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                c.id AS conversation_id

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
                        :user_one

                    OR

                    c.user_two_id =
                        :user_two
                )

                AND c.status = 'active'

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':access_code' =>
                $chatCode,

            ':user_one' =>
                $userId,

            ':user_two' =>
                $userId
        ]
    );

    $conversationId =
        $stmt->fetchColumn();

} catch (
    Throwable $e
) {

    markReadJson(
        false,
        'Unable to verify the conversation.',
        [],
        500
    );

}

if (
    !$conversationId
) {

    markReadJson(
        false,
        'Conversation not found or access denied.',
        [],
        404
    );

}


/* ============================================================
   MARK RECEIVED MESSAGES
============================================================ */

try {

    $update =
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

    $update->execute(
        [
            ':conversation_id' =>
                (int)
                $conversationId,

            ':receiver_id' =>
                $userId
        ]
    );

    $updated =
        $update->rowCount();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MARK READ] '
        .
        $e->getMessage()
    );

    markReadJson(
        false,
        'Unable to mark messages as read.',
        [],
        500
    );

}


markReadJson(
    true,
    'Messages marked as read.',
    [
        'conversation_id' =>
            (int)
            $conversationId,

        'updated_messages' =>
            $updated
    ]
);