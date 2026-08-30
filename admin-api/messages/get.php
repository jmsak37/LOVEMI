<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - MESSAGE GET API
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);

ini_set(
    'display_errors',
    '0'
);


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' =>
            0,

        'path' =>
            '/',

        'secure' =>
            $isHttps,

        'httponly' =>
            true,

        'samesite' =>
            'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function messageGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        [
            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| REQUEST
|--------------------------------------------------------------------------
*/

$messageId =
    (int)(
        $_GET['id']
        ??
        0
    );


$conversationId =
    (int)(
        $_GET['conversation_id']
        ??
        0
    );


if (
    $messageId <= 0
    &&
    $conversationId <= 0
) {

    messageGetResponse(
        false,
        'A valid message ID or conversation ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    messageGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN SESSION
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    messageGetResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/*
|--------------------------------------------------------------------------
| ADMIN AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'messages.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [
            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash
        ]
    );


    if (
        !$auth->fetch()
    ) {

        messageGetResponse(
            false,
            'You do not have permission to manage messages.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    messageGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| MESSAGE OR CONVERSATION
|--------------------------------------------------------------------------
*/

try {

    if (
        $messageId > 0
    ) {

        $stmt =
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

                    m.deleted_by_sender,

                    m.deleted_by_receiver,

                    m.created_at,

                    su.username
                        AS sender_username,

                    su.full_names
                        AS sender_full_name,

                    ru.username
                        AS receiver_username,

                    ru.full_names
                        AS receiver_full_name,

                    (
                        SELECT ph.file_path

                        FROM photos ph

                        WHERE

                            ph.user_id = su.id

                            AND ph.photo_type = 'profile'

                            AND ph.is_primary = 1

                            AND ph.approval_status = 'approved'

                        ORDER BY ph.id DESC

                        LIMIT 1

                    ) AS sender_avatar,

                    (
                        SELECT ph.file_path

                        FROM photos ph

                        WHERE

                            ph.user_id = ru.id

                            AND ph.photo_type = 'profile'

                            AND ph.is_primary = 1

                            AND ph.approval_status = 'approved'

                        ORDER BY ph.id DESC

                        LIMIT 1

                    ) AS receiver_avatar

                FROM messages m

                INNER JOIN users su
                    ON su.id = m.sender_id

                INNER JOIN users ru
                    ON ru.id = m.receiver_id

                WHERE
                    m.id = :message_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':message_id' =>
                    $messageId
            ]
        );


        $message =
            $stmt->fetch();


        if (
            !$message
        ) {

            messageGetResponse(
                false,
                'Message not found.',
                [],
                404
            );

        }


        /*
        |--------------------------------------------------------------------------
        | LOAD CONVERSATION MESSAGES
        |--------------------------------------------------------------------------
        */

        $conversationMessages =
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

                    m.created_at,

                    u.username AS sender_username,

                    u.full_names AS sender_full_name

                FROM messages m

                INNER JOIN users u
                    ON u.id = m.sender_id

                WHERE

                    m.conversation_id =
                        :conversation_id

                ORDER BY

                    m.created_at ASC,

                    m.id ASC

                LIMIT 500
                "
            );


        $conversationMessages->execute(
            [
                ':conversation_id' =>
                    (int)
                    $message['conversation_id']
            ]
        );


        $messages =
            $conversationMessages->fetchAll();


        messageGetResponse(
            true,
            'Message loaded successfully.',
            [

                'admin_id' =>
                    $adminId,

                'message' =>
                    $message,

                'messages' =>
                    $messages,

                'message_count' =>
                    count(
                        $messages
                    )

            ]
        );

    }


    /*
    |--------------------------------------------------------------------------
    | CONVERSATION MODE
    |--------------------------------------------------------------------------
    */

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                c.id,

                c.connection_id,

                c.user_one_id,

                c.user_two_id,

                c.status,

                c.created_at,

                c.updated_at

            FROM conversations c

            WHERE
                c.id = :conversation_id

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


    if (
        !$conversation
    ) {

        messageGetResponse(
            false,
            'Conversation not found.',
            [],
            404
        );

    }


    $messagesStmt =
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

                m.deleted_by_sender,

                m.deleted_by_receiver,

                m.created_at,

                u.username AS sender_username,

                u.full_names AS sender_full_name,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = m.sender_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS sender_avatar

            FROM messages m

            INNER JOIN users u
                ON u.id = m.sender_id

            WHERE

                m.conversation_id =
                    :conversation_id

            ORDER BY

                m.created_at ASC,

                m.id ASC

            LIMIT 500
            "
        );


    $messagesStmt->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );


    $messages =
        $messagesStmt->fetchAll();


    messageGetResponse(
        true,
        'Conversation messages loaded successfully.',
        [

            'admin_id' =>
                $adminId,

            'conversation' =>
                $conversation,

            'messages' =>
                $messages,

            'message_count' =>
                count(
                    $messages
                )

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGE GET] '
        .
        $e->getMessage()
    );


    messageGetResponse(
        false,
        'Unable to load the message.',
        [],
        500
    );

}