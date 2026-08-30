<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');


$isHttps =
    !empty($_SERVER['HTTPS']) &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);


if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


function conversationGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        [
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;

}


$conversationId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $conversationId <= 0
) {

    conversationGetResponse(
        false,
        'A valid conversation ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| SESSION
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
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    conversationGetResponse(
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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    conversationGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


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

                AND pm.slug = 'conversations.manage'

            LIMIT 1
            "
        );


    $auth->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    if (
        !$auth->fetch()
    ) {

        conversationGetResponse(
            false,
            'You do not have permission to manage conversations.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    conversationGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| CONVERSATION
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                c.id,

                c.connection_id,

                c.user_one_id,

                c.user_two_id,

                c.status,

                c.created_at,

                c.updated_at,

                u1.username
                    AS user_one_username,

                u1.full_names
                    AS user_one_full_name,

                u2.username
                    AS user_two_username,

                u2.full_names
                    AS user_two_full_name,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = c.user_one_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS user_one_avatar,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = c.user_two_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS user_two_avatar

            FROM conversations c

            INNER JOIN users u1
                ON u1.id = c.user_one_id

            INNER JOIN users u2
                ON u2.id = c.user_two_id

            WHERE
                c.id = :conversation_id

            LIMIT 1
            "
        );


    $stmt->execute([
        ':conversation_id' =>
            $conversationId
    ]);


    $conversation =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION GET] '
        .
        $e->getMessage()
    );

    conversationGetResponse(
        false,
        'Unable to load the conversation.',
        [],
        500
    );

}


if (
    !$conversation
) {

    conversationGetResponse(
        false,
        'Conversation not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| MESSAGES
|--------------------------------------------------------------------------
*/

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

                m.deleted_by_sender,

                m.deleted_by_receiver,

                m.created_at,

                sender.username
                    AS sender_username,

                sender.full_names
                    AS sender_name

            FROM messages m

            INNER JOIN users sender
                ON sender.id = m.sender_id

            WHERE

                m.conversation_id =
                    :conversation_id

                AND NOT
                (
                    m.deleted_by_sender = 1
                    AND
                    m.deleted_by_receiver = 1
                )

            ORDER BY

                m.created_at ASC,
                m.id ASC

            LIMIT 500
            "
        );


    $messageStmt->execute([
        ':conversation_id' =>
            $conversationId
    ]);


    $messages =
        $messageStmt->fetchAll();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION MESSAGES] '
        .
        $e->getMessage()
    );

    conversationGetResponse(
        false,
        'Unable to load conversation messages.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| MESSAGE COUNT
|--------------------------------------------------------------------------
*/

try {

    $count =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM messages

            WHERE
                conversation_id =
                    :conversation_id
            "
        );


    $count->execute([
        ':conversation_id' =>
            $conversationId
    ]);


    $messageCount =
        (int)
        $count->fetchColumn();

} catch (
    Throwable $e
) {

    $messageCount = count(
        $messages
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN ID FOR FRONTEND
|--------------------------------------------------------------------------
*/

foreach (
    $messages as &$message
) {

    $message['admin_id'] =
        $adminId;

}


unset(
    $message
);


/*
|--------------------------------------------------------------------------
| UPDATE SESSION
|--------------------------------------------------------------------------
*/

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE

                id = :session_id

                AND user_id = :user_id

            LIMIT 1
            "
        );


    $activity->execute([
        ':session_id' =>
            $sessionId,

        ':user_id' =>
            $adminId
    ]);

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION GET ACTIVITY] '
        .
        $e->getMessage()
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

conversationGetResponse(
    true,
    'Conversation loaded successfully.',
    [

        'conversation' =>
            $conversation,

        'messages' =>
            $messages,

        'message_count' =>
            $messageCount,

        'admin_id' =>
            $adminId

    ]
);