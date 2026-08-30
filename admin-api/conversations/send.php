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


function conversationSendResponse(
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


/*
|--------------------------------------------------------------------------
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    conversationSendResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$raw =
    file_get_contents(
        'php://input'
    );


$data =
    json_decode(
        $raw ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data =
        $_POST;

}


$conversationId =
    (int)(
        $data['conversation_id']
        ??
        0
    );


$messageText =
    trim(
        (string)(
            $data['message_text']
            ??
            ''
        )
    );


if (
    $conversationId <= 0
) {

    conversationSendResponse(
        false,
        'A valid conversation ID is required.',
        [],
        422
    );

}


if (
    $messageText === ''
) {

    conversationSendResponse(
        false,
        'Message text is required.',
        [],
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

    conversationSendResponse(
        false,
        'The message is too long.',
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

    conversationSendResponse(
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

    conversationSendResponse(
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
            SELECT

                u.id,

                u.username,

                u.full_names,

                r.name AS role_name

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

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug =
                    'conversations.manage'

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


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    conversationSendResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    conversationSendResponse(
        false,
        'You do not have permission to send administrative messages.',
        [],
        403
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

                id,

                user_one_id,

                user_two_id,

                status

            FROM conversations

            WHERE
                id = :conversation_id

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

    conversationSendResponse(
        false,
        'Unable to load the conversation.',
        [],
        500
    );

}


if (
    !$conversation
) {

    conversationSendResponse(
        false,
        'Conversation not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| ALLOWED STATUS
|--------------------------------------------------------------------------
*/

if (
    in_array(
        strtolower(
            (string)
            $conversation['status']
        ),
        [
            'closed',
            'archived',
            'blocked'
        ],
        true
    )
) {

    conversationSendResponse(
        false,
        'This conversation is not open for new messages.',
        [
            'code' =>
                'CONVERSATION_CLOSED'
        ],
        409
    );

}


/*
|--------------------------------------------------------------------------
| DETERMINE RECEIVER
|--------------------------------------------------------------------------
*/

$receiverId =
    (int)
    $conversation['user_one_id'];


/*
|--------------------------------------------------------------------------
| SEND MESSAGE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $insert =
        $pdo->prepare(
            "
            INSERT INTO messages
            (
                conversation_id,
                sender_id,
                receiver_id,
                message_type,
                message_text,
                is_read
            )
            VALUES
            (
                :conversation_id,
                :sender_id,
                :receiver_id,
                'text',
                :message_text,
                0
            )
            "
        );


    $insert->execute([
        ':conversation_id' =>
            $conversationId,

        ':sender_id' =>
            $adminId,

        ':receiver_id' =>
            $receiverId,

        ':message_text' =>
            $messageText
    ]);


    $messageId =
        (int)
        $pdo->lastInsertId();


    /*
    |--------------------------------------------------------------------------
    | CONVERSATION UPDATED
    |--------------------------------------------------------------------------
    */

    $updateConversation =
        $pdo->prepare(
            "
            UPDATE conversations

            SET
                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :conversation_id

            LIMIT 1
            "
        );


    $updateConversation->execute([
        ':conversation_id' =>
            $conversationId
    ]);


    /*
    |--------------------------------------------------------------------------
    | NOTIFICATION
    |--------------------------------------------------------------------------
    |
    | The receiver is notified that the administrator sent a
    | message. The notification tables already support sender,
    | reference and audio fields.
    |
    */

    try {

        $notification =
            $pdo->prepare(
                "
                INSERT INTO notifications
                (
                    user_id,
                    sender_id,
                    title,
                    message,
                    reference_type,
                    reference_id
                )
                VALUES
                (
                    :user_id,
                    :sender_id,
                    'New Message',
                    :message,
                    'conversation',
                    :conversation_id
                )
                "
            );


        $notification->execute([
            ':user_id' =>
                $receiverId,

            ':sender_id' =>
                $adminId,

            ':message' =>
                'You have a new message from LOVEMI Administration.',

            ':conversation_id' =>
                $conversationId
        ]);

    } catch (
        Throwable $notificationError
    ) {

        /*
         * Do not fail message delivery only because a notification
         * could not be created.
         */

        error_log(
            '[LOVEMI ADMIN MESSAGE NOTIFICATION] '
            .
            $notificationError->getMessage()
        );

    }


    /*
    |--------------------------------------------------------------------------
    | AUDIT
    |--------------------------------------------------------------------------
    */

    try {

        $audit =
            $pdo->prepare(
                "
                INSERT INTO audit_logs
                (
                    user_id,
                    action,
                    entity_type,
                    entity_id,
                    old_values,
                    new_values,
                    ip_address,
                    user_agent
                )
                VALUES
                (
                    :user_id,
                    'admin_send_message',
                    'conversation',
                    :entity_id,
                    NULL,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute([
            ':user_id' =>
                $adminId,

            ':entity_id' =>
                $conversationId,

            ':new_values' =>
                json_encode(
                    [
                        'message_id' =>
                            $messageId
                    ]
                ),

            ':ip' =>
                $_SERVER['REMOTE_ADDR']
                ??
                null,

            ':agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ??
                null
        ]);

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI ADMIN MESSAGE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CONVERSATION SEND] '
        .
        $e->getMessage()
    );


    conversationSendResponse(
        false,
        'Unable to send the message.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ACTIVITY
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
        '[LOVEMI SEND MESSAGE ACTIVITY] '
        .
        $e->getMessage()
    );

}


conversationSendResponse(
    true,
    'Message sent successfully.',
    [

        'message_id' =>
            $messageId,

        'conversation_id' =>
            $conversationId

    ]
);