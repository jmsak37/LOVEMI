<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - DELETE MESSAGE API
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

function messageDeleteResponse(
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
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    messageDeleteResponse(
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

$data =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data =
        $_POST;

}


$messageId =
    (int)(
        $data['message_id']
        ??
        0
    );


if (
    $messageId <= 0
) {

    messageDeleteResponse(
        false,
        'A valid message ID is required.',
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

    messageDeleteResponse(
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

    messageDeleteResponse(
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

        messageDeleteResponse(
            false,
            'You do not have permission to delete messages.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    messageDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| GET MESSAGE
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                conversation_id,

                sender_id,

                receiver_id,

                message_type,

                message_text,

                attachment_path,

                attachment_name,

                attachment_mime,

                is_read,

                read_at,

                deleted_by_sender,

                deleted_by_receiver,

                created_at

            FROM messages

            WHERE
                id = :message_id

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

} catch (
    Throwable $e
) {

    messageDeleteResponse(
        false,
        'Unable to load the message.',
        [],
        500
    );

}


if (
    !$message
) {

    messageDeleteResponse(
        false,
        'Message not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| DELETE
|--------------------------------------------------------------------------
|
| The messages table is a child of conversations and the schema
| provides cascade deletion from a conversation to its messages.
| Here the administrator intentionally removes one message.
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | AUDIT BEFORE DELETE
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
                    'admin_delete_message',
                    'message',
                    :entity_id,
                    :old_values,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute(
            [
                ':user_id' =>
                    $adminId,

                ':entity_id' =>
                    $messageId,

                ':old_values' =>
                    json_encode(
                        [
                            'conversation_id' =>
                                (int)
                                $message['conversation_id'],

                            'sender_id' =>
                                (int)
                                $message['sender_id'],

                            'receiver_id' =>
                                (int)
                                $message['receiver_id'],

                            'message_type' =>
                                $message['message_type'],

                            'message_text' =>
                                $message['message_text'],

                            'attachment_name' =>
                                $message['attachment_name'],

                            'created_at' =>
                                $message['created_at']
                        ],
                        JSON_UNESCAPED_UNICODE |
                        JSON_UNESCAPED_SLASHES
                    ),

                ':new_values' =>
                    json_encode(
                        [
                            'deleted' =>
                                true
                        ],
                        JSON_UNESCAPED_UNICODE |
                        JSON_UNESCAPED_SLASHES
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null
            ]
        );

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI MESSAGE DELETE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    /*
    |--------------------------------------------------------------------------
    | DELETE MESSAGE
    |--------------------------------------------------------------------------
    */

    $delete =
        $pdo->prepare(
            "
            DELETE FROM messages

            WHERE
                id = :message_id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':message_id' =>
                $messageId
        ]
    );


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'Message could not be deleted.'
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
        '[LOVEMI MESSAGE DELETE] '
        .
        $e->getMessage()
    );


    messageDeleteResponse(
        false,
        'Unable to delete the message.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| UPDATE ADMIN SESSION ACTIVITY
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


    $activity->execute(
        [
            ':session_id' =>
                $sessionId,

            ':user_id' =>
                $adminId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGE DELETE ACTIVITY] '
        .
        $e->getMessage()
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

messageDeleteResponse(
    true,
    'Message deleted successfully.',
    [

        'message_id' =>
            $messageId,

        'deleted' =>
            true

    ]
);