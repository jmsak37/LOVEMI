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


function conversationDeleteResponse(
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

    conversationDeleteResponse(
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


$conversationId =
    (int)(
        $data['conversation_id']
        ??
        0
    );


if (
    $conversationId <= 0
) {

    conversationDeleteResponse(
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

    conversationDeleteResponse(
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

    conversationDeleteResponse(
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


    if (
        !$auth->fetch()
    ) {

        conversationDeleteResponse(
            false,
            'You do not have permission to delete conversations.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    conversationDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| LOAD CONVERSATION
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                connection_id,

                user_one_id,

                user_two_id,

                status,

                created_at,

                updated_at

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

    conversationDeleteResponse(
        false,
        'Unable to load the conversation.',
        [],
        500
    );

}


if (
    !$conversation
) {

    conversationDeleteResponse(
        false,
        'Conversation not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| DELETE
|--------------------------------------------------------------------------
|
| Messages reference conversations with ON DELETE CASCADE in the
| saved schema, so deleting the conversation also removes the
| messages belonging to it. :contentReference[oaicite:3]{index=3}
|
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
                    'conversation_deleted',
                    'conversation',
                    :entity_id,
                    :old_values,
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

            ':old_values' =>
                json_encode(
                    $conversation
                ),

            ':new_values' =>
                json_encode(
                    [
                        'deleted' =>
                            true
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
            '[LOVEMI CONVERSATION DELETE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    /*
    |--------------------------------------------------------------------------
    | DELETE CONVERSATION
    |--------------------------------------------------------------------------
    */

    $delete =
        $pdo->prepare(
            "
            DELETE FROM conversations

            WHERE
                id = :conversation_id

            LIMIT 1
            "
        );


    $delete->execute([
        ':conversation_id' =>
            $conversationId
    ]);


    if (
        $delete->rowCount() !== 1
    ) {

        throw new RuntimeException(
            'Conversation could not be deleted.'
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
        '[LOVEMI CONVERSATION DELETE] '
        .
        $e->getMessage()
    );


    conversationDeleteResponse(
        false,
        'Unable to delete the conversation.',
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
        '[LOVEMI DELETE CONVERSATION ACTIVITY] '
        .
        $e->getMessage()
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

conversationDeleteResponse(
    true,
    'Conversation deleted successfully.',
    [

        'conversation_id' =>
            $conversationId,

        'deleted' =>
            true

    ]
);