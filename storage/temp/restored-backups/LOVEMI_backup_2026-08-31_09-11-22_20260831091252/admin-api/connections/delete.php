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

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function connectionDeleteResponse(
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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    connectionDeleteResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );
}


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


$connectionId =
    (int)(
        $data['connection_id']
        ??
        0
    );


if ($connectionId <= 0) {

    connectionDeleteResponse(
        false,
        'A valid connection ID is required.',
        [],
        422
    );
}


$adminId =
    (int)(
        $_SESSION['lovemi_user_id'] ?? 0
    );

$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id'] ?? 0
    );

$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token'] ?? ''
    );


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    connectionDeleteResponse(
        false,
        'You must log in first.',
        [],
        401
    );
}


try {

    $pdo =
        db();

} catch (Throwable $e) {

    connectionDeleteResponse(
        false,
        'Database connection failed.',
        [],
        500
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
                    'connections.manage'

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

        connectionDeleteResponse(
            false,
            'You do not have permission to remove connections.',
            [],
            403
        );
    }

} catch (Throwable $e) {

    connectionDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| LOAD ORIGINAL CONNECTION
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                connected_user_id,

                initiated_by,

                status,

                connected_at,

                created_at

            FROM connections

            WHERE id = :connection_id

            LIMIT 1
            "
        );

    $stmt->execute([
        ':connection_id' =>
            $connectionId
    ]);

    $connection =
        $stmt->fetch();

} catch (Throwable $e) {

    connectionDeleteResponse(
        false,
        'Unable to load connection.',
        [],
        500
    );
}


if (!$connection) {

    connectionDeleteResponse(
        false,
        'Connection not found.',
        [],
        404
    );
}


/*
|--------------------------------------------------------------------------
| REMOVE CONNECTION
|--------------------------------------------------------------------------
|
| The conversations table can reference a connection, so delete
| the connection after removing its connection reference from
| conversations. Messages stay attached to the conversation.
|
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $clearConversation =
        $pdo->prepare(
            "
            UPDATE conversations

            SET
                connection_id = NULL

            WHERE
                connection_id = :connection_id
            "
        );


    $clearConversation->execute([
        ':connection_id' =>
            $connectionId
    ]);


    $delete =
        $pdo->prepare(
            "
            DELETE FROM connections

            WHERE
                id = :connection_id

            LIMIT 1
            "
        );


    $delete->execute([
        ':connection_id' =>
            $connectionId
    ]);


    if (
        $delete->rowCount() !== 1
    ) {

        throw new RuntimeException(
            'Connection could not be deleted.'
        );

    }


    /*
    |--------------------------------------------------------------------------
    | AUDIT
    |--------------------------------------------------------------------------
    */

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
                'connection_deleted',
                'connection',
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
            $connectionId,

        ':old_values' =>
            json_encode(
                $connection
            ),

        ':new_values' =>
            json_encode([
                'deleted' =>
                    true
            ]),

        ':ip' =>
            $_SERVER['REMOTE_ADDR']
            ??
            null,

        ':agent' =>
            $_SERVER['HTTP_USER_AGENT']
            ??
            null
    ]);


    $pdo->commit();

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CONNECTION DELETE] ' .
        $e->getMessage()
    );


    connectionDeleteResponse(
        false,
        'Unable to remove connection.',
        [],
        500
    );
}


connectionDeleteResponse(
    true,
    'Connection removed successfully.',
    [
        'connection_id' =>
            $connectionId,

        'deleted' =>
            true
    ]
);