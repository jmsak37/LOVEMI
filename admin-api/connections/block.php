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


function connectionBlockResponse(
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

    connectionBlockResponse(
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


$reason =
    trim(
        (string)(
            $data['reason']
            ??
            'Blocked by administrator'
        )
    );


if ($connectionId <= 0) {

    connectionBlockResponse(
        false,
        'A valid connection ID is required.',
        [],
        422
    );
}


if (
    mb_strlen(
        $reason
    )
    >
    255
) {

    $reason =
        mb_substr(
            $reason,
            0,
            255
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

    connectionBlockResponse(
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

    connectionBlockResponse(
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

        connectionBlockResponse(
            false,
            'You do not have permission to block connections.',
            [],
            403
        );
    }

} catch (Throwable $e) {

    connectionBlockResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| LOAD CONNECTION
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

                status

            FROM connections

            WHERE
                id = :connection_id

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

    connectionBlockResponse(
        false,
        'Unable to load connection.',
        [],
        500
    );
}


if (!$connection) {

    connectionBlockResponse(
        false,
        'Connection not found.',
        [],
        404
    );
}


/*
|--------------------------------------------------------------------------
| PREVENT INVALID USER PAIRS
|--------------------------------------------------------------------------
*/

if (
    (int)
    $connection['user_id']
    ===
    (int)
    $connection['connected_user_id']
) {

    connectionBlockResponse(
        false,
        'Invalid connection pair.',
        [],
        409
    );
}


$userOne =
    (int)
    $connection['user_id'];


$userTwo =
    (int)
    $connection['connected_user_id'];


/*
|--------------------------------------------------------------------------
| BLOCK
|--------------------------------------------------------------------------
|
| blocked_users has a unique user pair. Because the connection
| itself is also retained for administration/history, we update
| its status to "blocked" and create both directional blocks.
|
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | BLOCK USER ONE -> USER TWO
    |--------------------------------------------------------------------------
    */

    $blockOne =
        $pdo->prepare(
            "
            INSERT INTO blocked_users
            (
                user_id,
                blocked_user_id,
                reason
            )
            VALUES
            (
                :user_id,
                :blocked_user_id,
                :reason
            )
            ON DUPLICATE KEY UPDATE
                reason =
                    VALUES(reason)
            "
        );


    $blockOne->execute([
        ':user_id' =>
            $userOne,

        ':blocked_user_id' =>
            $userTwo,

        ':reason' =>
            $reason
    ]);


    /*
    |--------------------------------------------------------------------------
    | BLOCK USER TWO -> USER ONE
    |--------------------------------------------------------------------------
    */

    $blockTwo =
        $pdo->prepare(
            "
            INSERT INTO blocked_users
            (
                user_id,
                blocked_user_id,
                reason
            )
            VALUES
            (
                :user_id,
                :blocked_user_id,
                :reason
            )
            ON DUPLICATE KEY UPDATE
                reason =
                    VALUES(reason)
            "
        );


    $blockTwo->execute([
        ':user_id' =>
            $userTwo,

        ':blocked_user_id' =>
            $userOne,

        ':reason' =>
            $reason
    ]);


    /*
    |--------------------------------------------------------------------------
    | UPDATE CONNECTION STATUS
    |--------------------------------------------------------------------------
    */

    $update =
        $pdo->prepare(
            "
            UPDATE connections

            SET
                status = 'blocked'

            WHERE
                id = :connection_id

            LIMIT 1
            "
        );


    $update->execute([
        ':connection_id' =>
            $connectionId
    ]);


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
                'connection_blocked',
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
            json_encode([
                'status' =>
                    $connection['status']
            ]),

        ':new_values' =>
            json_encode([
                'status' =>
                    'blocked',

                'blocked_user_one' =>
                    $userOne,

                'blocked_user_two' =>
                    $userTwo,

                'reason' =>
                    $reason
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
        '[LOVEMI CONNECTION BLOCK] ' .
        $e->getMessage()
    );


    connectionBlockResponse(
        false,
        'Unable to block this connection.',
        [],
        500
    );
}


connectionBlockResponse(
    true,
    'Connection has been blocked successfully.',
    [

        'connection_id' =>
            $connectionId,

        'status' =>
            'blocked',

        'blocked_users' => [

            $userOne,
            $userTwo

        ]

    ]
);