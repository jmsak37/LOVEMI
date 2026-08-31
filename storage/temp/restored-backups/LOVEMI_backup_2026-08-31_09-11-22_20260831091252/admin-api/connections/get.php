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


function connectionGetResponse(
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


$connectionId =
    (int)(
        $_GET['id'] ?? 0
    );


if ($connectionId <= 0) {

    connectionGetResponse(
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

    connectionGetResponse(
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


try {

    $pdo = db();

} catch (Throwable $e) {

    connectionGetResponse(
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

    $authStmt =
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

    $authStmt->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    if (
        !$authStmt->fetch()
    ) {

        connectionGetResponse(
            false,
            'You do not have permission to manage connections.',
            [
                'code' =>
                    'PERMISSION_DENIED'
            ],
            403
        );

    }

} catch (Throwable $e) {

    connectionGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| GET CONNECTION
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                c.id,

                c.user_id,

                c.connected_user_id,

                c.initiated_by,

                c.status,

                c.connected_at,

                c.created_at,

                c.updated_at,

                u1.username
                    AS user_one_username,

                u1.full_names
                    AS user_one_full_name,

                u1.gender
                    AS user_one_gender,

                u1.email
                    AS user_one_email,

                u1.phone_number
                    AS user_one_phone,

                u1.phone_e164
                    AS user_one_phone_e164,

                u2.username
                    AS user_two_username,

                u2.full_names
                    AS user_two_full_name,

                u2.gender
                    AS user_two_gender,

                u2.email
                    AS user_two_email,

                u2.phone_number
                    AS user_two_phone,

                u2.phone_e164
                    AS user_two_phone_e164,

                iu.username
                    AS initiated_by_username,

                c1.name
                    AS user_one_country,

                c2.name
                    AS user_two_country,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = c.user_id

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

                        ph.user_id =
                            c.connected_user_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS user_two_avatar

            FROM connections c

            INNER JOIN users u1
                ON u1.id = c.user_id

            INNER JOIN users u2
                ON u2.id = c.connected_user_id

            INNER JOIN users iu
                ON iu.id = c.initiated_by

            LEFT JOIN countries c1
                ON c1.id = u1.country_id

            LEFT JOIN countries c2
                ON c2.id = u2.country_id

            WHERE
                c.id = :connection_id

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

    error_log(
        '[LOVEMI CONNECTION GET] ' .
        $e->getMessage()
    );

    connectionGetResponse(
        false,
        'Unable to load connection.',
        [],
        500
    );
}


if (
    !$connection
) {

    connectionGetResponse(
        false,
        'Connection not found.',
        [],
        404
    );
}


connectionGetResponse(
    true,
    'Connection loaded successfully.',
    [
        'connection' =>
            $connection
    ]
);