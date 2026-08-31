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


function connectionsListResponse(
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


try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTIONS LIST DB] ' .
        $e->getMessage()
    );

    connectionsListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

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

    connectionsListResponse(
        false,
        'You must log in first.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
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

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.email,

                r.id AS role_id,
                r.name AS role_name,
                r.slug AS role_slug

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

    $admin =
        $authStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST AUTH] ' .
        $e->getMessage()
    );

    connectionsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


if (!$admin) {

    connectionsListResponse(
        false,
        'You do not have permission to manage connections.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );
}


/*
|--------------------------------------------------------------------------
| AVATAR
|--------------------------------------------------------------------------
*/

try {

    $adminPhotoStmt =
        $pdo->prepare(
            "
            SELECT file_path

            FROM photos

            WHERE

                user_id = :user_id

                AND photo_type = 'profile'

                AND is_primary = 1

                AND approval_status = 'approved'

            ORDER BY id DESC

            LIMIT 1
            "
        );

    $adminPhotoStmt->execute([
        ':user_id' =>
            $adminId
    ]);

    $adminAvatar =
        $adminPhotoStmt->fetchColumn()
        ?: null;

} catch (Throwable $e) {

    $adminAvatar = null;
}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$page =
    max(
        1,
        (int)(
            $_GET['page'] ?? 1
        )
    );

$limit =
    max(
        5,
        min(
            100,
            (int)(
                $_GET['limit'] ?? 20
            )
        )
    );

$offset =
    (
        $page - 1
    ) * $limit;


$search =
    trim(
        (string)(
            $_GET['search'] ?? ''
        )
    );


$status =
    strtolower(
        trim(
            (string)(
                $_GET['status'] ?? ''
            )
        )
    );


$allowedStatuses = [
    'pending',
    'accepted',
    'connected',
    'rejected',
    'cancelled',
    'blocked'
];


if (
    !in_array(
        $status,
        $allowedStatuses,
        true
    )
) {

    $status = '';

}


/*
|--------------------------------------------------------------------------
| CONDITIONS
|--------------------------------------------------------------------------
*/

$where = [];

$params = [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            u1.username LIKE :search
            OR u1.full_names LIKE :search
            OR u2.username LIKE :search
            OR u2.full_names LIKE :search
        )
        ";

    $params[':search'] =
        '%'
        .
        $search
        .
        '%';

}


if (
    $status !== ''
) {

    $where[] =
        'c.status = :status';

    $params[':status'] =
        $status;

}


$whereSql =
    $where
        ?
        'WHERE '
        .
        implode(
            ' AND ',
            $where
        )
        :
        '';


/*
|--------------------------------------------------------------------------
| TOTAL
|--------------------------------------------------------------------------
*/

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM connections c

            INNER JOIN users u1
                ON u1.id = c.user_id

            INNER JOIN users u2
                ON u2.id = c.connected_user_id

            {$whereSql}
            "
        );

    $countStmt->execute(
        $params
    );

    $total =
        (int)
        $countStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION COUNT] ' .
        $e->getMessage()
    );

    connectionsListResponse(
        false,
        'Unable to count connections.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| CONNECTIONS
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

                u2.username
                    AS user_two_username,

                u2.full_names
                    AS user_two_full_name,

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

            {$whereSql}

            ORDER BY

                CASE

                    WHEN c.status = 'pending'
                    THEN 0

                    WHEN c.status IN
                        ('accepted','connected')
                    THEN 1

                    WHEN c.status = 'blocked'
                    THEN 2

                    ELSE 3

                END,

                c.created_at DESC

            LIMIT :limit

            OFFSET :offset
            "
        );


    foreach (
        $params as $key => $value
    ) {

        $stmt->bindValue(
            $key,
            $value
        );

    }


    $stmt->bindValue(
        ':limit',
        $limit,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':offset',
        $offset,
        PDO::PARAM_INT
    );


    $stmt->execute();


    $connections =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTIONS LOAD] ' .
        $e->getMessage()
    );

    connectionsListResponse(
        false,
        'Unable to load connections.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| SUMMARY
|--------------------------------------------------------------------------
*/

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS total,

                COALESCE(
                    SUM(
                        status = 'pending'
                    ),
                    0
                ) AS pending,

                COALESCE(
                    SUM(
                        status IN
                        ('accepted','connected')
                    ),
                    0
                ) AS connected,

                COALESCE(
                    SUM(
                        status = 'blocked'
                    ),
                    0
                ) AS blocked

            FROM connections
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (Throwable $e) {

    $summary = [
        'total' =>
            0,

        'pending' =>
            0,

        'connected' =>
            0,

        'blocked' =>
            0
    ];

}


/*
|--------------------------------------------------------------------------
| SESSION ACTIVITY
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION ACTIVITY] ' .
        $e->getMessage()
    );
}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

$pages =
    $total > 0
        ?
        (int)
        ceil(
            $total / $limit
        )
        :
        1;


connectionsListResponse(
    true,
    'Connections loaded successfully.',
    [

        'current_admin' => [

            'id' =>
                (int)
                $admin['id'],

            'username' =>
                $admin['username'],

            'full_names' =>
                $admin['full_names'],

            'email' =>
                $admin['email'],

            'role_name' =>
                $admin['role_name'],

            'role_slug' =>
                $admin['role_slug'],

            'avatar_url' =>
                $adminAvatar

        ],

        'connections' =>
            $connections,

        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ?? 0
                ),

            'pending' =>
                (int)(
                    $summary['pending']
                    ?? 0
                ),

            'connected' =>
                (int)(
                    $summary['connected']
                    ?? 0
                ),

            'blocked' =>
                (int)(
                    $summary['blocked']
                    ?? 0
                )

        ],

        'pagination' => [

            'page' =>
                $page,

            'limit' =>
                $limit,

            'total' =>
                $total,

            'pages' =>
                $pages

        ]

    ]
);