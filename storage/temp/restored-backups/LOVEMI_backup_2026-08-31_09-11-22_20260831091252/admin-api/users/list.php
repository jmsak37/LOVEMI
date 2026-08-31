<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');

ini_set('display_errors', '0');
error_reporting(E_ALL);


/* ============================================================
   SESSION
============================================================ */

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
    session_status() !==
    PHP_SESSION_ACTIVE
) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function userListResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    userListResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   SESSION VALUES
============================================================ */

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ?? 0
    );

$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ?? 0
    );

$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ?? ''
    );


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    userListResponse(
        false,
        'You must log in first.',
        [
            'code' => 'NOT_AUTHENTICATED'
        ],
        401
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS LIST DB] ' .
        $e->getMessage()
    );

    userListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ADMIN AUTH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role,

                p.display_name AS admin_display_name,

                ph.file_path AS avatar_url

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            LEFT JOIN photos ph
                ON ph.user_id = u.id

                AND ph.photo_type = 'profile'

                AND ph.is_primary = 1

                AND ph.approval_status = 'approved'

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

            LIMIT 1
            "
        );


    $stmt->execute([
        ':admin_id' => $adminId,
        ':session_id' => $sessionId,
        ':token_hash' => $tokenHash
    ]);


    $admin =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS LIST AUTH] ' .
        $e->getMessage()
    );

    userListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    userListResponse(
        false,
        'Administrator access is required.',
        [
            'code' => 'ADMIN_ACCESS_REQUIRED'
        ],
        403
    );

}


/* ============================================================
   PERMISSION
============================================================ */

try {

    $permission =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                rp.role_id = :role_id

                AND p.slug IN
                (
                    'users.view',
                    'users.manage'
                )
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)$admin['role_id']
    ]);


    $allowed =
        (int)$permission->fetchColumn() > 0;

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS LIST PERMISSION] ' .
        $e->getMessage()
    );

    userListResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


if (!$allowed) {

    userListResponse(
        false,
        'You do not have permission to view users.',
        [
            'code' => 'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   INPUT
============================================================ */

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
    ($page - 1) * $limit;


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


$role =
    strtolower(
        trim(
            (string)(
                $_GET['role'] ?? ''
            )
        )
    );


$verification =
    strtolower(
        trim(
            (string)(
                $_GET['verification'] ?? ''
            )
        )
    );


/* ============================================================
   WHERE
============================================================ */

$where = [
    '1 = 1'
];

$params = [];


if ($search !== '') {

    $where[] =
        "
        (
            u.username LIKE :search
            OR u.full_names LIKE :search
            OR u.email LIKE :search
        )
        ";

    $params[':search'] =
        '%' . $search . '%';

}


if ($status === 'active') {

    $where[] =
        "
        u.is_active = 1
        AND u.is_suspended = 0
        AND u.is_deleted = 0
        ";

}


if ($status === 'suspended') {

    $where[] =
        "
        u.is_suspended = 1
        AND u.is_deleted = 0
        ";

}


if ($status === 'deleted') {

    $where[] =
        'u.is_deleted = 1';

}


if (
    in_array(
        $role,
        [
            'member',
            'admin',
            'moderator',
            'support'
        ],
        true
    )
) {

    $where[] =
        'r.slug = :role';

    $params[':role'] =
        $role;

}


if ($verification === 'verified') {

    $where[] =
        'u.email_verified = 1';

}


if ($verification === 'unverified') {

    $where[] =
        'u.email_verified = 0';

}


$whereSql =
    implode(
        ' AND ',
        $where
    );


/* ============================================================
   COUNT
============================================================ */

try {

    $count =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE
                {$whereSql}
            "
        );


    $count->execute(
        $params
    );


    $total =
        (int)$count->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS COUNT] ' .
        $e->getMessage()
    );

    userListResponse(
        false,
        'Unable to count users.',
        [],
        500
    );

}


/* ============================================================
   USERS
============================================================ */

try {

    $sql =
        "
        SELECT

            u.id,

            u.role_id,

            u.username,

            u.full_names,

            u.gender,

            u.email,

            u.country_id,

            u.phone_number,

            u.phone_e164,

            u.date_of_birth,

            u.two_factor_enabled,

            u.account_status,

            u.email_verified,

            u.phone_verified,

            u.identity_verified,

            u.age_verified,

            u.is_active,

            u.is_suspended,

            u.is_deleted,

            u.last_login_at,

            u.last_seen_at,

            u.created_at,

            u.updated_at,

            r.name AS role_name,

            r.slug AS role_slug,

            r.is_admin_role,

            c.name AS country_name,

            c.iso2 AS country_iso2,

            p.display_name,

            ph.file_path AS avatar_url

        FROM users u

        INNER JOIN roles r
            ON r.id = u.role_id

        LEFT JOIN countries c
            ON c.id = u.country_id

        LEFT JOIN profiles p
            ON p.user_id = u.id

        LEFT JOIN photos ph
            ON ph.user_id = u.id

            AND ph.photo_type = 'profile'

            AND ph.is_primary = 1

            AND ph.approval_status = 'approved'

        WHERE
            {$whereSql}

        ORDER BY
            u.created_at DESC,
            u.id DESC

        LIMIT :limit

        OFFSET :offset
        ";


    $stmt =
        $pdo->prepare(
            $sql
        );


    foreach (
        $params
        as $key =>
        $value
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


    $users =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS LIST QUERY] ' .
        $e->getMessage()
    );

    userListResponse(
        false,
        'Unable to load users.',
        [],
        500
    );

}


/* ============================================================
   SUMMARY
============================================================ */

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS total_users,

                SUM(
                    CASE
                        WHEN is_active = 1
                        AND is_suspended = 0
                        AND is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS active_users,

                SUM(
                    CASE
                        WHEN is_suspended = 1
                        AND is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS suspended_users,

                SUM(
                    CASE
                        WHEN email_verified = 1
                        AND is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS verified_users

            FROM users
            "
        );


    $summary =
        $summaryStmt->fetch()
        ?: [];



    $adminStmt =
        $pdo->query(
            "
            SELECT COUNT(*)

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE
                r.is_admin_role = 1

                AND u.is_deleted = 0
            "
        );


    $summary['admin_users'] =
        (int)$adminStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS SUMMARY] ' .
        $e->getMessage()
    );

    $summary = [
        'total_users' => 0,
        'active_users' => 0,
        'suspended_users' => 0,
        'verified_users' => 0,
        'admin_users' => 0
    ];

}


/* ============================================================
   SESSION ACTIVITY
============================================================ */

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
        ':session_id' => $sessionId,
        ':user_id' => $adminId
    ]);

} catch (Throwable $e) {

    error_log(
        '[LOVEMI USERS ACTIVITY] ' .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

$pages =
    $total > 0
        ?
        (int)ceil(
            $total / $limit
        )
        :
        1;


userListResponse(
    true,
    'Users loaded successfully.',
    [
        'data' => [

            'current_admin' => [

                'id' =>
                    (int)$admin['id'],

                'username' =>
                    $admin['username'],

                'full_names' =>
                    $admin['full_names'],

                'email' =>
                    $admin['email'],

                'role_id' =>
                    (int)$admin['role_id'],

                'role_name' =>
                    $admin['role_name'],

                'role_slug' =>
                    $admin['role_slug'],

                'avatar_url' =>
                    $admin['avatar_url'] ?? null

            ],

            'users' =>
                $users,

            'summary' => [

                'total_users' =>
                    (int)(
                        $summary['total_users'] ?? 0
                    ),

                'active_users' =>
                    (int)(
                        $summary['active_users'] ?? 0
                    ),

                'suspended_users' =>
                    (int)(
                        $summary['suspended_users'] ?? 0
                    ),

                'verified_users' =>
                    (int)(
                        $summary['verified_users'] ?? 0
                    ),

                'admin_users' =>
                    (int)(
                        $summary['admin_users'] ?? 0
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
    ]
);