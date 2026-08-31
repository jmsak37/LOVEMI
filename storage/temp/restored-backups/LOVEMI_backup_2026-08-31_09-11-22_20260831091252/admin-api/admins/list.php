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


function adminListResponse(
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
   AUTH SESSION
============================================================ */

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

    adminListResponse(
        false,
        'You must log in first.',
        [
            'code' => 'NOT_AUTHENTICATED'
        ],
        401
    );

}


try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    adminListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ADMIN ACCESS
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $auth =
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

                p.display_name,

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


    $auth->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    $currentAdmin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMINS LIST AUTH] ' .
        $e->getMessage()
    );

    adminListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$currentAdmin) {

    adminListResponse(
        false,
        'Administrator access is required.',
        [
            'code' =>
                'ADMIN_ACCESS_REQUIRED'
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

                AND p.slug = 'admins.manage'
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)$currentAdmin['role_id']
    ]);


    $allowed =
        (int)$permission->fetchColumn() >
        0;

} catch (
    Throwable $e
) {

    adminListResponse(
        false,
        'Unable to verify administrator permission.',
        [],
        500
    );

}


if (!$allowed) {

    adminListResponse(
        false,
        'You do not have permission to manage administrators.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   FILTERS
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


$role =
    strtolower(
        trim(
            (string)(
                $_GET['role'] ?? ''
            )
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


$where = [
    'r.is_admin_role = 1'
];


$params = [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            u.username LIKE :search
            OR u.full_names LIKE :search
            OR u.email LIKE :search
        )
        ";

    $params[':search'] =
        '%' .
        $search .
        '%';

}


if (
    in_array(
        $role,
        [
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


if (
    $status ===
    'active'
) {

    $where[] =
        "
        u.is_active = 1
        AND u.is_suspended = 0
        AND u.is_deleted = 0
        ";

}


if (
    $status ===
    'suspended'
) {

    $where[] =
        "
        u.is_suspended = 1
        AND u.is_deleted = 0
        ";

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

} catch (
    Throwable $e
) {

    adminListResponse(
        false,
        'Unable to count administrators.',
        [],
        500
    );

}


/* ============================================================
   ADMIN LIST
============================================================ */

try {

    $stmt =
        $pdo->prepare(
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

                u.account_status,

                u.email_verified,

                u.phone_verified,

                u.identity_verified,

                u.age_verified,

                u.two_factor_enabled,

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
            "
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


    $admins =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMINS LIST QUERY] ' .
        $e->getMessage()
    );

    adminListResponse(
        false,
        'Unable to load administrators.',
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

                COUNT(*) AS total_admins,

                SUM(
                    CASE
                        WHEN u.is_active = 1
                        AND u.is_suspended = 0
                        AND u.is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS active_admins,

                SUM(
                    CASE
                        WHEN u.is_suspended = 1
                        AND u.is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS suspended_admins,

                SUM(
                    CASE
                        WHEN u.two_factor_enabled = 1
                        AND u.is_deleted = 0
                        THEN 1
                        ELSE 0
                    END
                ) AS two_factor_admins

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE
                r.is_admin_role = 1
            "
        );


    $summary =
        $summaryStmt->fetch()
        ?: [];

} catch (
    Throwable $e
) {

    $summary = [
        'total_admins' => 0,
        'active_admins' => 0,
        'suspended_admins' => 0,
        'two_factor_admins' => 0
    ];

}


$pages =
    $total > 0
        ?
        (int)ceil(
            $total /
            $limit
        )
        :
        1;


/* ============================================================
   ACTIVITY
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
        ':session_id' =>
            $sessionId,

        ':user_id' =>
            $adminId
    ]);

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMINS ACTIVITY] ' .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

adminListResponse(
    true,
    'Administrators loaded successfully.',
    [
        'data' => [

            'current_admin' => [

                'id' =>
                    (int)$currentAdmin['id'],

                'username' =>
                    $currentAdmin['username'],

                'full_names' =>
                    $currentAdmin['full_names'],

                'email' =>
                    $currentAdmin['email'],

                'role_id' =>
                    (int)$currentAdmin['role_id'],

                'role_name' =>
                    $currentAdmin['role_name'],

                'role_slug' =>
                    $currentAdmin['role_slug'],

                'avatar_url' =>
                    $currentAdmin['avatar_url']
                    ??
                    null

            ],

            'admins' =>
                $admins,

            'summary' => [

                'total_admins' =>
                    (int)(
                        $summary['total_admins']
                        ??
                        0
                    ),

                'active_admins' =>
                    (int)(
                        $summary['active_admins']
                        ??
                        0
                    ),

                'suspended_admins' =>
                    (int)(
                        $summary['suspended_admins']
                        ??
                        0
                    ),

                'two_factor_admins' =>
                    (int)(
                        $summary['two_factor_admins']
                        ??
                        0
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