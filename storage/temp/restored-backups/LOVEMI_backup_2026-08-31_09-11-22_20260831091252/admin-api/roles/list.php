<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


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

header(
    'X-Content-Type-Options: nosniff'
);


ini_set(
    'display_errors',
    '0'
);

error_reporting(
    E_ALL
);


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    $_SERVER['HTTPS'] !==
    'off';


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


/* ============================================================
   RESPONSE
============================================================ */

function rolesListResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES LIST DB] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   AUTH
============================================================ */

$currentAdminId =
    (int)(
        $_SESSION[
            'lovemi_user_id'
        ]
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION[
            'lovemi_database_session_id'
        ]
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION[
            'lovemi_session_token'
        ]
        ??
        ''
    );


if (
    $currentAdminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    rolesListResponse(
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


/* ============================================================
   ADMIN AUTHORIZATION
============================================================ */

try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.full_names,

                u.username,

                u.email,

                u.role_id,

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

                u.id = :user_id

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


    $auth->execute(
        [
            ':user_id' =>
                $currentAdminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash
        ]
    );


    $currentAdmin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES AUTH] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$currentAdmin
) {

    rolesListResponse(
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

                rp.role_id =
                    :role_id

                AND p.slug =
                    'roles.manage'
            "
        );


    $permission->execute(
        [
            ':role_id' =>
                (int)$currentAdmin[
                    'role_id'
                ]
        ]
    );


    $allowed =
        (int)$permission->fetchColumn()
        >
        0;

} catch (
    Throwable $e
) {

    rolesListResponse(
        false,
        'Unable to verify role-management permission.',
        [],
        500
    );

}


if (
    !$allowed
) {

    rolesListResponse(
        false,
        'You do not have permission to manage roles.',
        [
            'code' =>
                'PERMISSION_DENIED'
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
            $_GET['page']
            ??
            1
        )
    );


$limit =
    max(
        5,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                20
            )
        )
    );


$offset =
    (
        $page -
        1
    )
    *
    $limit;


$search =
    trim(
        (string)(
            $_GET['search']
            ??
            ''
        )
    );


$adminFilter =
    strtolower(
        trim(
            (string)(
                $_GET['admin']
                ??
                ''
            )
        )
    );


$systemFilter =
    strtolower(
        trim(
            (string)(
                $_GET['system']
                ??
                ''
            )
        )
    );


$singleRoleId =
    (int)(
        $_GET['role_id']
        ??
        0
    );


/* ============================================================
   CONDITIONS
============================================================ */

$where = [];

$params = [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            r.name LIKE :search
            OR r.slug LIKE :search
            OR r.description LIKE :search
        )
        ";

    $params[
        ':search'
    ] =
        '%' .
        $search .
        '%';

}


if (
    $adminFilter ===
    'admin'
) {

    $where[] =
        'r.is_admin_role = 1';

}


if (
    $adminFilter ===
    'member'
) {

    $where[] =
        'r.is_admin_role = 0';

}


if (
    $systemFilter ===
    'system'
) {

    $where[] =
        'r.is_system_role = 1';

}


if (
    $systemFilter ===
    'custom'
) {

    $where[] =
        'r.is_system_role = 0';

}


if (
    $singleRoleId > 0
) {

    $where[] =
        'r.id = :single_role_id';

    $params[
        ':single_role_id'
    ] =
        $singleRoleId;

}


$whereSql =
    $where
        ?
        (
            'WHERE '
            .
            implode(
                ' AND ',
                $where
            )
        )
        :
        '';


/* ============================================================
   COUNT
============================================================ */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM roles r

            {$whereSql}
            "
        );


    $countStmt->execute(
        $params
    );


    $total =
        (int)$countStmt->fetchColumn();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES COUNT] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to count roles.',
        [],
        500
    );

}


/* ============================================================
   LOAD ROLES
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                r.id,

                r.name,

                r.slug,

                r.description,

                r.is_admin_role,

                r.is_system_role,

                r.created_at,

                r.updated_at,

                (
                    SELECT COUNT(*)

                    FROM users u

                    WHERE
                        u.role_id =
                            r.id

                        AND u.is_deleted = 0
                ) AS user_count,

                (
                    SELECT COUNT(*)

                    FROM role_permissions rp

                    WHERE
                        rp.role_id =
                            r.id
                ) AS permission_count

            FROM roles r

            {$whereSql}

            ORDER BY

                r.is_system_role DESC,

                r.is_admin_role DESC,

                r.id ASC

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


    $roles =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES LOAD] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to load roles.',
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

                COUNT(*) AS total_roles,

                COALESCE(
                    SUM(
                        CASE
                            WHEN is_admin_role = 1
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS admin_roles,

                COALESCE(
                    SUM(
                        CASE
                            WHEN is_system_role = 1
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS system_roles,

                COALESCE(
                    SUM(
                        CASE
                            WHEN is_system_role = 0
                            THEN 1
                            ELSE 0
                        END
                    ),
                    0
                ) AS custom_roles

            FROM roles
            "
        );


    $summary =
        $summaryStmt->fetch()
        ?:
        [
            'total_roles' =>
                0,

            'admin_roles' =>
                0,

            'system_roles' =>
                0,

            'custom_roles' =>
                0
        ];

} catch (
    Throwable $e
) {

    $summary = [

        'total_roles' =>
            0,

        'admin_roles' =>
            0,

        'system_roles' =>
            0,

        'custom_roles' =>
            0

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


    $activity->execute(
        [
            ':session_id' =>
                $sessionId,

            ':user_id' =>
                $currentAdminId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   PAGINATION
============================================================ */

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
   RESPONSE
============================================================ */

rolesListResponse(
    true,
    'Roles loaded successfully.',
    [

        'data' => [

            'current_admin' => [

                'id' =>
                    (int)$currentAdmin[
                        'id'
                    ],

                'username' =>
                    $currentAdmin[
                        'username'
                    ],

                'full_names' =>
                    $currentAdmin[
                        'full_names'
                    ],

                'email' =>
                    $currentAdmin[
                        'email'
                    ],

                'role_id' =>
                    (int)$currentAdmin[
                        'role_id'
                    ],

                'role_name' =>
                    $currentAdmin[
                        'role_name'
                    ],

                'role_slug' =>
                    $currentAdmin[
                        'role_slug'
                    ],

                'avatar_url' =>
                    $currentAdmin[
                        'avatar_url'
                    ]
                    ??
                    null

            ],

            'roles' =>
                $roles,

            'summary' => [

                'total_roles' =>
                    (int)(
                        $summary[
                            'total_roles'
                        ]
                        ??
                        0
                    ),

                'admin_roles' =>
                    (int)(
                        $summary[
                            'admin_roles'
                        ]
                        ??
                        0
                    ),

                'system_roles' =>
                    (int)(
                        $summary[
                            'system_roles'
                        ]
                        ??
                        0
                    ),

                'custom_roles' =>
                    (int)(
                        $summary[
                            'custom_roles'
                        ]
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