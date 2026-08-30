<?php

declare(strict_types=1);


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

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


/* ============================================================
   RESPONSE
============================================================ */

function permissionsListResponse(
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
        '[LOVEMI PERMISSIONS LIST DB] '
        .
        $e->getMessage()
    );


    permissionsListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   AUTHENTICATION
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

    permissionsListResponse(
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

                AND s.expires_at >
                    CURRENT_TIMESTAMP

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
        '[LOVEMI PERMISSIONS AUTH] '
        .
        $e->getMessage()
    );


    permissionsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$currentAdmin
) {

    permissionsListResponse(
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
   PERMISSION CHECK
============================================================ */

try {

    $permissionStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                rp.role_id =
                    :role_id

                AND p.slug =
                    'permissions.manage'
            "
        );


    $permissionStmt->execute(
        [
            ':role_id' =>
                (int)
                $currentAdmin[
                    'role_id'
                ]
        ]
    );


    $hasPermission =
        (int)
        $permissionStmt->fetchColumn()
        >
        0;

} catch (
    Throwable $e
) {

    permissionsListResponse(
        false,
        'Unable to verify permission-management access.',
        [],
        500
    );

}


if (
    !$hasPermission
) {

    permissionsListResponse(
        false,
        'You do not have permission to manage permissions.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   SPECIAL ROLES REQUEST
============================================================ */

$rolesOnly =
    isset(
        $_GET['roles']
    )
    &&
    (string)
    $_GET['roles'] ===
    '1';


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


$assignedFilter =
    strtolower(
        trim(
            (string)(
                $_GET['assigned']
                ??
                ''
            )
        )
    );


$roleFilter =
    (int)(
        $_GET['role_id']
        ??
        0
    );


$singlePermissionId =
    (int)(
        $_GET['permission_id']
        ??
        0
    );


/* ============================================================
   LOAD ROLES
============================================================ */

try {

    $rolesStmt =
        $pdo->query(
            "
            SELECT

                id,

                name,

                slug,

                description,

                is_admin_role,

                is_system_role

            FROM roles

            ORDER BY

                is_admin_role DESC,

                is_system_role DESC,

                name ASC
            "
        );


    $roles =
        $rolesStmt->fetchAll();

} catch (
    Throwable $e
) {

    permissionsListResponse(
        false,
        'Unable to load roles.',
        [],
        500
    );

}


if (
    $rolesOnly
) {

    permissionsListResponse(
        true,
        'Roles loaded successfully.',
        [
            'data' => [

                'roles' =>
                    $roles

            ]
        ]
    );

}


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
            p.name LIKE :search
            OR p.slug LIKE :search
            OR p.description LIKE :search
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
    $singlePermissionId >
    0
) {

    $where[] =
        'p.id = :permission_id';

    $params[
        ':permission_id'
    ] =
        $singlePermissionId;

}


if (
    $roleFilter >
    0
) {

    $where[] =
        "
        EXISTS
        (
            SELECT 1

            FROM role_permissions filter_rp

            WHERE

                filter_rp.permission_id =
                    p.id

                AND filter_rp.role_id =
                    :filter_role_id
        )
        ";

    $params[
        ':filter_role_id'
    ] =
        $roleFilter;

}


if (
    $assignedFilter ===
    'assigned'
) {

    $where[] =
        "
        EXISTS
        (
            SELECT 1

            FROM role_permissions assigned_rp

            WHERE
                assigned_rp.permission_id =
                    p.id
        )
        ";

}


if (
    $assignedFilter ===
    'unassigned'
) {

    $where[] =
        "
        NOT EXISTS
        (
            SELECT 1

            FROM role_permissions unassigned_rp

            WHERE
                unassigned_rp.permission_id =
                    p.id
        )
        ";

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

            FROM permissions p

            {$whereSql}
            "
        );


    $countStmt->execute(
        $params
    );


    $total =
        (int)
        $countStmt->fetchColumn();

} catch (
    Throwable $e
) {

    permissionsListResponse(
        false,
        'Unable to count permissions.',
        [],
        500
    );

}


/* ============================================================
   LOAD PERMISSIONS
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.name,

                p.slug,

                p.description,

                p.created_at,

                COALESCE(
                    (
                        SELECT COUNT(*)

                        FROM role_permissions rp

                        WHERE
                            rp.permission_id =
                                p.id
                    ),
                    0
                ) AS role_count

            FROM permissions p

            {$whereSql}

            ORDER BY

                p.name ASC

            LIMIT :limit

            OFFSET :offset
            "
        );


    foreach (
        $params as $key =>
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


    $permissions =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PERMISSIONS LOAD] '
        .
        $e->getMessage()
    );


    permissionsListResponse(
        false,
        'Unable to load permissions.',
        [],
        500
    );

}


/* ============================================================
   ADD ROLE IDS TO EACH PERMISSION
============================================================ */

foreach (
    $permissions
    as &$permission
) {

    try {

        $assignmentStmt =
            $pdo->prepare(
                "
                SELECT role_id

                FROM role_permissions

                WHERE
                    permission_id =
                        :permission_id
                "
            );


        $assignmentStmt->execute(
            [
                ':permission_id' =>
                    (int)
                    $permission[
                        'id'
                    ]
            ]
        );


        $permission[
            'role_ids'
        ] =
            array_map(
                'intval',
                $assignmentStmt->fetchAll(
                    PDO::FETCH_COLUMN
                )
            );

    } catch (
        Throwable $e
    ) {

        $permission[
            'role_ids'
        ] =
            [];

    }

}

unset(
    $permission
);


/* ============================================================
   SUMMARY
============================================================ */

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                (
                    SELECT COUNT(*)

                    FROM permissions
                ) AS total_permissions,

                (
                    SELECT COUNT(DISTINCT permission_id)

                    FROM role_permissions
                ) AS assigned_permissions,

                (
                    SELECT COUNT(*)

                    FROM permissions p2

                    WHERE NOT EXISTS
                    (
                        SELECT 1

                        FROM role_permissions rp2

                        WHERE
                            rp2.permission_id =
                                p2.id
                    )
                ) AS unassigned_permissions,

                (
                    SELECT COUNT(*)

                    FROM roles
                ) AS total_roles
            "
        );


    $summary =
        $summaryStmt->fetch()
        ?:
        [
            'total_permissions' =>
                0,

            'assigned_permissions' =>
                0,

            'unassigned_permissions' =>
                0,

            'total_roles' =>
                0
        ];

} catch (
    Throwable $e
) {

    $summary = [

        'total_permissions' =>
            0,

        'assigned_permissions' =>
            0,

        'unassigned_permissions' =>
            0,

        'total_roles' =>
            count(
                $roles
            )

    ];

}


/* ============================================================
   UPDATE ACTIVITY
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

                id =
                    :session_id

                AND user_id =
                    :user_id

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
        '[LOVEMI PERMISSION ACTIVITY] '
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

permissionsListResponse(
    true,
    'Permissions loaded successfully.',
    [
        'data' => [

            'current_admin' => [

                'id' =>
                    (int)
                    $currentAdmin[
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
                    (int)
                    $currentAdmin[
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

            'permissions' =>
                $permissions,

            'roles' =>
                $roles,

            'summary' => [

                'total_permissions' =>
                    (int)(
                        $summary[
                            'total_permissions'
                        ]
                        ??
                        0
                    ),

                'assigned_permissions' =>
                    (int)(
                        $summary[
                            'assigned_permissions'
                        ]
                        ??
                        0
                    ),

                'unassigned_permissions' =>
                    (int)(
                        $summary[
                            'unassigned_permissions'
                        ]
                        ??
                        0
                    ),

                'total_roles' =>
                    (int)(
                        $summary[
                            'total_roles'
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