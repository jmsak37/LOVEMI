<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN ROLES / PERMISSIONS LIST API
|--------------------------------------------------------------------------
|
| GET:
|
|   /admin-api/roles/list.php
|
| Returns:
|
|   - authenticated current administrator
|   - roles
|   - role permission counts
|   - complete permission catalogue
|   - summary
|
|--------------------------------------------------------------------------
*/


require_once
    __DIR__
    . '/../../../../config/database.php';


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
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    rolesListResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   SESSION VALUES
============================================================ */

$currentAdminId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ?
        (string)
        $_SESSION['lovemi_session_token']
        :
        '';


$databaseSessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


if (
    $currentAdminId <= 0
    ||
    $sessionToken === ''
    ||
    $databaseSessionId <= 0
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
        '[LOVEMI ROLES DB] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   VERIFY ADMIN SESSION
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role

            FROM users u

            INNER JOIN roles r
                ON r.id =
                   u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                   u.id

            WHERE

                u.id =
                    :user_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

            LIMIT 1
            "
        );


    $authStmt->execute(
        [

            ':user_id' =>
                $currentAdminId,

            ':session_id' =>
                $databaseSessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    $currentAdmin =
        $authStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES ADMIN AUTH] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to verify administrator access.',
        [
            'code' =>
                'ADMIN_AUTH_FAILED'
        ],
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
                    'roles.manage'
            "
        );


    $permissionStmt->execute(
        [
            ':role_id' =>
                (int)
                $currentAdmin['role_id']
        ]
    );


    $canManageRoles =
        (
            (int)
            $permissionStmt->fetchColumn()
        )
        >
        0;

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES PERMISSION CHECK] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to verify role management permission.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


/* ============================================================
   PERMISSION CATALOGUE
============================================================ */

try {

    $permissionQuery =
        $pdo->query(
            "
            SELECT

                id,

                name,

                slug,

                description,

                created_at

            FROM permissions

            ORDER BY
                id ASC
            "
        );


    $permissions =
        $permissionQuery->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES PERMISSION LIST] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to load permission catalogue.',
        [
            'code' =>
                'PERMISSION_LIST_FAILED'
        ],
        500
    );

}


/* ============================================================
   ROLE LIST
============================================================ */

try {

    $roleQuery =
        $pdo->query(
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

                COUNT(
                    DISTINCT rp.permission_id
                ) AS permission_count

            FROM roles r

            LEFT JOIN role_permissions rp
                ON rp.role_id =
                   r.id

            GROUP BY

                r.id,

                r.name,

                r.slug,

                r.description,

                r.is_admin_role,

                r.is_system_role,

                r.created_at,

                r.updated_at

            ORDER BY
                r.id ASC
            "
        );


    $roles =
        $roleQuery->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ROLES LIST] '
        .
        $e->getMessage()
    );


    rolesListResponse(
        false,
        'Unable to load roles.',
        [
            'code' =>
                'ROLE_LIST_FAILED'
        ],
        500
    );

}


/* ============================================================
   SUMMARY
============================================================ */

$totalRoles =
    count(
        $roles
    );


$adminRoles =
    0;


$systemRoles =
    0;


$customRoles =
    0;


foreach (
    $roles
    as $role
) {

    if (
        (int)
        $role['is_admin_role']
        ===
        1
    ) {

        $adminRoles++;

    }


    if (
        (int)
        $role['is_system_role']
        ===
        1
    ) {

        $systemRoles++;

    }


    if (
        (int)
        $role['is_system_role']
        ===
        0
    ) {

        $customRoles++;

    }

}


/* ============================================================
   CURRENT ACTIVITY
============================================================ */

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET last_activity_at =
                CURRENT_TIMESTAMP

            WHERE id =
                :session_id

              AND user_id =
                :user_id

            LIMIT 1
            "
        );


    $activity->execute(
        [

            ':session_id' =>
                $databaseSessionId,

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
   RESPONSE
============================================================ */

rolesListResponse(
    true,
    'Roles and permissions loaded successfully.',
    [

        'data' => [

            'current_admin' => [

                'id' =>
                    (int)
                    $currentAdmin['id'],

                'username' =>
                    $currentAdmin['username'],

                'full_names' =>
                    $currentAdmin['full_names'],

                'email' =>
                    $currentAdmin['email'],

                'role_name' =>
                    $currentAdmin['role_name'],

                'role_slug' =>
                    $currentAdmin['role_slug']

            ],


            'roles' =>
                $roles,


            'permissions' =>
                $permissions,


            'permissions_manage' =>
                (
                    (
                        $permissionStmt
                        ??
                        null
                    )
                    ?
                    $canManageRoles
                    :
                    $canManageRoles
                ),


            'summary' => [

                'total_roles' =>
                    $totalRoles,

                'admin_roles' =>
                    $adminRoles,

                'system_roles' =>
                    $systemRoles,

                'custom_roles' =>
                    $customRoles

            ]

        ]

    ]
);