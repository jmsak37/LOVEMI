<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - PERMISSIONS LIST API
|--------------------------------------------------------------------------
|
| GET /admin-api/permissions/list.php
|
| Returns:
|
|   - current authenticated administrator
|   - complete permissions catalogue
|   - role/permission assignments
|
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../../config/database.php';

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
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';

session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);

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

function permissionListResponse(
    bool $success,
    string $message,
    array $extra = [],
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
            $extra
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    permissionListResponse(
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
   SESSION
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

    permissionListResponse(
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION LIST DB] '
        .
        $e->getMessage()
    );

    permissionListResponse(
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

                u.two_factor_enabled,

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

    $authStmt->execute([
        ':user_id' =>
            $currentAdminId,

        ':session_id' =>
            $databaseSessionId,

        ':token_hash' =>
            $tokenHash
    ]);

    $currentAdmin =
        $authStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION LIST AUTH] '
        .
        $e->getMessage()
    );

    permissionListResponse(
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

    permissionListResponse(
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
   CHECK permissions.manage
============================================================ */

try {

    $manageStmt =
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

    $manageStmt->execute([
        ':role_id' =>
            (int)
            $currentAdmin['role_id']
    ]);

    $canManage =
        (
            (int)
            $manageStmt->fetchColumn()
        )
        >
        0;

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION LIST CHECK] '
        .
        $e->getMessage()
    );

    permissionListResponse(
        false,
        'Unable to verify permission access.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


/* ============================================================
   FILTER
============================================================ */

$roleId =
    isset($_GET['role_id'])
        ?
        (int) $_GET['role_id']
        :
        0;


/* ============================================================
   LOAD PERMISSIONS
============================================================ */

try {

    $permissionSql =
        "
        SELECT

            p.id,

            p.name,

            p.slug,

            p.description,

            p.created_at,

            COUNT(
                DISTINCT rp.role_id
            ) AS assigned_role_count

        FROM permissions p

        LEFT JOIN role_permissions rp
            ON rp.permission_id =
               p.id

        GROUP BY

            p.id,
            p.name,
            p.slug,
            p.description,
            p.created_at

        ORDER BY
            p.id ASC
        ";

    $permissionStmt =
        $pdo->query(
            $permissionSql
        );

    $permissions =
        $permissionStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION LIST QUERY] '
        .
        $e->getMessage()
    );

    permissionListResponse(
        false,
        'Unable to load permissions.',
        [
            'code' =>
                'PERMISSION_LIST_FAILED'
        ],
        500
    );

}


/* ============================================================
   ROLE FILTER
============================================================ */

$selectedRole =
    null;


$roleAssignments =
    [];


if (
    $roleId > 0
) {

    try {

        $roleStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    name,
                    slug,
                    description,
                    is_admin_role,
                    is_system_role

                FROM roles

                WHERE id =
                    :role_id

                LIMIT 1
                "
            );

        $roleStmt->execute([
            ':role_id' =>
                $roleId
        ]);

        $selectedRole =
            $roleStmt->fetch();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PERMISSION ROLE FILTER] '
            .
            $e->getMessage()
        );

    }


    if (
        $selectedRole
    ) {

        try {

            $assignmentStmt =
                $pdo->prepare(
                    "
                    SELECT

                        p.id,
                        p.name,
                        p.slug,
                        p.description

                    FROM role_permissions rp

                    INNER JOIN permissions p
                        ON p.id =
                           rp.permission_id

                    WHERE

                        rp.role_id =
                            :role_id

                    ORDER BY
                        p.id ASC
                    "
                );

            $assignmentStmt->execute([
                ':role_id' =>
                    $roleId
            ]);

            $roleAssignments =
                $assignmentStmt->fetchAll();

        } catch (Throwable $e) {

            error_log(
                '[LOVEMI PERMISSION ROLE ASSIGNMENTS] '
                .
                $e->getMessage()
            );

        }

    }

}


/* ============================================================
   LOAD ROLES
============================================================ */

try {

    $rolesQuery =
        $pdo->query(
            "
            SELECT

                r.id,
                r.name,
                r.slug,
                r.description,
                r.is_admin_role,
                r.is_system_role,

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
                r.is_system_role

            ORDER BY
                r.id ASC
            "
        );

    $roles =
        $rolesQuery->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION ROLES] '
        .
        $e->getMessage()
    );

    $roles =
        [];

}


/* ============================================================
   ACTIVITY
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

    $activity->execute([
        ':session_id' =>
            $databaseSessionId,

        ':user_id' =>
            $currentAdminId
    ]);

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PERMISSION ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

permissionListResponse(
    true,
    'Permissions loaded successfully.',
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

                'role_id' =>
                    (int)
                    $currentAdmin['role_id'],

                'role_name' =>
                    $currentAdmin['role_name'],

                'role_slug' =>
                    $currentAdmin['role_slug']

            ],

            'permissions' =>
                $permissions,

            'roles' =>
                $roles,

            'selected_role' =>
                $selectedRole,

            'role_permissions' =>
                $roleAssignments,

            'can_manage' =>
                $canManage,

            'summary' => [

                'total_permissions' =>
                    count($permissions),

                'total_roles' =>
                    count($roles),

                'assigned_to_selected_role' =>
                    count($roleAssignments)

            ]

        ]

    ]
);