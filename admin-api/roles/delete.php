<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - DELETE ROLE API
|--------------------------------------------------------------------------
|
| POST /admin-api/roles/delete.php
|
| JSON:
|
| {
|   "id": 5
| }
|
|--------------------------------------------------------------------------
|
| System roles are protected.
|
| A role cannot be deleted while users still use it.
|
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../../../config/database.php';

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

function roleDeleteResponse(
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
    'POST'
) {

    roleDeleteResponse(
        false,
        'Only POST requests are allowed.',
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

    roleDeleteResponse(
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
        '[LOVEMI ROLE DELETE DATABASE] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
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
   VERIFY ADMIN
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

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

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
        '[LOVEMI ROLE DELETE AUTH] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
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

    roleDeleteResponse(
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
   CHECK roles.manage
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

    $permissionStmt->execute([
        ':role_id' =>
            (int)
            $currentAdmin[
                'role_id'
            ]
    ]);

    $allowed =
        (
            (int)
            $permissionStmt->fetchColumn()
        )
        >
        0;

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ROLE DELETE PERMISSION] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
        false,
        'Unable to verify your permissions.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


if (!$allowed) {

    roleDeleteResponse(
        false,
        'You do not have permission to delete roles.',
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

$rawBody =
    file_get_contents(
        'php://input'
    );

$data =
    json_decode(
        $rawBody ?: '{}',
        true
    );

if (
    !is_array($data)
) {

    $data =
        $_POST;

}


$roleId =
    (int)
    (
        $data['id']
        ??
        0
    );


if (
    $roleId <= 0
) {

    roleDeleteResponse(
        false,
        'A valid role ID is required.',
        [
            'code' =>
                'ROLE_ID_REQUIRED'
        ],
        422
    );

}


/* ============================================================
   LOAD ROLE
============================================================ */

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
                :id

            LIMIT 1
            "
        );

    $roleStmt->execute([
        ':id' =>
            $roleId
    ]);

    $role =
        $roleStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ROLE DELETE LOAD] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
        false,
        'Unable to load the role.',
        [
            'code' =>
                'ROLE_LOAD_FAILED'
        ],
        500
    );

}


if (
    !$role
) {

    roleDeleteResponse(
        false,
        'Role not found.',
        [
            'code' =>
                'ROLE_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   SYSTEM ROLE PROTECTION
============================================================ */

if (
    (int)
    $role['is_system_role']
    ===
    1
) {

    roleDeleteResponse(
        false,
        'System roles cannot be deleted.',
        [
            'code' =>
                'SYSTEM_ROLE_PROTECTED'
        ],
        403
    );

}


/* ============================================================
   CHECK USERS
============================================================ */

try {

    $usersStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM users

            WHERE role_id =
                :role_id

              AND is_deleted = 0
            "
        );

    $usersStmt->execute([
        ':role_id' =>
            $roleId
    ]);

    $usersUsingRole =
        (int)
        $usersStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ROLE DELETE USERS] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
        false,
        'Unable to check users assigned to this role.',
        [
            'code' =>
                'USER_CHECK_FAILED'
        ],
        500
    );

}


if (
    $usersUsingRole > 0
) {

    roleDeleteResponse(
        false,
        'This role cannot be deleted because users are still assigned to it.',
        [
            'code' =>
                'ROLE_IN_USE',

            'users_count' =>
                $usersUsingRole
        ],
        409
    );

}


/* ============================================================
   DELETE
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * role_permissions has a foreign key with ON DELETE CASCADE,
     * but deleting explicitly keeps the operation clear.
     */

    $deletePermissions =
        $pdo->prepare(
            "
            DELETE FROM role_permissions

            WHERE role_id =
                :role_id
            "
        );

    $deletePermissions->execute([
        ':role_id' =>
            $roleId
    ]);


    $deleteRole =
        $pdo->prepare(
            "
            DELETE FROM roles

            WHERE id =
                :role_id

            LIMIT 1
            "
        );

    $deleteRole->execute([
        ':role_id' =>
            $roleId
    ]);


    if (
        $deleteRole->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'ROLE_DELETE_FAILED'
        );

    }


    /* ========================================================
       AUDIT
    ========================================================= */

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
                'role_deleted',
                'role',
                :entity_id,
                :old_values,
                NULL,
                :ip,
                :agent
            )
            "
        );

    $audit->execute([
        ':user_id' =>
            $currentAdminId,

        ':entity_id' =>
            $roleId,

        ':old_values' =>
            json_encode(
                [
                    'id' =>
                        (int)
                        $role['id'],

                    'name' =>
                        $role['name'],

                    'slug' =>
                        $role['slug'],

                    'description' =>
                        $role['description'],

                    'is_admin_role' =>
                        (int)
                        $role['is_admin_role'],

                    'is_system_role' =>
                        (int)
                        $role['is_system_role']
                ],
                JSON_UNESCAPED_UNICODE
            ),

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
        '[LOVEMI ROLE DELETE SAVE] '
        .
        $e->getMessage()
    );

    roleDeleteResponse(
        false,
        'Unable to delete the role.',
        [
            'code' =>
                'ROLE_DELETE_FAILED'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

roleDeleteResponse(
    true,
    'Role deleted successfully.',
    [
        'data' => [
            'id' =>
                $roleId,

            'name' =>
                $role['name'],

            'slug' =>
                $role['slug']
        ]
    ]
);