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

function rolesDeleteResponse(
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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    rolesDeleteResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* ============================================================
   INPUT
============================================================ */

$data =
    json_decode(
        file_get_contents(
            'php://input'
        )
        ?:
        '{}',
        true
    );


if (
    !is_array(
        $data
    )
) {

    $data =
        $_POST;

}


$roleId =
    (int)(
        $data['role_id']
        ??
        0
    );


if (
    $roleId <= 0
) {

    rolesDeleteResponse(
        false,
        'A valid role ID is required.',
        [],
        422
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

    rolesDeleteResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   CURRENT ADMIN
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

    rolesDeleteResponse(
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


/* ============================================================
   ADMIN AUTHORIZATION
============================================================ */

try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.role_id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

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


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    rolesDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    rolesDeleteResponse(
        false,
        'Administrator access is required.',
        [],
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

                AND p.slug = 'roles.manage'
            "
        );


    $permission->execute(
        [
            ':role_id' =>
                (int)$admin[
                    'role_id'
                ]
        ]
    );


    if (
        (int)$permission->fetchColumn()
        <=
        0
    ) {

        rolesDeleteResponse(
            false,
            'You do not have permission to delete roles.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    rolesDeleteResponse(
        false,
        'Unable to verify permission.',
        [],
        500
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

            WHERE
                id = :role_id

            LIMIT 1
            "
        );


    $roleStmt->execute(
        [
            ':role_id' =>
                $roleId
        ]
    );


    $role =
        $roleStmt->fetch();

} catch (
    Throwable $e
) {

    rolesDeleteResponse(
        false,
        'Unable to load role.',
        [],
        500
    );

}


if (
    !$role
) {

    rolesDeleteResponse(
        false,
        'Role not found.',
        [],
        404
    );

}


/* ============================================================
   SYSTEM ROLE
============================================================ */

if (
    (int)$role[
        'is_system_role'
    ]
    ===
    1
) {

    rolesDeleteResponse(
        false,
        'System roles cannot be deleted.',
        [
            'code' =>
                'SYSTEM_ROLE_PROTECTED'
        ],
        409
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

            WHERE

                role_id = :role_id

                AND is_deleted = 0
            "
        );


    $usersStmt->execute(
        [
            ':role_id' =>
                $roleId
        ]
    );


    $assignedUsers =
        (int)$usersStmt->fetchColumn();

} catch (
    Throwable $e
) {

    rolesDeleteResponse(
        false,
        'Unable to check users assigned to this role.',
        [],
        500
    );

}


if (
    $assignedUsers > 0
) {

    rolesDeleteResponse(
        false,
        'This role is currently assigned to users. Move those users to another role before deleting it.',
        [
            'code' =>
                'ROLE_IN_USE',

            'assigned_users' =>
                $assignedUsers
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
     * Delete role-permission mappings first.
     */

    $permissionDelete =
        $pdo->prepare(
            "
            DELETE FROM role_permissions

            WHERE
                role_id = :role_id
            "
        );


    $permissionDelete->execute(
        [
            ':role_id' =>
                $roleId
        ]
    );


    /*
     * Delete role.
     */

    $delete =
        $pdo->prepare(
            "
            DELETE FROM roles

            WHERE
                id = :role_id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':role_id' =>
                $roleId
        ]
    );


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'ROLE_DELETE_FAILED'
        );

    }


    /*
     * Audit.
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


    $audit->execute(
        [
            ':user_id' =>
                $currentAdminId,

            ':entity_id' =>
                $roleId,

            ':old_values' =>
                json_encode(
                    [
                        'name' =>
                            $role[
                                'name'
                            ],

                        'slug' =>
                            $role[
                                'slug'
                            ],

                        'description' =>
                            $role[
                                'description'
                            ],

                        'is_admin_role' =>
                            (int)$role[
                                'is_admin_role'
                            ],

                        'is_system_role' =>
                            (int)$role[
                                'is_system_role'
                            ]
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':ip' =>
                $_SERVER[
                    'REMOTE_ADDR'
                ]
                ??
                null,

            ':agent' =>
                $_SERVER[
                    'HTTP_USER_AGENT'
                ]
                ??
                null
        ]
    );


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI ROLE DELETE] '
        .
        $e->getMessage()
    );


    rolesDeleteResponse(
        false,
        'Unable to delete role.',
        [],
        500
    );

}


rolesDeleteResponse(
    true,
    'Role deleted successfully.',
    [
        'data' => [

            'role_id' =>
                $roleId

        ]
    ]
);