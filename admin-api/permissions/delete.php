<?php

declare(strict_types=1);


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

function permissionsDeleteResponse(
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

    permissionsDeleteResponse(
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


$permissionId =
    (int)(
        $data['permission_id']
        ??
        0
    );


if (
    $permissionId <= 0
) {

    permissionsDeleteResponse(
        false,
        'A valid permission ID is required.',
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

    permissionsDeleteResponse(
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

    permissionsDeleteResponse(
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
   ADMIN AUTH
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

    permissionsDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    permissionsDeleteResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


/* ============================================================
   PERMISSION CHECK
============================================================ */

try {

    $permissionCheck =
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


    $permissionCheck->execute(
        [
            ':role_id' =>
                (int)$admin[
                    'role_id'
                ]
        ]
    );


    if (
        (int)
        $permissionCheck->fetchColumn()
        <=
        0
    ) {

        permissionsDeleteResponse(
            false,
            'You do not have permission to delete permissions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    permissionsDeleteResponse(
        false,
        'Unable to verify permission-management access.',
        [],
        500
    );

}


/* ============================================================
   LOAD PERMISSION
============================================================ */

try {

    $permissionStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                name,

                slug,

                description

            FROM permissions

            WHERE

                id =
                    :permission_id

            LIMIT 1
            "
        );


    $permissionStmt->execute(
        [
            ':permission_id' =>
                $permissionId
        ]
    );


    $permission =
        $permissionStmt->fetch();

} catch (
    Throwable $e
) {

    permissionsDeleteResponse(
        false,
        'Unable to load permission.',
        [],
        500
    );

}


if (
    !$permission
) {

    permissionsDeleteResponse(
        false,
        'Permission not found.',
        [],
        404
    );

}


/* ============================================================
   PROTECT SYSTEM PERMISSIONS
============================================================ */

$coreSlugs = [

    'dashboard.view',
    'users.manage',
    'users.view',
    'profiles.manage',
    'photos.manage',
    'posts.manage',
    'connections.manage',
    'conversations.manage',
    'messages.manage',
    'premium.manage',
    'payments.manage',
    'services.manage',
    'countries.manage',
    'currencies.manage',
    'exchange_rates.manage',
    'notifications.manage',
    'audio.manage',
    'reports.manage',
    'blocks.manage',
    'admins.manage',
    'roles.manage',
    'permissions.manage',
    'audit.view',
    'login_logs.view',
    'settings.manage',
    'backups.manage'

];


if (
    in_array(
        (string)$permission['slug'],
        $coreSlugs,
        true
    )
) {

    permissionsDeleteResponse(
        false,
        'Core LOVEMI system permissions cannot be deleted.',
        [
            'code' =>
                'SYSTEM_PERMISSION_PROTECTED'
        ],
        409
    );

}


/* ============================================================
   CHECK ROLE ASSIGNMENTS
============================================================ */

try {

    $assignmentStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions

            WHERE
                permission_id =
                    :permission_id
            "
        );


    $assignmentStmt->execute(
        [
            ':permission_id' =>
                $permissionId
        ]
    );


    $roleCount =
        (int)
        $assignmentStmt->fetchColumn();

} catch (
    Throwable $e
) {

    permissionsDeleteResponse(
        false,
        'Unable to check permission assignments.',
        [],
        500
    );

}


if (
    $roleCount >
    0
) {

    permissionsDeleteResponse(
        false,
        'This permission is currently assigned to one or more roles. Remove its role assignments before deleting it.',
        [
            'code' =>
                'PERMISSION_IN_USE',

            'assigned_roles' =>
                $roleCount
        ],
        409
    );

}


/* ============================================================
   DELETE
============================================================ */

try {

    $pdo->beginTransaction();


    $delete =
        $pdo->prepare(
            "
            DELETE FROM permissions

            WHERE
                id =
                    :permission_id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':permission_id' =>
                $permissionId
        ]
    );


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'PERMISSION_DELETE_FAILED'
        );

    }


    /* ========================================================
       AUDIT
    ======================================================== */

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
                'permission_deleted',
                'permission',
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
                $permissionId,

            ':old_values' =>
                json_encode(
                    [
                        'name' =>
                            $permission[
                                'name'
                            ],

                        'slug' =>
                            $permission[
                                'slug'
                            ],

                        'description' =>
                            $permission[
                                'description'
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
        '[LOVEMI PERMISSION DELETE] '
        .
        $e->getMessage()
    );


    permissionsDeleteResponse(
        false,
        'Unable to delete permission.',
        [],
        500
    );

}


permissionsDeleteResponse(
    true,
    'Permission deleted successfully.',
    [
        'data' => [

            'permission_id' =>
                $permissionId

        ]
    ]
);