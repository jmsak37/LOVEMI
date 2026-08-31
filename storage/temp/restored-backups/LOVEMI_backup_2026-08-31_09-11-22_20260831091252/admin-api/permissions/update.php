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

function permissionsUpdateResponse(
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

    permissionsUpdateResponse(
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


$name =
    trim(
        (string)(
            $data['name']
            ??
            ''
        )
    );


$slug =
    strtolower(
        trim(
            (string)(
                $data['slug']
                ??
                ''
            )
        )
    );


$description =
    trim(
        (string)(
            $data['description']
            ??
            ''
        )
    );


$roleIds =
    isset(
        $data['role_ids']
    )
    &&
    is_array(
        $data['role_ids']
    )
        ?
        array_values(
            array_unique(
                array_filter(
                    array_map(
                        'intval',
                        $data['role_ids']
                    ),
                    static function (
                        int $value
                    ): bool {

                        return $value > 0;

                    }
                )
            )
        )
        :
        [];


/* ============================================================
   VALIDATION
============================================================ */

if (
    $permissionId <= 0
) {

    permissionsUpdateResponse(
        false,
        'A valid permission ID is required.',
        [],
        422
    );

}


if (
    $name === ''
    ||
    $slug === ''
) {

    permissionsUpdateResponse(
        false,
        'Permission name and slug are required.',
        [],
        422
    );

}


if (
    strlen(
        $name
    ) > 100
    ||
    strlen(
        $slug
    ) > 120
    ||
    strlen(
        $description
    ) > 255
) {

    permissionsUpdateResponse(
        false,
        'One or more permission fields are too long.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[a-z0-9]+(?:[._-][a-z0-9]+)*$/',
        $slug
    )
) {

    permissionsUpdateResponse(
        false,
        'Permission slug contains invalid characters.',
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

    permissionsUpdateResponse(
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

    permissionsUpdateResponse(
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

    permissionsUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    permissionsUpdateResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


/* ============================================================
   PERMISSION TO MANAGE PERMISSIONS
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

        permissionsUpdateResponse(
            false,
            'You do not have permission to update permissions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    permissionsUpdateResponse(
        false,
        'Unable to verify permission-management access.',
        [],
        500
    );

}


/* ============================================================
   LOAD TARGET
============================================================ */

try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                name,

                slug,

                description

            FROM permissions

            WHERE
                id = :permission_id

            LIMIT 1
            "
        );


    $targetStmt->execute(
        [
            ':permission_id' =>
                $permissionId
        ]
    );


    $target =
        $targetStmt->fetch();

} catch (
    Throwable $e
) {

    permissionsUpdateResponse(
        false,
        'Unable to load permission.',
        [],
        500
    );

}


if (
    !$target
) {

    permissionsUpdateResponse(
        false,
        'Permission not found.',
        [],
        404
    );

}


/* ============================================================
   PROTECT CORE PERMISSION SLUGS
============================================================ */

/*
 * The system permission records are referenced by many
 * protected APIs. The administrator may edit descriptions
 * and assignments, but cannot rename the core slug.
 */

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
        (string)$target['slug'],
        $coreSlugs,
        true
    )
) {

    if (
        $slug !==
        $target['slug']
    ) {

        permissionsUpdateResponse(
            false,
            'The slug of a protected system permission cannot be changed.',
            [
                'code' =>
                    'SYSTEM_PERMISSION_PROTECTED'
            ],
            409
        );

    }

}


/* ============================================================
   VALIDATE ROLES
============================================================ */

if (
    $roleIds
) {

    $placeholders =
        implode(
            ',',
            array_fill(
                0,
                count($roleIds),
                '?'
            )
        );


    try {

        $roleCheck =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM roles

                WHERE

                    id IN (
                        {$placeholders}
                    )
                "
            );


        $roleCheck->execute(
            $roleIds
        );


        $foundRoles =
            (int)
            $roleCheck->fetchColumn();

    } catch (
        Throwable $e
    ) {

        permissionsUpdateResponse(
            false,
            'Unable to validate selected roles.',
            [],
            500
        );

    }


    if (
        $foundRoles
        !==
        count(
            $roleIds
        )
    ) {

        permissionsUpdateResponse(
            false,
            'One or more selected roles do not exist.',
            [],
            422
        );

    }

}


/* ============================================================
   DUPLICATE CHECK
============================================================ */

try {

    $duplicate =
        $pdo->prepare(
            "
            SELECT id

            FROM permissions

            WHERE

                id <> :permission_id

                AND
                (
                    LOWER(name) =
                        LOWER(:name)

                    OR slug =
                        :slug
                )

            LIMIT 1
            "
        );


    $duplicate->execute(
        [
            ':permission_id' =>
                $permissionId,

            ':name' =>
                $name,

            ':slug' =>
                $slug
        ]
    );


    if (
        $duplicate->fetch()
    ) {

        permissionsUpdateResponse(
            false,
            'Another permission already uses this name or slug.',
            [
                'code' =>
                    'DUPLICATE_PERMISSION'
            ],
            409
        );

    }

} catch (
    Throwable $e
) {

    permissionsUpdateResponse(
        false,
        'Unable to validate duplicate permissions.',
        [],
        500
    );

}


/* ============================================================
   SAFETY: CURRENT ADMIN ROLE
============================================================ */

/*
 * Prevent an administrator from removing the
 * permissions.manage permission from their own role.
 */

$currentAdminRoleId =
    (int)$admin[
        'role_id'
    ];


if (
    $permissionId
    >
    0
) {

    try {

        $currentAssignment =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM role_permissions

                WHERE

                    role_id =
                        :role_id

                    AND permission_id =
                        :permission_id
                "
            );


        $currentAssignment->execute(
            [
                ':role_id' =>
                    $currentAdminRoleId,

                ':permission_id' =>
                    $permissionId
            ]
        );


        $assignedToCurrentRole =
            (int)
            $currentAssignment->fetchColumn()
            >
            0;

    } catch (
        Throwable $e
    ) {

        $assignedToCurrentRole =
            false;

    }


    if (
        $target['slug'] ===
        'permissions.manage'
        &&
        !in_array(
            $currentAdminRoleId,
            $roleIds,
            true
        )
    ) {

        permissionsUpdateResponse(
            false,
            'You cannot remove permissions.manage from your own administrator role.',
            [
                'code' =>
                    'SELF_LOCKOUT_PREVENTED'
            ],
            409
        );

    }

}


/* ============================================================
   UPDATE
============================================================ */

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE permissions

            SET

                name =
                    :name,

                slug =
                    :slug,

                description =
                    :description

            WHERE

                id =
                    :permission_id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':name' =>
                $name,

            ':slug' =>
                $slug,

            ':description' =>
                $description !== ''
                    ?
                    $description
                    :
                    null,

            ':permission_id' =>
                $permissionId
        ]
    );


    /*
     * Replace role assignments atomically.
     */

    $deleteAssignments =
        $pdo->prepare(
            "
            DELETE FROM role_permissions

            WHERE
                permission_id =
                    :permission_id
            "
        );


    $deleteAssignments->execute(
        [
            ':permission_id' =>
                $permissionId
        ]
    );


    if (
        $roleIds
    ) {

        $insertAssignment =
            $pdo->prepare(
                "
                INSERT INTO role_permissions
                (
                    role_id,
                    permission_id
                )
                VALUES
                (
                    :role_id,
                    :permission_id
                )
                "
            );


        foreach (
            $roleIds as $roleId
        ) {

            $insertAssignment->execute(
                [
                    ':role_id' =>
                        $roleId,

                    ':permission_id' =>
                        $permissionId
                ]
            );

        }

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
                'permission_updated',
                'permission',
                :entity_id,
                :old_values,
                :new_values,
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
                            $target[
                                'name'
                            ],

                        'slug' =>
                            $target[
                                'slug'
                            ],

                        'description' =>
                            $target[
                                'description'
                            ]
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':new_values' =>
                json_encode(
                    [
                        'name' =>
                            $name,

                        'slug' =>
                            $slug,

                        'description' =>
                            $description,

                        'role_ids' =>
                            $roleIds
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
        '[LOVEMI PERMISSION UPDATE] '
        .
        $e->getMessage()
    );


    permissionsUpdateResponse(
        false,
        'Unable to update permission.',
        [],
        500
    );

}


permissionsUpdateResponse(
    true,
    'Permission updated successfully.',
    [
        'data' => [

            'permission_id' =>
                $permissionId,

            'name' =>
                $name,

            'slug' =>
                $slug,

            'role_ids' =>
                $roleIds

        ]
    ]
);