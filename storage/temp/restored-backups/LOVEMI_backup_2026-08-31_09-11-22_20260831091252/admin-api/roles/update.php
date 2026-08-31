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

function rolesUpdateResponse(
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

    rolesUpdateResponse(
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


$isAdminRole =
    !empty(
        $data['is_admin_role']
    )
        ?
        1
        :
        0;


$isSystemRole =
    !empty(
        $data['is_system_role']
    )
        ?
        1
        :
        0;


if (
    $roleId <= 0
) {

    rolesUpdateResponse(
        false,
        'A valid role ID is required.',
        [],
        422
    );

}


if (
    $name === ''
    ||
    $slug === ''
) {

    rolesUpdateResponse(
        false,
        'Role name and slug are required.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[a-z0-9]+(?:[_-][a-z0-9]+)*$/',
        $slug
    )
) {

    rolesUpdateResponse(
        false,
        'Role slug may contain only lowercase letters, numbers, underscores and hyphens.',
        [],
        422
    );

}


if (
    strlen(
        $name
    ) > 80
    ||
    strlen(
        $slug
    ) > 80
    ||
    strlen(
        $description
    ) > 255
) {

    rolesUpdateResponse(
        false,
        'One or more role fields are too long.',
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

    rolesUpdateResponse(
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

    rolesUpdateResponse(
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

    rolesUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    rolesUpdateResponse(
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

        rolesUpdateResponse(
            false,
            'You do not have permission to update roles.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    rolesUpdateResponse(
        false,
        'Unable to verify permission.',
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

                description,

                is_admin_role,

                is_system_role

            FROM roles

            WHERE
                id = :role_id

            LIMIT 1
            "
        );


    $targetStmt->execute(
        [
            ':role_id' =>
                $roleId
        ]
    );


    $target =
        $targetStmt->fetch();

} catch (
    Throwable $e
) {

    rolesUpdateResponse(
        false,
        'Unable to load role.',
        [],
        500
    );

}


if (
    !$target
) {

    rolesUpdateResponse(
        false,
        'Role not found.',
        [],
        404
    );

}


/* ============================================================
   SYSTEM ROLE PROTECTION
============================================================ */

if (
    (int)$target[
        'is_system_role'
    ]
    ===
    1
) {

    /*
     * Protect the defining identity of system roles.
     * Their names/slugs and system flag cannot be changed.
     *
     * Description and administrator status may still be
     * controlled by a sufficiently privileged administrator.
     */

    $name =
        $target['name'];

    $slug =
        $target['slug'];

    $isSystemRole =
        1;

}


/* ============================================================
   DUPLICATE CHECK
============================================================ */

try {

    $duplicate =
        $pdo->prepare(
            "
            SELECT id

            FROM roles

            WHERE

                id <> :role_id

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
            ':role_id' =>
                $roleId,

            ':name' =>
                $name,

            ':slug' =>
                $slug
        ]
    );


    if (
        $duplicate->fetch()
    ) {

        rolesUpdateResponse(
            false,
            'Another role already uses this name or slug.',
            [
                'code' =>
                    'DUPLICATE_ROLE'
            ],
            409
        );

    }

} catch (
    Throwable $e
) {

    rolesUpdateResponse(
        false,
        'Unable to validate duplicate roles.',
        [],
        500
    );

}


/* ============================================================
   SAFETY: LAST ADMIN ROLE
============================================================ */

if (
    (int)$target[
        'is_admin_role'
    ]
    ===
    1
    &&
    $isAdminRole ===
    0
) {

    try {

        $activeAdminUsersStmt =
            $pdo->query(
                "
                SELECT COUNT(*)

                FROM users u

                INNER JOIN roles r
                    ON r.id = u.role_id

                WHERE

                    r.is_admin_role = 1

                    AND u.is_active = 1

                    AND u.is_suspended = 0

                    AND u.is_deleted = 0
                "
            );


        $activeAdminUsers =
            (int)$activeAdminUsersStmt
                ->fetchColumn();

    } catch (
        Throwable $e
    ) {

        rolesUpdateResponse(
            false,
            'Unable to check administrator safety rules.',
            [],
            500
        );

    }


    /*
     * Do not remove administrator status from the role if
     * active administrators are still using it.
     */

    if (
        $activeAdminUsers >
        0
    ) {

        rolesUpdateResponse(
            false,
            'This administrator role is currently assigned to active administrators. Move those accounts to another administrator role before removing administrator access from this role.',
            [
                'code' =>
                    'ADMIN_ROLE_IN_USE'
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
            UPDATE roles

            SET

                name =
                    :name,

                slug =
                    :slug,

                description =
                    :description,

                is_admin_role =
                    :is_admin_role,

                is_system_role =
                    :is_system_role,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE

                id =
                    :role_id

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

            ':is_admin_role' =>
                $isAdminRole,

            ':is_system_role' =>
                $isSystemRole,

            ':role_id' =>
                $roleId
        ]
    );


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
                'role_updated',
                'role',
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
                $roleId,

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
                            ],

                        'is_admin_role' =>
                            (int)$target[
                                'is_admin_role'
                            ],

                        'is_system_role' =>
                            (int)$target[
                                'is_system_role'
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

                        'is_admin_role' =>
                            $isAdminRole,

                        'is_system_role' =>
                            $isSystemRole
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
        '[LOVEMI ROLE UPDATE] '
        .
        $e->getMessage()
    );


    rolesUpdateResponse(
        false,
        'Unable to update role.',
        [],
        500
    );

}


rolesUpdateResponse(
    true,
    'Role updated successfully.',
    [
        'data' => [

            'role_id' =>
                $roleId,

            'name' =>
                $name,

            'slug' =>
                $slug

        ]
    ]
);