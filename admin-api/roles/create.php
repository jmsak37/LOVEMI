<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - CREATE ROLE API
|--------------------------------------------------------------------------
|
| POST /admin-api/roles/create.php
|
| JSON:
|
| {
|     "name": "Content Manager",
|     "slug": "content_manager",
|     "description": "Manages approved content",
|     "is_admin_role": 1,
|     "permission_ids": [5, 6]
| }
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

function createRoleResponse(
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
    'POST'
) {

    createRoleResponse(
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

    createRoleResponse(
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
        '[LOVEMI CREATE ROLE DB] '
        .
        $e->getMessage()
    );


    createRoleResponse(
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
        '[LOVEMI CREATE ROLE AUTH] '
        .
        $e->getMessage()
    );


    createRoleResponse(
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

    createRoleResponse(
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


    $permissionStmt->execute(
        [
            ':role_id' =>
                (int)
                $currentAdmin['role_id']
        ]
    );


    $allowed =
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
        '[LOVEMI CREATE ROLE PERMISSION] '
        .
        $e->getMessage()
    );


    createRoleResponse(
        false,
        'Unable to verify your permissions.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


if (
    !$allowed
) {

    createRoleResponse(
        false,
        'You do not have permission to create roles.',
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
    !is_array(
        $data
    )
) {

    createRoleResponse(
        false,
        'Invalid JSON request.',
        [
            'code' =>
                'INVALID_JSON'
        ],
        400
    );

}


/* ============================================================
   FIELDS
============================================================ */

$name =
    trim(
        (string)
        (
            $data['name']
            ??
            ''
        )
    );


$slug =
    strtolower(
        trim(
            (string)
            (
                $data['slug']
                ??
                ''
            )
        )
    );


$description =
    trim(
        (string)
        (
            $data['description']
            ??
            ''
        )
    );


$isAdminRole =
    filter_var(
        $data['is_admin_role']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
        ?
        1
        :
        0;


$permissionIds =
    $data['permission_ids']
    ??
    [];


if (
    !is_array(
        $permissionIds
    )
) {

    $permissionIds =
        [];

}


/* ============================================================
   VALIDATE NAME
============================================================ */

if (
    mb_strlen(
        $name
    )
    <
    2
    ||
    mb_strlen(
        $name
    )
    >
    80
) {

    createRoleResponse(
        false,
        'Role name must contain between 2 and 80 characters.',
        [
            'code' =>
                'INVALID_ROLE_NAME'
        ],
        422
    );

}


/* ============================================================
   VALIDATE SLUG
============================================================ */

if (
    !preg_match(
        '/^[a-z0-9]+(?:[_-][a-z0-9]+)*$/',
        $slug
    )
) {

    createRoleResponse(
        false,
        'Role slug may contain lowercase letters, numbers, underscores and hyphens only.',
        [
            'code' =>
                'INVALID_ROLE_SLUG'
        ],
        422
    );

}


/* ============================================================
   SYSTEM SLUG PROTECTION
============================================================ */

$protectedSlugs = [

    'member',

    'admin',

    'moderator',

    'support'

];


if (
    in_array(
        $slug,
        $protectedSlugs,
        true
    )
) {

    createRoleResponse(
        false,
        'That role slug is reserved for a LOVEMI system role.',
        [
            'code' =>
                'RESERVED_ROLE_SLUG'
        ],
        409
    );

}


/* ============================================================
   DESCRIPTION
============================================================ */

if (
    mb_strlen(
        $description
    )
    >
    255
) {

    createRoleResponse(
        false,
        'Role description must not exceed 255 characters.',
        [
            'code' =>
                'DESCRIPTION_TOO_LONG'
        ],
        422
    );

}


/* ============================================================
   NORMALIZE PERMISSION IDS
============================================================ */

$cleanPermissionIds =
    [];


foreach (
    $permissionIds
    as $permissionId
) {

    $permissionId =
        (int)
        $permissionId;


    if (
        $permissionId > 0
    ) {

        $cleanPermissionIds[
            $permissionId
        ] = $permissionId;

    }

}


$cleanPermissionIds =
    array_values(
        $cleanPermissionIds
    );


/* ============================================================
   ROLE DUPLICATE CHECK
============================================================ */

try {

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                name,

                slug

            FROM roles

            WHERE

                LOWER(name) =
                    LOWER(:name)

                OR

                LOWER(slug) =
                    LOWER(:slug)

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':name' =>
                $name,

            ':slug' =>
                $slug

        ]
    );


    $duplicate =
        $duplicateStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CREATE ROLE DUPLICATE] '
        .
        $e->getMessage()
    );


    createRoleResponse(
        false,
        'Unable to validate the new role.',
        [
            'code' =>
                'DUPLICATE_CHECK_FAILED'
        ],
        500
    );

}


if (
    $duplicate
) {

    createRoleResponse(
        false,
        'A role with that name or slug already exists.',
        [
            'code' =>
                'ROLE_EXISTS',

            'existing_role_id' =>
                (int)
                $duplicate['id']
        ],
        409
    );

}


/* ============================================================
   VERIFY PERMISSIONS
============================================================ */

if (
    count(
        $cleanPermissionIds
    )
    >
    0
) {

    $placeholders =
        implode(
            ',',
            array_fill(
                0,
                count(
                    $cleanPermissionIds
                ),
                '?'
            )
        );


    try {

        $verifyPermissions =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM permissions

                WHERE id IN (
                    {$placeholders}
                )
                "
            );


        $verifyPermissions->execute(
            $cleanPermissionIds
        );


        $validPermissionCount =
            (int)
            $verifyPermissions->fetchColumn();

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI CREATE ROLE PERMISSION VALIDATION] '
            .
            $e->getMessage()
        );


        createRoleResponse(
            false,
            'Unable to validate selected permissions.',
            [
                'code' =>
                    'PERMISSION_VALIDATION_FAILED'
            ],
            500
        );

    }


    if (
        $validPermissionCount
        !==
        count(
            $cleanPermissionIds
        )
    ) {

        createRoleResponse(
            false,
            'One or more selected permissions do not exist.',
            [
                'code' =>
                    'INVALID_PERMISSION_IDS'
            ],
            422
        );

    }

}


/* ============================================================
   CREATE ROLE
============================================================ */

try {

    $pdo->beginTransaction();


    $insertRole =
        $pdo->prepare(
            "
            INSERT INTO roles
            (
                name,
                slug,
                description,
                is_admin_role,
                is_system_role,
                created_at,
                updated_at
            )
            VALUES
            (
                :name,
                :slug,
                :description,
                :is_admin_role,
                0,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insertRole->execute(
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
                $isAdminRole

        ]
    );


    $roleId =
        (int)
        $pdo->lastInsertId();


    /* ========================================================
       ASSIGN PERMISSIONS
    ========================================================= */

    if (
        count(
            $cleanPermissionIds
        )
        >
        0
    ) {

        $insertPermission =
            $pdo->prepare(
                "
                INSERT INTO role_permissions
                (
                    role_id,
                    permission_id,
                    created_at
                )
                VALUES
                (
                    :role_id,
                    :permission_id,
                    CURRENT_TIMESTAMP
                )
                "
            );


        foreach (
            $cleanPermissionIds
            as $permissionId
        ) {

            $insertPermission->execute(
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
                'role_created',
                'role',
                :entity_id,
                NULL,
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

                        'permission_ids' =>
                            $cleanPermissionIds

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
        '[LOVEMI CREATE ROLE INSERT] '
        .
        $e->getMessage()
    );


    createRoleResponse(
        false,
        'Unable to create the new role.',
        [
            'code' =>
                'CREATE_ROLE_FAILED'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

createRoleResponse(
    true,
    'Role created successfully.',
    [

        'data' => [

            'id' =>
                $roleId,

            'name' =>
                $name,

            'slug' =>
                $slug,

            'description' =>
                $description,

            'is_admin_role' =>
                $isAdminRole,

            'is_system_role' =>
                0,

            'permission_ids' =>
                $cleanPermissionIds,

            'permission_count' =>
                count(
                    $cleanPermissionIds
                ),

            'redirect' =>
                'roles.html'

        ]

    ],
    201
);