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

function rolesCreateResponse(
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
   REQUEST
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    rolesCreateResponse(
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


/* ============================================================
   VALIDATION
============================================================ */

if (
    $name === ''
    ||
    $slug === ''
) {

    rolesCreateResponse(
        false,
        'Role name and slug are required.',
        [],
        422
    );

}


if (
    strlen(
        $name
    ) > 80
) {

    rolesCreateResponse(
        false,
        'Role name is too long.',
        [],
        422
    );

}


if (
    strlen(
        $slug
    ) > 80
) {

    rolesCreateResponse(
        false,
        'Role slug is too long.',
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

    rolesCreateResponse(
        false,
        'Role slug may contain only lowercase letters, numbers, underscores and hyphens.',
        [],
        422
    );

}


if (
    strlen(
        $description
    ) > 255
) {

    rolesCreateResponse(
        false,
        'Role description is too long.',
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

    rolesCreateResponse(
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

    rolesCreateResponse(
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
   AUTHORIZE
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

    rolesCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    rolesCreateResponse(
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

        rolesCreateResponse(
            false,
            'You do not have permission to create roles.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    rolesCreateResponse(
        false,
        'Unable to verify role-management permission.',
        [],
        500
    );

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

                LOWER(name) =
                    LOWER(:name)

                OR
                slug =
                    :slug

            LIMIT 1
            "
        );


    $duplicate->execute(
        [
            ':name' =>
                $name,

            ':slug' =>
                $slug
        ]
    );


    if (
        $duplicate->fetch()
    ) {

        rolesCreateResponse(
            false,
            'A role with this name or slug already exists.',
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

    rolesCreateResponse(
        false,
        'Unable to check duplicate roles.',
        [],
        500
    );

}


/* ============================================================
   CREATE
============================================================ */

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            INSERT INTO roles
            (
                name,
                slug,
                description,
                is_admin_role,
                is_system_role
            )
            VALUES
            (
                :name,
                :slug,
                :description,
                :is_admin_role,
                :is_system_role
            )
            "
        );


    $stmt->execute(
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
                $isSystemRole
        ]
    );


    $roleId =
        (int)$pdo->lastInsertId();


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
        '[LOVEMI ROLE CREATE] '
        .
        $e->getMessage()
    );


    rolesCreateResponse(
        false,
        'Unable to create role.',
        [],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

rolesCreateResponse(
    true,
    'Role created successfully.',
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