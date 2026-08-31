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

function permissionsCreateResponse(
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

    permissionsCreateResponse(
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
    $name === ''
    ||
    $slug === ''
) {

    permissionsCreateResponse(
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
) {

    permissionsCreateResponse(
        false,
        'Permission name is too long.',
        [],
        422
    );

}


if (
    strlen(
        $slug
    ) > 120
) {

    permissionsCreateResponse(
        false,
        'Permission slug is too long.',
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

    permissionsCreateResponse(
        false,
        'Permission slug must contain lowercase letters, numbers, dots, underscores or hyphens.',
        [],
        422
    );

}


if (
    strlen(
        $description
    ) > 255
) {

    permissionsCreateResponse(
        false,
        'Permission description is too long.',
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

    permissionsCreateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   AUTH
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

    permissionsCreateResponse(
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

    permissionsCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    permissionsCreateResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


/* ============================================================
   MANAGE PERMISSIONS CHECK
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

        permissionsCreateResponse(
            false,
            'You do not have permission to create permissions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    permissionsCreateResponse(
        false,
        'Unable to verify permission-management access.',
        [],
        500
    );

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

        permissionsCreateResponse(
            false,
            'Unable to validate selected roles.',
            [],
            500
        );

    }


    if (
        $foundRoles
        !==
        count($roleIds)
    ) {

        permissionsCreateResponse(
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

                LOWER(name) =
                    LOWER(:name)

                OR slug =
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

        permissionsCreateResponse(
            false,
            'A permission with this name or slug already exists.',
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

    permissionsCreateResponse(
        false,
        'Unable to check for duplicate permissions.',
        [],
        500
    );

}


/* ============================================================
   CREATE
============================================================ */

try {

    $pdo->beginTransaction();


    $insert =
        $pdo->prepare(
            "
            INSERT INTO permissions
            (
                name,
                slug,
                description
            )
            VALUES
            (
                :name,
                :slug,
                :description
            )
            "
        );


    $insert->execute(
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
                    null
        ]
    );


    $permissionId =
        (int)
        $pdo->lastInsertId();


    if (
        $roleIds
    ) {

        $assign =
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

            $assign->execute(
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
                'permission_created',
                'permission',
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
                $permissionId,

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
        '[LOVEMI PERMISSION CREATE] '
        .
        $e->getMessage()
    );


    permissionsCreateResponse(
        false,
        'Unable to create permission.',
        [],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

permissionsCreateResponse(
    true,
    'Permission created successfully.',
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