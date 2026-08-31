<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN DELETE PROFILE API
|--------------------------------------------------------------------------
|
| POST /admin-api/profiles/delete.php
|
| JSON:
|
| {
|   "user_id": 4
| }
|
| IMPORTANT:
|
| This deletes only the profile row.
| The user account is NOT deleted.
|
|--------------------------------------------------------------------------
*/

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
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
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

function profileDeleteResponse(
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

    profileDeleteResponse(
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

$adminId =
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


$sessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


if (
    $adminId <= 0
    ||
    $sessionToken === ''
    ||
    $sessionId <= 0
) {

    profileDeleteResponse(
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


$userId =
    (int)
    (
        $data['user_id']
        ??
        $data['id']
        ??
        0
    );


if (
    $userId <= 0
) {

    profileDeleteResponse(
        false,
        'A valid user ID is required.',
        [
            'code' =>
                'USER_ID_REQUIRED'
        ],
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

    error_log(
        '[LOVEMI DELETE PROFILE DB] '
        .
        $e->getMessage()
    );


    profileDeleteResponse(
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
   ADMIN AUTH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $auth =
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
                    :admin_id

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


    $auth->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE PROFILE AUTH] '
        .
        $e->getMessage()
    );


    profileDeleteResponse(
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
    !$admin
) {

    profileDeleteResponse(
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
   PERMISSION
============================================================ */

try {

    $permission =
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
                    'profiles.manage'
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)
            $admin['role_id']
    ]);


    $allowed =
        (
            (int)
            $permission->fetchColumn()
        )
        >
        0;

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE PROFILE PERMISSION] '
        .
        $e->getMessage()
    );


    profileDeleteResponse(
        false,
        'Unable to verify profile management permission.',
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

    profileDeleteResponse(
        false,
        'You do not have permission to delete profiles.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   PREVENT ADMIN SELF PROFILE DELETE
============================================================ */

if (
    $userId ===
    $adminId
) {

    profileDeleteResponse(
        false,
        'You cannot delete your own administrator profile from this page.',
        [
            'code' =>
                'SELF_DELETE_BLOCKED'
        ],
        403
    );

}


/* ============================================================
   LOAD PROFILE
============================================================ */

try {

    $profileStmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.user_id,

                p.display_name,

                p.bio,

                p.occupation,

                p.education,

                p.city,

                p.relationship_status,

                p.looking_for,

                p.interests,

                p.profile_visibility,

                p.show_online_status,

                p.allow_messages,

                p.created_at,

                p.updated_at,

                u.username,

                u.full_names,

                u.email

            FROM profiles p

            INNER JOIN users u
                ON u.id =
                   p.user_id

            WHERE
                p.user_id =
                    :user_id

            LIMIT 1
            "
        );


    $profileStmt->execute([
        ':user_id' =>
            $userId
    ]);


    $profile =
        $profileStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE PROFILE LOAD] '
        .
        $e->getMessage()
    );


    profileDeleteResponse(
        false,
        'Unable to load the profile.',
        [
            'code' =>
                'PROFILE_LOAD_FAILED'
        ],
        500
    );

}


if (
    !$profile
) {

    profileDeleteResponse(
        false,
        'The profile does not exist.',
        [
            'code' =>
                'PROFILE_NOT_FOUND'
        ],
        404
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
            DELETE FROM profiles

            WHERE user_id =
                :user_id

            LIMIT 1
            "
        );


    $delete->execute([
        ':user_id' =>
            $userId
    ]);


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'PROFILE_DELETE_FAILED'
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
                'admin_profile_deleted',
                'profile',
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
            $adminId,

        ':entity_id' =>
            (int)
            $profile['id'],

        ':old_values' =>
            json_encode(
                $profile,
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

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI DELETE PROFILE SAVE] '
        .
        $e->getMessage()
    );


    profileDeleteResponse(
        false,
        'Unable to delete the profile.',
        [
            'code' =>
                'PROFILE_DELETE_FAILED'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

profileDeleteResponse(
    true,
    'Profile deleted successfully. The user account remains active.',
    [
        'data' => [

            'profile_id' =>
                (int)
                $profile['id'],

            'user_id' =>
                $userId,

            'username' =>
                $profile['username'],

            'full_names' =>
                $profile['full_names']

        ]
    ]
);