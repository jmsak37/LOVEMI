<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');


$isHttps =
    !empty($_SERVER['HTTPS']) &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);


if (
    session_status() !==
    PHP_SESSION_ACTIVE
) {
    session_start();
}


function userGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    userGetResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

}


$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ?? 0
    );

$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ?? 0
    );

$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ?? ''
    );


$userId =
    (int)(
        $_GET['id']
        ??
        $_GET['user_id']
        ??
        0
    );


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    userGetResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if ($userId <= 0) {

    userGetResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    userGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


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

                r.is_admin_role,

                p.display_name AS admin_display_name,

                ph.file_path AS avatar_url

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            LEFT JOIN photos ph
                ON ph.user_id = u.id

                AND ph.photo_type = 'profile'

                AND ph.is_primary = 1

                AND ph.approval_status = 'approved'

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

            LIMIT 1
            "
        );


    $auth->execute([
        ':admin_id' => $adminId,
        ':session_id' => $sessionId,
        ':token_hash' => $tokenHash
    ]);


    $admin =
        $auth->fetch();

} catch (Throwable $e) {

    userGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    userGetResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


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

                AND p.slug IN
                (
                    'users.view',
                    'users.manage'
                )
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)$admin['role_id']
    ]);


    if (
        (int)$permission->fetchColumn() <=
        0
    ) {

        userGetResponse(
            false,
            'You do not have permission to view users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    userGetResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.*,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role,

                c.name AS country_name,

                c.iso2 AS country_iso2,

                c.iso3 AS country_iso3,

                c.phone_code,

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

                ph.file_path AS avatar_url,

                ph.thumbnail_path AS avatar_thumbnail

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            LEFT JOIN photos ph
                ON ph.user_id = u.id

                AND ph.photo_type = 'profile'

                AND ph.is_primary = 1

                AND ph.approval_status = 'approved'

            WHERE
                u.id = :user_id

            LIMIT 1
            "
        );


    $stmt->execute([
        ':user_id' => $userId
    ]);


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET USER] ' .
        $e->getMessage()
    );

    userGetResponse(
        false,
        'Unable to load the user.',
        [],
        500
    );

}


if (!$user) {

    userGetResponse(
        false,
        'User not found.',
        [],
        404
    );

}


/*
 * Never return password_hash or encrypted ID number data
 * to the browser.
 */

unset(
    $user['password_hash'],
    $user['id_number_hash'],
    $user['id_number_encrypted'],
    $user['two_factor_secret_encrypted']
);


try {

    $photos =
        $pdo->prepare(
            "
            SELECT

                id,

                file_name,

                file_path,

                thumbnail_path,

                mime_type,

                file_size,

                width,

                height,

                photo_type,

                approval_status,

                is_primary,

                is_featured,

                uploaded_at,

                approved_at

            FROM photos

            WHERE
                user_id = :user_id

            ORDER BY
                is_primary DESC,
                uploaded_at DESC

            LIMIT 30
            "
        );


    $photos->execute([
        ':user_id' => $userId
    ]);


    $photoRows =
        $photos->fetchAll();

} catch (Throwable $e) {

    $photoRows = [];

}


userGetResponse(
    true,
    'User loaded successfully.',
    [
        'data' => [

            'current_admin' =>
                $admin,

            'user' =>
                $user,

            'photos' =>
                $photoRows

        ]
    ]
);