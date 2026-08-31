<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET PHOTO DETAILS
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


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


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function pendingPhotosGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        [
            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    pendingPhotosGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN SESSION
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    pendingPhotosGetResponse(
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


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT
                u.id

            FROM users u

            INNER JOIN roles r
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

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

                AND p.slug =
                    'photos.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        pendingPhotosGetResponse(
            false,
            'You do not have permission to manage photos.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingPhotosGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| PHOTO ID
|--------------------------------------------------------------------------
*/

$photoId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $photoId <= 0
) {

    pendingPhotosGetResponse(
        false,
        'A valid photo ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| PHOTO
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                ph.id,

                ph.user_id,

                ph.file_name,

                ph.file_path,

                ph.thumbnail_path,

                ph.mime_type,

                ph.file_size,

                ph.width,

                ph.height,

                ph.photo_type,

                ph.approval_status,

                ph.is_primary,

                ph.is_featured,

                ph.uploaded_at,

                ph.approved_at,

                ph.approved_by,

                u.username,

                u.full_names,

                (
                    SELECT
                        p2.file_path

                    FROM photos p2

                    WHERE

                        p2.user_id =
                            u.id

                        AND p2.photo_type =
                            'profile'

                        AND p2.is_primary =
                            1

                        AND p2.approval_status =
                            'approved'

                    ORDER BY
                        p2.id DESC

                    LIMIT 1

                ) AS avatar

            FROM photos ph

            INNER JOIN users u
                ON u.id =
                    ph.user_id

            WHERE

                ph.id =
                    :photo_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    $photo =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PHOTO GET] '
        .
        $e->getMessage()
    );


    pendingPhotosGetResponse(
        false,
        'Unable to load media details.',
        [],
        500
    );

}


if (
    !$photo
) {

    pendingPhotosGetResponse(
        false,
        'Media not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| BUTTON PERMISSIONS
|--------------------------------------------------------------------------
*/

$canApprove =
    strtolower(
        (string)
        $photo['approval_status']
    )
    ===
    'pending';


$canFeature =
    strtolower(
        (string)
        $photo['approval_status']
    )
    ===
    'approved';


pendingPhotosGetResponse(
    true,
    'Media details loaded successfully.',
    [

        'photo' =>
            $photo,

        'can_approve' =>
            $canApprove,

        'can_feature' =>
            $canFeature

    ]
);