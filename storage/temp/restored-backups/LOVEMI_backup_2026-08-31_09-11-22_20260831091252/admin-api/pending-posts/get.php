<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET PENDING POST
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

function pendingPostsGetResponse(
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
    !empty($_SERVER['HTTPS'])
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

    pendingPostsGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN
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

    pendingPostsGetResponse(
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
                    'posts.manage'

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

        pendingPostsGetResponse(
            false,
            'You do not have permission to manage posts.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingPostsGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| POST ID
|--------------------------------------------------------------------------
*/

$postId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $postId <= 0
) {

    pendingPostsGetResponse(
        false,
        'A valid post ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| POST
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.user_id,

                p.content,

                p.visibility,

                p.approval_status,

                p.is_featured,

                p.created_at,

                p.updated_at,

                p.approved_at,

                u.username,

                u.full_names,

                (
                    SELECT
                        ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id =
                            u.id

                        AND ph.photo_type =
                            'profile'

                        AND ph.is_primary =
                            1

                        AND ph.approval_status =
                            'approved'

                    ORDER BY
                        ph.id DESC

                    LIMIT 1

                ) AS avatar

            FROM posts p

            INNER JOIN users u
                ON u.id =
                    p.user_id

            WHERE

                p.id =
                    :post_id

                AND p.deleted_at IS NULL

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING POST GET] '
        .
        $e->getMessage()
    );


    pendingPostsGetResponse(
        false,
        'Unable to load post details.',
        [],
        500
    );

}


if (
    !$post
) {

    pendingPostsGetResponse(
        false,
        'Post not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| MEDIA
|--------------------------------------------------------------------------
*/

try {

    $mediaStmt =
        $pdo->prepare(
            "
            SELECT

                ph.id,

                ph.file_name,

                ph.file_path,

                ph.thumbnail_path,

                ph.mime_type,

                ph.file_size,

                ph.width,

                ph.height,

                ph.photo_type,

                ph.approval_status,

                ppx.display_order

            FROM post_photos ppx

            INNER JOIN photos ph
                ON ph.id =
                    ppx.photo_id

            WHERE

                ppx.post_id =
                    :post_id

            ORDER BY

                ppx.display_order ASC,

                ppx.id ASC
            "
        );


    $mediaStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $media =
        $mediaStmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING POST MEDIA] '
        .
        $e->getMessage()
    );


    $media =
        [];

}


/*
|--------------------------------------------------------------------------
| PRIMARY MEDIA
|--------------------------------------------------------------------------
*/

$primaryMedia =
    null;


foreach (
    $media as $item
) {

    if (
        strtolower(
            (string)
            $item['approval_status']
        )
        ===
        'approved'
    ) {

        $primaryMedia =
            $item;

        break;

    }

}


/*
|--------------------------------------------------------------------------
| PRIMARY MEDIA DATA
|--------------------------------------------------------------------------
*/

$post['media_url'] =
    $primaryMedia['file_path']
    ??
    null;


$post['thumbnail_url'] =
    $primaryMedia['thumbnail_path']
    ??
    (
        $primaryMedia['file_path']
        ??
        null
    );


$post['media_type'] =
    'text';


if (
    $primaryMedia
) {

    $mime =
        strtolower(
            (string)
            (
                $primaryMedia['mime_type']
                ??
                ''
            )
        );


    if (
        str_starts_with(
            $mime,
            'video/'
        )
    ) {

        $post['media_type'] =
            'video';

    } elseif (
        str_starts_with(
            $mime,
            'image/'
        )
    ) {

        $post['media_type'] =
            'image';

    } else {

        $post['media_type'] =
            'media';

    }

}


/*
|--------------------------------------------------------------------------
| CAN APPROVE
|--------------------------------------------------------------------------
*/

$post['can_approve'] =
    strtolower(
        (string)
        $post['approval_status']
    )
    ===
    'pending';


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

pendingPostsGetResponse(
    true,
    'Post details loaded successfully.',
    [

        'post' =>
            $post,

        'media' =>
            $media,

        'can_approve' =>
            $post['can_approve']

    ]
);