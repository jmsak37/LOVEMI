<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN GET POST API
|--------------------------------------------------------------------------
*/

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

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function postsGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        [
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


$postId =
    (int)(
        $_GET['id']
        ??
        0
    );


if ($postId <= 0) {

    postsGetResponse(
        false,
        'A valid post ID is required.',
        [],
        422
    );
}


$userId =
    (int)(
        $_SESSION['lovemi_user_id'] ?? 0
    );

$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id'] ?? 0
    );

$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token'] ?? ''
    );


if (
    $userId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    postsGetResponse(
        false,
        'You must log in first.',
        [],
        401
    );
}


try {

    $pdo = db();

} catch (Throwable $e) {

    postsGetResponse(
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


/*
|--------------------------------------------------------------------------
| ADMIN AUTH + PERMISSION
|--------------------------------------------------------------------------
*/

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

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

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

                AND pm.slug =
                    'posts.manage'

            LIMIT 1
            "
        );

    $auth->execute([
        ':user_id' =>
            $userId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);

    if (!$auth->fetch()) {

        postsGetResponse(
            false,
            'You do not have permission to manage posts.',
            [],
            403
        );
    }

} catch (Throwable $e) {

    postsGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| GET POST
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

                p.approved_by,

                u.username,

                u.full_names,

                u.email,

                u.gender,

                u.country_id,

                c.name AS country_name,

                c.iso2 AS country_iso2,

                pr.display_name,

                pr.bio

            FROM posts p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles pr
                ON pr.user_id = u.id

            WHERE
                p.id = :post_id

            LIMIT 1
            "
        );

    $stmt->execute([
        ':post_id' =>
            $postId
    ]);

    $post =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS GET] ' .
        $e->getMessage()
    );

    postsGetResponse(
        false,
        'Unable to load post.',
        [],
        500
    );
}


if (!$post) {

    postsGetResponse(
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

                ph.id AS photo_id,

                ph.file_name,

                ph.file_path,

                ph.thumbnail_path,

                ph.mime_type,

                ph.file_size,

                ph.width,

                ph.height,

                ph.approval_status,

                pp.display_order

            FROM post_photos pp

            INNER JOIN photos ph
                ON ph.id = pp.photo_id

            WHERE
                pp.post_id = :post_id

            ORDER BY
                pp.display_order ASC,
                pp.id ASC
            "
        );

    $mediaStmt->execute([
        ':post_id' =>
            $postId
    ]);

    $media =
        $mediaStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS GET MEDIA] ' .
        $e->getMessage()
    );

    $media = [];
}


postsGetResponse(
    true,
    'Post loaded successfully.',
    [

        'post' =>
            $post,

        'media' =>
            $media

    ]
);