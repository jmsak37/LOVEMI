<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN UPDATE POST
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


function updatePostResponse(
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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    updatePostResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );
}


$data =
    json_decode(
        file_get_contents('php://input') ?: '{}',
        true
    );

if (!is_array($data)) {
    $data = $_POST;
}


$postId =
    (int)(
        $data['post_id']
        ??
        0
    );

$content =
    trim(
        (string)(
            $data['content']
            ??
            ''
        )
    );

$visibility =
    strtolower(
        trim(
            (string)(
                $data['visibility']
                ??
                'public'
            )
        )
    );

$isFeatured =
    filter_var(
        $data['is_featured']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


if ($postId <= 0) {

    updatePostResponse(
        false,
        'A valid post ID is required.',
        [],
        422
    );
}


if (
    $content === ''
) {

    updatePostResponse(
        false,
        'Post content cannot be empty.',
        [],
        422
    );
}


if (
    mb_strlen(
        $content
    ) >
    10000
) {

    updatePostResponse(
        false,
        'Post content is too long.',
        [],
        422
    );
}


$validVisibility = [
    'public',
    'private',
    'connections'
];


if (
    !in_array(
        $visibility,
        $validVisibility,
        true
    )
) {

    updatePostResponse(
        false,
        'Invalid visibility option.',
        [],
        422
    );
}


try {

    $pdo = db();

} catch (Throwable $e) {

    updatePostResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


$adminId =
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
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    updatePostResponse(
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
| ADMIN AUTH
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

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
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);

    if (!$auth->fetch()) {

        updatePostResponse(
            false,
            'You do not have permission to edit posts.',
            [],
            403
        );
    }

} catch (Throwable $e) {

    updatePostResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| CURRENT VALUES
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                content,

                visibility,

                approval_status,

                is_featured,

                deleted_at

            FROM posts

            WHERE
                id = :post_id

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

    updatePostResponse(
        false,
        'Unable to load post.',
        [],
        500
    );
}


if (!$post) {

    updatePostResponse(
        false,
        'Post not found.',
        [],
        404
    );
}


if (
    $post['deleted_at'] !== null
) {

    updatePostResponse(
        false,
        'A deleted post cannot be edited.',
        [],
        409
    );
}


/*
|--------------------------------------------------------------------------
| UPDATE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE posts

            SET

                content =
                    :content,

                visibility =
                    :visibility,

                is_featured =
                    :is_featured

            WHERE
                id = :post_id

            LIMIT 1
            "
        );

    $update->execute([
        ':content' =>
            $content,

        ':visibility' =>
            $visibility,

        ':is_featured' =>
            $isFeatured
                ? 1
                : 0,

        ':post_id' =>
            $postId
    ]);


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
                'post_updated',
                'post',
                :entity_id,
                :old_values,
                :new_values,
                :ip,
                :agent
            )
            "
        );

    $audit->execute([
        ':user_id' =>
            $adminId,

        ':entity_id' =>
            $postId,

        ':old_values' =>
            json_encode([
                'content' =>
                    $post['content'],

                'visibility' =>
                    $post['visibility'],

                'is_featured' =>
                    (int)
                    $post['is_featured']
            ]),

        ':new_values' =>
            json_encode([
                'content' =>
                    $content,

                'visibility' =>
                    $visibility,

                'is_featured' =>
                    $isFeatured
                        ? 1
                        : 0
            ]),

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

} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        '[LOVEMI POST UPDATE] ' .
        $e->getMessage()
    );

    updatePostResponse(
        false,
        'Unable to update post.',
        [],
        500
    );
}


updatePostResponse(
    true,
    'Post updated successfully.',
    [
        'post_id' =>
            $postId
    ]
);