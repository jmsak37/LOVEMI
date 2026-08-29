<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function deletePostResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    &&
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'DELETE'
) {

    deletePostResponse(
        false,
        'Only POST or DELETE requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTH
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
        $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    deletePostResponse(
        false,
        'Please log in first.',
        [

            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'

        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $raw,
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$postId =
    (int)
    (
        $input['post_id']
        ??
        $input['id']
        ??
        ($_GET['post_id'] ?? 0)
    );


if (
    $postId <= 0
) {

    deletePostResponse(
        false,
        'Post ID is required.',
        [
            'code' =>
                'POST_ID_REQUIRED'
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
        '[LOVEMI DELETE POST DB] '
        .
        $e->getMessage()
    );


    deletePostResponse(
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
   LOAD POST
============================================================ */

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

            WHERE id =
                  :post_id

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
        '[LOVEMI DELETE POST LOOKUP] '
        .
        $e->getMessage()
    );


    deletePostResponse(
        false,
        'Unable to load the post.',
        [
            'code' =>
                'POST_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$post
) {

    deletePostResponse(
        false,
        'Post not found.',
        [
            'code' =>
                'POST_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   OWNER CHECK
============================================================ */

if (
    (int)
    $post['user_id']
    !==
    $userId
) {

    deletePostResponse(
        false,
        'You can only delete your own posts.',
        [
            'code' =>
                'NOT_POST_OWNER'
        ],
        403
    );
}


/* ============================================================
   ALREADY DELETED
============================================================ */

if (
    $post['deleted_at'] !==
    null
) {

    deletePostResponse(
        true,
        'This post has already been deleted.',
        [
            'post_id' =>
                $postId,

            'already_deleted' =>
                true
        ]
    );
}


/* ============================================================
   SOFT DELETE
============================================================ */

try {

    $deleteStmt =
        $pdo->prepare(
            "
            UPDATE posts

            SET

                deleted_at =
                    CURRENT_TIMESTAMP,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id =
                :post_id

              AND user_id =
                  :user_id

              AND deleted_at IS NULL

            LIMIT 1
            "
        );


    $deleteStmt->execute(
        [

            ':post_id' =>
                $postId,

            ':user_id' =>
                $userId

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE POST UPDATE] '
        .
        $e->getMessage()
    );


    deletePostResponse(
        false,
        'Unable to delete the post.',
        [
            'code' =>
                'POST_DELETE_FAILED'
        ],
        500
    );
}


if (
    $deleteStmt->rowCount() !==
    1
) {

    deletePostResponse(
        false,
        'The post could not be deleted.',
        [
            'code' =>
                'POST_NOT_UPDATED'
        ],
        409
    );
}


/* ============================================================
   RESPONSE
============================================================ */

deletePostResponse(
    true,
    'Post deleted successfully.',
    [

        'post_id' =>
            $postId,

        'deleted' =>
            true,

        'deleted_at' =>
            date(
                'Y-m-d H:i:s'
            )

    ]
);