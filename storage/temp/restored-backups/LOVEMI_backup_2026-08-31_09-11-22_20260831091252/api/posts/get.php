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

function getPostResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    getPostResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   INPUT
============================================================ */

$postId =
    (int) (
        $_GET['post_id']
        ??
        $_GET['id']
        ??
        0
    );


if ($postId <= 0) {

    getPostResponse(
        false,
        'Post ID is required.',
        [
            'code' => 'POST_ID_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   OPTIONAL SESSION
============================================================ */

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET POST DB] ' .
        $e->getMessage()
    );

    getPostResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   POST
============================================================ */

try {

    $stmt = $pdo->prepare(
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
            u.gender,

            pr.display_name,
            pr.bio,
            pr.city

        FROM posts p

        INNER JOIN users u
            ON u.id = p.user_id

        LEFT JOIN profiles pr
            ON pr.user_id = u.id

        WHERE p.id = :post_id

          AND p.deleted_at IS NULL

        LIMIT 1
        "
    );


    $stmt->execute([
        ':post_id' => $postId
    ]);


    $post = $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET POST QUERY] ' .
        $e->getMessage()
    );

    getPostResponse(
        false,
        'Unable to load the post.',
        [
            'code' => 'POST_QUERY_FAILED'
        ],
        500
    );
}


if (!$post) {

    getPostResponse(
        false,
        'Post not found.',
        [
            'code' => 'POST_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   USER AVAILABILITY
============================================================ */

if (
    (int) $post['user_id'] !==
    $currentUserId
) {

    /*
     * A deleted, suspended or inactive account's content
     * must not be publicly exposed.
     */

    try {

        $ownerStmt = $pdo->prepare(
            "
            SELECT

                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :user_id

            LIMIT 1
            "
        );

        $ownerStmt->execute([
            ':user_id' =>
                (int) $post['user_id']
        ]);

        $owner =
            $ownerStmt->fetch();

    } catch (Throwable $e) {

        getPostResponse(
            false,
            'Unable to verify the post owner.',
            [
                'code' =>
                    'OWNER_CHECK_FAILED'
            ],
            500
        );
    }


    if (
        !$owner
        ||
        (int) $owner['is_deleted'] === 1
        ||
        (int) $owner['is_suspended'] === 1
        ||
        (int) $owner['is_active'] !== 1
    ) {

        getPostResponse(
            false,
            'This post is no longer available.',
            [
                'code' =>
                    'POST_UNAVAILABLE'
            ],
            404
        );
    }

}


/* ============================================================
   VISIBILITY / APPROVAL
============================================================ */

$isOwner =
    (
        (int)
        $post['user_id']
        ===
        $currentUserId
    );


if (!$isOwner) {

    if (
        $post['approval_status'] !==
        'approved'
    ) {

        getPostResponse(
            false,
            'This post is not publicly available.',
            [
                'code' =>
                    'POST_NOT_APPROVED'
            ],
            404
        );
    }


    if (
        $post['visibility'] !==
        'public'
    ) {

        getPostResponse(
            false,
            'This post is not publicly available.',
            [
                'code' =>
                    'POST_PRIVATE'
            ],
            403
        );
    }

}


/* ============================================================
   POST PHOTOS
============================================================ */

$photos = [];


try {

    $photoStmt = $pdo->prepare(
        "
        SELECT

            pp.id,
            pp.display_order,

            ph.id AS photo_id,
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
            ph.is_featured

        FROM post_photos pp

        INNER JOIN photos ph
            ON ph.id = pp.photo_id

        WHERE pp.post_id = :post_id

          AND
          (
              ph.approval_status = 'approved'

              OR

              (
                  :owner_check = 1
                  AND
                  ph.user_id = :owner_id
              )
          )

        ORDER BY
            pp.display_order ASC,
            pp.id ASC
        "
    );


    $photoStmt->execute([
        ':post_id' =>
            $postId,

        ':owner_check' =>
            $isOwner ? 1 : 0,

        ':owner_id' =>
            $currentUserId
    ]);


    $photoRows =
        $photoStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET POST PHOTOS] ' .
        $e->getMessage()
    );

    $photoRows = [];
}


foreach (
    $photoRows
    as $photo
) {

    $photos[] = [

        'id' =>
            (int)
            $photo['photo_id'],

        'post_photo_id' =>
            (int)
            $photo['id'],

        'display_order' =>
            (int)
            $photo['display_order'],

        'file_name' =>
            $photo['file_name'],

        'file_path' =>
            $photo['file_path'],

        'thumbnail_path' =>
            $photo['thumbnail_path'],

        'mime_type' =>
            $photo['mime_type'],

        'file_size' =>
            $photo['file_size'] !== null
                ?
                (int)
                $photo['file_size']
                :
                null,

        'width' =>
            $photo['width'] !== null
                ?
                (int)
                $photo['width']
                :
                null,

        'height' =>
            $photo['height'] !== null
                ?
                (int)
                $photo['height']
                :
                null,

        'photo_type' =>
            $photo['photo_type'],

        'approval_status' =>
            $photo['approval_status'],

        'is_primary' =>
            (bool)
            $photo['is_primary'],

        'is_featured' =>
            (bool)
            $photo['is_featured']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

getPostResponse(
    true,
    'Post loaded successfully.',
    [

        'post' => [

            'id' =>
                (int)
                $post['id'],

            'user_id' =>
                (int)
                $post['user_id'],

            'content' =>
                $post['content'],

            'visibility' =>
                $post['visibility'],

            'approval_status' =>
                $post['approval_status'],

            'is_featured' =>
                (bool)
                $post['is_featured'],

            'created_at' =>
                $post['created_at'],

            'updated_at' =>
                $post['updated_at'],

            'approved_at' =>
                $post['approved_at'],

            'author' => [

                'id' =>
                    (int)
                    $post['user_id'],

                'username' =>
                    $post['username'],

                'full_names' =>
                    $post['full_names'],

                'display_name' =>
                    $post['display_name']
                    ??
                    $post['full_names'],

                'gender' =>
                    $post['gender'],

                'bio' =>
                    $post['bio'],

                'city' =>
                    $post['city']

            ],

            'photos' =>
                $photos

        ],

        'is_owner' =>
            $isOwner

    ]
);