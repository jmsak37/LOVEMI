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

function updatePostResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'PUT'
) {

    updatePostResponse(
        false,
        'Only POST or PUT requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTH
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    updatePostResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw = file_get_contents('php://input');

$input = json_decode(
    (string) $raw,
    true
);

if (!is_array($input)) {
    $input = $_POST;
}


$postId =
    (int)
    (
        $input['post_id']
        ??
        $input['id']
        ??
        0
    );


$content =
    trim(
        (string)
        (
            $input['content']
            ??
            ''
        )
    );


$visibility =
    strtolower(
        trim(
            (string)
            (
                $input['visibility']
                ??
                'public'
            )
        )
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    $postId <= 0
) {

    updatePostResponse(
        false,
        'Post ID is required.',
        [
            'code' =>
                'POST_ID_REQUIRED'
        ],
        422
    );
}


if (
    $content === ''
) {

    updatePostResponse(
        false,
        'Post content is required.',
        [
            'code' =>
                'CONTENT_REQUIRED'
        ],
        422
    );
}


if (
    mb_strlen($content) >
    10000
) {

    updatePostResponse(
        false,
        'Your post is too long. Maximum allowed length is 10,000 characters.',
        [
            'code' =>
                'CONTENT_TOO_LONG'
        ],
        422
    );
}


$allowedVisibility =
    [
        'public',
        'connections',
        'private'
    ];


if (
    !in_array(
        $visibility,
        $allowedVisibility,
        true
    )
) {

    updatePostResponse(
        false,
        'Invalid visibility option.',
        [
            'code' =>
                'INVALID_VISIBILITY',

            'allowed' =>
                $allowedVisibility
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
        '[LOVEMI UPDATE POST DB] '
        .
        $e->getMessage()
    );


    updatePostResponse(
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
   VERIFY PREMIUM
============================================================ */

try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT

                s.id,
                s.status,
                s.end_at,

                sv.slug,
                sv.is_premium,
                sv.is_active

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id =
                   s.service_id

            WHERE s.user_id =
                  :user_id

              AND s.status =
                  'active'

              AND s.end_at >
                  CURRENT_TIMESTAMP

              AND sv.slug =
                  'lovemi-premium'

              AND sv.is_premium =
                  1

              AND sv.is_active =
                  1

            ORDER BY
                s.end_at DESC,
                s.id DESC

            LIMIT 1
            "
        );


    $premiumStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $premium =
        $premiumStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE POST PREMIUM] '
        .
        $e->getMessage()
    );


    updatePostResponse(
        false,
        'Unable to verify Premium access.',
        [
            'code' =>
                'PREMIUM_CHECK_FAILED'
        ],
        500
    );
}


if (
    !$premium
) {

    updatePostResponse(
        false,
        'An active LOVEMI Premium subscription is required to edit posts.',
        [
            'code' =>
                'PREMIUM_REQUIRED',

            'redirect' =>
                'premium.html'
        ],
        403
    );
}


/* ============================================================
   LOAD POST
============================================================ */

try {

    $postStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                content,
                visibility,
                approval_status,
                is_featured,
                created_at,
                updated_at

            FROM posts

            WHERE id =
                  :post_id

              AND deleted_at IS NULL

            LIMIT 1
            "
        );


    $postStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $postStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE POST LOOKUP] '
        .
        $e->getMessage()
    );


    updatePostResponse(
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

    updatePostResponse(
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

    updatePostResponse(
        false,
        'You can only edit your own posts.',
        [
            'code' =>
                'NOT_POST_OWNER'
        ],
        403
    );
}


/* ============================================================
   UPDATE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            UPDATE posts

            SET

                content =
                    :content,

                visibility =
                    :visibility,

                approval_status =
                    'pending',

                approved_at =
                    NULL,

                approved_by =
                    NULL

            WHERE id =
                :post_id

              AND user_id =
                  :user_id

              AND deleted_at IS NULL

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':content' =>
                $content,

            ':visibility' =>
                $visibility,

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
        '[LOVEMI UPDATE POST] '
        .
        $e->getMessage()
    );


    updatePostResponse(
        false,
        'Unable to update the post.',
        [
            'code' =>
                'POST_UPDATE_FAILED'
        ],
        500
    );
}


if (
    $stmt->rowCount() ===
    0
) {

    updatePostResponse(
        true,
        'No changes were required.',
        [
            'post_id' =>
                $postId
        ]
    );
}


/* ============================================================
   RESPONSE
============================================================ */

updatePostResponse(
    true,
    'Post updated and returned to admin review.',
    [

        'post' => [

            'id' =>
                $postId,

            'content' =>
                $content,

            'visibility' =>
                $visibility,

            'approval_status' =>
                'pending'

        ]

    ]
);