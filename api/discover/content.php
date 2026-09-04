<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function contentResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    contentResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

if (
    session_status() !== PHP_SESSION_ACTIVE
) {
    session_start();
}

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int)$_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {

    contentResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html?return=discover.html'
        ],
        401
    );
}

$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit'] ?? 100
            )
        )
    );

$page =
    max(
        0,
        (int)(
            $_GET['page'] ?? 0
        )
    );

$offset =
    max(
        0,
        (int)(
            $_GET['offset'] ??
            ($page * $limit)
        )
    );

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER CONTENT DB] ' .
        $e->getMessage()
    );

    contentResponse(
        false,
        'Database connection failed.',
        [
            'posts' => []
        ],
        500
    );
}

/*
 * Only approved and public posts are shown.
 *
 * The saved database explicitly stores:
 *
 * posts.content
 * posts.visibility
 * posts.approval_status
 * posts.deleted_at
 *
 * and post media through:
 *
 * post_photos -> photos
 */

$sql = "

    SELECT

        p.id,
        p.user_id,
        p.content,
        p.visibility,
        p.approval_status,
        p.is_featured,
        p.created_at,
        p.updated_at,

        u.username,
        u.full_names,
        u.gender,
        u.country_id,
        u.date_of_birth,

        c.name AS country_name,
        c.iso2 AS country_iso2,

        pr.display_name,
        pr.bio,
        pr.occupation,
        pr.education,
        pr.city,
        pr.relationship_status,
        pr.looking_for,
        pr.interests,

        profile_photo.file_path AS profile_photo,
        profile_photo.thumbnail_path AS profile_thumbnail

    FROM posts p

    INNER JOIN users u
        ON u.id = p.user_id

    LEFT JOIN countries c
        ON c.id = u.country_id

    LEFT JOIN profiles pr
        ON pr.user_id = u.id

    LEFT JOIN photos profile_photo
        ON profile_photo.id =
        (
            SELECT p2.id

            FROM photos p2

            WHERE p2.user_id = u.id

              AND p2.photo_type = 'profile'

              AND p2.approval_status = 'approved'

              AND p2.is_primary = 1

            ORDER BY
                p2.id DESC

            LIMIT 1
        )

    WHERE

        p.approval_status = 'approved'

        AND

        p.visibility = 'public'

        AND

        p.deleted_at IS NULL

        AND

        u.account_status = 'approved'

        AND

        u.email_verified = 1

        AND

        u.is_active = 1

        AND

        u.is_suspended = 0

        AND

        u.is_deleted = 0

    ORDER BY

        p.created_at DESC,

        p.id DESC

    LIMIT :limit_plus_one

    OFFSET :offset

";

try {

    $stmt =
        $pdo->prepare(
            $sql
        );

    $stmt->bindValue(
        ':limit_plus_one',
        $limit + 1,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':offset',
        $offset,
        PDO::PARAM_INT
    );

    $stmt->execute();

    $postRows =
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER CONTENT QUERY] ' .
        $e->getMessage()
    );

    contentResponse(
        false,
        'Public posts could not be loaded.',
        [
            'code' => 'CONTENT_QUERY_ERROR',
            'posts' => []
        ],
        500
    );
}

$hasMore =
    count($postRows) > $limit;

if ($hasMore) {

    array_pop(
        $postRows
    );
}

$posts = [];

foreach ($postRows as $row) {

    $postId =
        (int)$row['id'];

    /*
     * Load every approved attachment for this post.
     */

    try {

        $attachmentStmt =
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

                    pp.display_order

                FROM post_photos pp

                INNER JOIN photos ph
                    ON ph.id = pp.photo_id

                WHERE pp.post_id = :post_id

                  AND ph.approval_status = 'approved'

                ORDER BY

                    pp.display_order ASC,

                    pp.id ASC

                "
            );

        $attachmentStmt->execute(
            [
                ':post_id' =>
                    $postId
            ]
        );

        $attachmentRows =
            $attachmentStmt->fetchAll(
                PDO::FETCH_ASSOC
            );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI DISCOVER ATTACHMENTS] ' .
            $e->getMessage()
        );

        $attachmentRows = [];
    }

    $attachments = [];

    foreach (
        $attachmentRows as $attachment
    ) {

        $attachments[] = [

            'id' =>
                (int)$attachment['id'],

            'name' =>
                (string)$attachment['file_name'],

            'file_name' =>
                (string)$attachment['file_name'],

            'url' =>
                (string)$attachment['file_path'],

            'file_path' =>
                (string)$attachment['file_path'],

            'thumbnail_url' =>
                $attachment['thumbnail_path'] !== null
                    ? (string)$attachment['thumbnail_path']
                    : null,

            'thumbnail_path' =>
                $attachment['thumbnail_path'] !== null
                    ? (string)$attachment['thumbnail_path']
                    : null,

            'mime_type' =>
                $attachment['mime_type'] !== null
                    ? (string)$attachment['mime_type']
                    : 'application/octet-stream',

            'file_size' =>
                $attachment['file_size'] !== null
                    ? (int)$attachment['file_size']
                    : null,

            'width' =>
                $attachment['width'] !== null
                    ? (int)$attachment['width']
                    : null,

            'height' =>
                $attachment['height'] !== null
                    ? (int)$attachment['height']
                    : null,

            'photo_type' =>
                (string)$attachment['photo_type'],

            'display_order' =>
                (int)$attachment['display_order']

        ];
    }

    $posts[] = [

        'id' =>
            $postId,

        'user_id' =>
            (int)$row['user_id'],

        'content' =>
            $row['content'] !== null
                ? (string)$row['content']
                : '',

        'visibility' =>
            (string)$row['visibility'],

        'approval_status' =>
            (string)$row['approval_status'],

        'is_featured' =>
            (bool)$row['is_featured'],

        'created_at' =>
            (string)$row['created_at'],

        'updated_at' =>
            (string)$row['updated_at'],

        'author' => [

            'id' =>
                (int)$row['user_id'],

            'username' =>
                (string)$row['username'],

            'full_name' =>
                (string)$row['full_names'],

            'gender' =>
                (string)$row['gender'],

            'country_id' =>
                $row['country_id'] !== null
                    ? (int)$row['country_id']
                    : null,

            'country_name' =>
                $row['country_name'] !== null
                    ? (string)$row['country_name']
                    : null,

            'country_iso2' =>
                $row['country_iso2'] !== null
                    ? strtoupper(
                        (string)$row['country_iso2']
                    )
                    : null,

            'date_of_birth' =>
                $row['date_of_birth'] !== null
                    ? (string)$row['date_of_birth']
                    : null,

            'display_name' =>
                $row['display_name'] !== null
                    ? (string)$row['display_name']
                    : null,

            'bio' =>
                $row['bio'] !== null
                    ? (string)$row['bio']
                    : null,

            'occupation' =>
                $row['occupation'] !== null
                    ? (string)$row['occupation']
                    : null,

            'education' =>
                $row['education'] !== null
                    ? (string)$row['education']
                    : null,

            'city' =>
                $row['city'] !== null
                    ? (string)$row['city']
                    : null,

            'relationship_status' =>
                $row['relationship_status'] !== null
                    ? (string)$row['relationship_status']
                    : null,

            'looking_for' =>
                $row['looking_for'] !== null
                    ? (string)$row['looking_for']
                    : null,

            'interests' =>
                $row['interests'] !== null
                    ? (string)$row['interests']
                    : null,

            'profile_photo' =>
                $row['profile_photo'] !== null
                    ? (string)$row['profile_photo']
                    : null,

            'profile_thumbnail' =>
                $row['profile_thumbnail'] !== null
                    ? (string)$row['profile_thumbnail']
                    : null

        ],

        'attachments' =>
            $attachments

    ];
}

contentResponse(
    true,
    'Approved public posts loaded successfully.',
    [

        'count' =>
            count($posts),

        'page' =>
            $page,

        'limit' =>
            $limit,

        'offset' =>
            $offset,

        'has_more' =>
            $hasMore,

        'posts' =>
            $posts,

        'data' =>
            $posts

    ]
);