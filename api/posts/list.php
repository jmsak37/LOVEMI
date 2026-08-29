<?php
/**
 * ============================================================
 * LOVEMI - APPROVED POSTS LIST API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\posts\list.php
 *
 * Returns approved image/video posts from MySQL.
 * Database is always the source of truth.
 * No browser cache is used.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function postsResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {
    postsResponse(
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

$status =
    strtolower(
        trim(
            (string)(
                $_GET['status'] ?? 'approved'
            )
        )
    );

$limit =
    (int)(
        $_GET['limit'] ?? 30
    );

$limit =
    max(
        1,
        min(
            50,
            $limit
        )
    );


$offset =
    (int)(
        $_GET['offset'] ?? 0
    );

$offset =
    max(
        0,
        $offset
    );


/*
 * Only approved content is publicly returned by this endpoint.
 */

if (
    $status !== 'approved'
) {
    $status = 'approved';
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS DB] ' . $e->getMessage()
    );

    postsResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR',
            'posts' => []
        ],
        500
    );
}


/* ============================================================
   CURRENT USER
============================================================ */

$currentUserId =
    0;


/*
 * This endpoint does not require authentication for reading
 * approved posts. If a session exists, it is used only to
 * identify the viewer and exclude their own duplicate actions.
 */

if (
    session_status() !== PHP_SESSION_ACTIVE
) {
    session_start();
}


if (
    isset($_SESSION['lovemi_user_id'])
) {

    $currentUserId =
        (int)
        $_SESSION['lovemi_user_id'];

}


/* ============================================================
   QUERY
============================================================ */

/*
 * Expected database structure:
 *
 * posts:
 *   id
 *   user_id
 *   content
 *   media_type
 *   media_url
 *   status
 *   created_at
 *
 * users:
 *   id
 *   username
 *   full_names
 *   gender
 *   email_verified
 *   is_active
 *   is_suspended
 *   is_deleted
 *
 * profiles:
 *   user_id
 *   profile_photo
 *
 * countries:
 *   id
 *   name
 *   iso2
 *
 * We intentionally do not return:
 *   phone_number
 *   phone_e164
 *   id_number_hash
 */

try {

    $sql = "
        SELECT

            p.id,
            p.user_id,
            p.content,
            p.media_type,
            p.media_url,
            p.status,
            p.created_at,

            u.username,
            u.full_names,
            u.gender,
            u.email_verified,

            c.name AS country_name,
            c.iso2 AS country_iso2,

            pr.profile_photo

        FROM posts p

        INNER JOIN users u
            ON u.id = p.user_id

        LEFT JOIN countries c
            ON c.id = u.country_id

        LEFT JOIN profiles pr
            ON pr.user_id = u.id

        WHERE

            p.status = :status

            AND u.email_verified = TRUE

            AND u.is_active = TRUE

            AND u.is_suspended = FALSE

            AND u.is_deleted = FALSE

        ORDER BY
            p.created_at DESC,
            p.id DESC

        LIMIT :limit
        OFFSET :offset
    ";


    $stmt =
        $pdo->prepare(
            $sql
        );


    $stmt->bindValue(
        ':status',
        $status,
        PDO::PARAM_STR
    );


    $stmt->bindValue(
        ':limit',
        $limit,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':offset',
        $offset,
        PDO::PARAM_INT
    );


    $stmt->execute();


    $posts =
        $stmt->fetchAll();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS QUERY] ' .
        $e->getMessage()
    );

    postsResponse(
        false,
        'Approved posts could not be loaded.',
        [
            'code' => 'POST_QUERY_ERROR',
            'posts' => []
        ],
        500
    );
}


/* ============================================================
   CLEAN RESPONSE
============================================================ */

$cleanPosts = [];


foreach (
    $posts as $post
) {

    $mediaType =
        strtolower(
            trim(
                (string)(
                    $post['media_type']
                    ?? ''
                )
            )
        );


    if (
        !in_array(
            $mediaType,
            [
                'image',
                'photo',
                'video'
            ],
            true
        )
    ) {

        $mediaType =
            'image';

    }


    $cleanPosts[] = [

        'id' =>
            (int)
            $post['id'],

        'user_id' =>
            (int)
            $post['user_id'],

        'username' =>
            (string)
            $post['username'],

        'full_name' =>
            (string)
            $post['full_names'],

        'gender' =>
            (string)
            $post['gender'],

        'country_name' =>
            $post['country_name'] !== null
                ? (string)$post['country_name']
                : null,

        'country_iso2' =>
            $post['country_iso2'] !== null
                ? strtoupper(
                    (string)$post['country_iso2']
                )
                : null,

        'email_verified' =>
            (bool)
            $post['email_verified'],

        'avatar' =>
            $post['profile_photo'] !== null
                ? (string)$post['profile_photo']
                : null,

        'content' =>
            (string)
            ($post['content'] ?? ''),

        'media_type' =>
            $mediaType,

        'media_url' =>
            $post['media_url'] !== null
                ? (string)$post['media_url']
                : null,

        'status' =>
            'approved',

        'created_at' =>
            (string)
            $post['created_at']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

postsResponse(
    true,
    'Approved posts loaded successfully.',
    [
        'count' =>
            count($cleanPosts),

        'posts' =>
            $cleanPosts,

        'data' =>
            $cleanPosts
    ]
);