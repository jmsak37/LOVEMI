<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function discoverFeedResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'GET'
) {

    discoverFeedResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   SESSION
============================================================ */

if (
    session_status()
    !== PHP_SESSION_ACTIVE
) {

    session_start();

}


$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


if (
    $currentUserId <= 0
) {

    discoverFeedResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=discover.html',

            'posts' =>
                []
        ],
        401
    );

}


/* ============================================================
   INPUT
============================================================ */

$search =
    trim(
        (string)(
            $_GET['search'] ?? ''
        )
    );


$gender =
    trim(
        (string)(
            $_GET['gender'] ?? ''
        )
    );


$countryId =
    max(
        0,
        (int)(
            $_GET['country_id']
            ?? 0
        )
    );


$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit']
                ?? 100
            )
        )
    );


$offset =
    max(
        0,
        (int)(
            $_GET['offset']
            ?? 0
        )
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER FEED DB] '
        .
        $e->getMessage()
    );

    discoverFeedResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR',

            'posts' =>
                []
        ],
        500
    );

}


/* ============================================================
   WHERE
============================================================ */

$where = [

    "p.approval_status = 'approved'",

    "p.visibility = 'public'",

    "p.deleted_at IS NULL",

    "u.account_status = 'approved'",

    "u.email_verified = 1",

    "u.is_active = 1",

    "u.is_suspended = 0",

    "u.is_deleted = 0",

    "(
        pr.profile_visibility IS NULL
        OR
        pr.profile_visibility = 'public'
    )"

];


$params = [];


/* ============================================================
   SEARCH
============================================================ */

if (
    $search !== ''
) {

    $where[] = "

        (

            LOWER(u.username)
                LIKE LOWER(:search_1)

            OR

            LOWER(u.full_names)
                LIKE LOWER(:search_2)

            OR

            LOWER(
                COALESCE(
                    pr.display_name,
                    ''
                )
            )
                LIKE LOWER(:search_3)

            OR

            LOWER(
                COALESCE(
                    pr.bio,
                    ''
                )
            )
                LIKE LOWER(:search_4)

            OR

            LOWER(
                COALESCE(
                    pr.occupation,
                    ''
                )
            )
                LIKE LOWER(:search_5)

            OR

            LOWER(
                COALESCE(
                    pr.city,
                    ''
                )
            )
                LIKE LOWER(:search_6)

            OR

            LOWER(
                COALESCE(
                    pr.interests,
                    ''
                )
            )
                LIKE LOWER(:search_7)

            OR

            LOWER(
                COALESCE(
                    p.content,
                    ''
                )
            )
                LIKE LOWER(:search_8)

            OR

            EXISTS
            (
                SELECT 1

                FROM post_photos pps

                INNER JOIN photos ps
                    ON ps.id = pps.photo_id

                WHERE pps.post_id = p.id

                  AND LOWER(
                        COALESCE(
                            ps.file_name,
                            ''
                        )
                  )
                  LIKE LOWER(:search_9)
            )

        )

    ";


    $searchValue =
        '%'
        .
        $search
        .
        '%';


    $params[':search_1'] =
        $searchValue;

    $params[':search_2'] =
        $searchValue;

    $params[':search_3'] =
        $searchValue;

    $params[':search_4'] =
        $searchValue;

    $params[':search_5'] =
        $searchValue;

    $params[':search_6'] =
        $searchValue;

    $params[':search_7'] =
        $searchValue;

    $params[':search_8'] =
        $searchValue;

    $params[':search_9'] =
        $searchValue;

}


/* ============================================================
   GENDER
============================================================ */

if (
    $gender !== ''
) {

    $allowedGenders = [

        'Male',
        'Female',
        'Other'

    ];


    if (
        in_array(
            $gender,
            $allowedGenders,
            true
        )
    ) {

        $where[] =
            "u.gender = :gender";

        $params[':gender'] =
            $gender;

    }

}


/* ============================================================
   COUNTRY
============================================================ */

if (
    $countryId > 0
) {

    $where[] =
        "u.country_id = :country_id";

    $params[':country_id'] =
        $countryId;

}


/* ============================================================
   MAIN POSTS QUERY
============================================================ */

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
        p.approved_at,

        u.username,
        u.full_names,
        u.gender,
        u.email_verified,
        u.identity_verified,
        u.age_verified,
        u.country_id,
        u.date_of_birth,

        c.name AS country_name,
        c.iso2 AS country_iso2,

        pr.display_name,
        pr.bio,
        pr.occupation,
        pr.city,
        pr.interests,
        pr.profile_visibility,

        profile_photo.file_path
            AS profile_photo,

        profile_photo.thumbnail_path
            AS profile_thumbnail

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
        "
        .
        implode(
            ' AND ',
            $where
        )
        .

    "

    ORDER BY

        p.is_featured DESC,

        p.created_at DESC,

        p.id DESC

    LIMIT :limit

    OFFSET :offset

";


/* ============================================================
   EXECUTE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            $sql
        );


    foreach (
        $params as $key => $value
    ) {

        if (
            in_array(
                $key,
                [
                    ':country_id'
                ],
                true
            )
        ) {

            $stmt->bindValue(
                $key,
                (int)$value,
                PDO::PARAM_INT
            );

        } else {

            $stmt->bindValue(
                $key,
                $value,
                PDO::PARAM_STR
            );

        }

    }


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


    $rows =
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER FEED QUERY] '
        .
        $e->getMessage()
    );

    discoverFeedResponse(
        false,
        'Posts could not be loaded.',
        [
            'code' =>
                'DISCOVER_FEED_QUERY_ERROR',

            'posts' =>
                []
        ],
        500
    );

}


/* ============================================================
   BUILD POSTS
============================================================ */

$posts = [];


$mediaStmt =
    $pdo->prepare(
        "

        SELECT

            pp.id AS post_photo_id,

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

            pp.display_order

        FROM post_photos pp

        INNER JOIN photos ph
            ON ph.id = pp.photo_id

        WHERE

            pp.post_id = :post_id

            AND

            ph.approval_status = 'approved'

        ORDER BY

            pp.display_order ASC,

            pp.id ASC

        "
    );


/* ============================================================
   EACH POST
============================================================ */

foreach (
    $rows as $row
) {

    $postId =
        (int)
        $row['id'];


    $media = [];


    try {

        $mediaStmt->execute(
            [
                ':post_id' =>
                    $postId
            ]
        );


        $mediaRows =
            $mediaStmt->fetchAll(
                PDO::FETCH_ASSOC
            );


        foreach (
            $mediaRows as $mediaRow
        ) {

            $media[] = [

                'post_photo_id' =>
                    (int)
                    $mediaRow[
                        'post_photo_id'
                    ],

                'photo_id' =>
                    (int)
                    $mediaRow[
                        'photo_id'
                    ],

                'file_name' =>
                    (string)
                    $mediaRow[
                        'file_name'
                    ],

                'url' =>
                    (string)
                    $mediaRow[
                        'file_path'
                    ],

                'file_path' =>
                    (string)
                    $mediaRow[
                        'file_path'
                    ],

                'thumbnail' =>
                    $mediaRow[
                        'thumbnail_path'
                    ] !== null
                        ?
                        (string)
                        $mediaRow[
                            'thumbnail_path'
                        ]
                        :
                        null,

                'thumbnail_path' =>
                    $mediaRow[
                        'thumbnail_path'
                    ] !== null
                        ?
                        (string)
                        $mediaRow[
                            'thumbnail_path'
                        ]
                        :
                        null,

                'mime_type' =>
                    $mediaRow[
                        'mime_type'
                    ] !== null
                        ?
                        (string)
                        $mediaRow[
                            'mime_type'
                        ]
                        :
                        null,

                'file_size' =>
                    $mediaRow[
                        'file_size'
                    ] !== null
                        ?
                        (int)
                        $mediaRow[
                            'file_size'
                        ]
                        :
                        null,

                'width' =>
                    $mediaRow[
                        'width'
                    ] !== null
                        ?
                        (int)
                        $mediaRow[
                            'width'
                        ]
                        :
                        null,

                'height' =>
                    $mediaRow[
                        'height'
                    ] !== null
                        ?
                        (int)
                        $mediaRow[
                            'height'
                        ]
                        :
                        null,

                'display_order' =>
                    (int)
                    $mediaRow[
                        'display_order'
                    ]

            ];

        }

    } catch (Throwable $mediaError) {

        error_log(
            '[LOVEMI DISCOVER FEED MEDIA] '
            .
            $mediaError->getMessage()
        );

        $media = [];

    }


    $posts[] = [

        'id' =>
            $postId,

        'post_id' =>
            $postId,

        'user_id' =>
            (int)
            $row['user_id'],

        'author_id' =>
            (int)
            $row['user_id'],

        'content' =>
            $row['content'] !== null
                ?
                (string)
                $row['content']
                :
                '',

        'visibility' =>
            (string)
            $row['visibility'],

        'approval_status' =>
            (string)
            $row['approval_status'],

        'is_featured' =>
            (bool)
            $row['is_featured'],

        'created_at' =>
            (string)
            $row['created_at'],

        'updated_at' =>
            (string)
            $row['updated_at'],

        'approved_at' =>
            $row['approved_at'] !== null
                ?
                (string)
                $row['approved_at']
                :
                null,

        'username' =>
            (string)
            $row['username'],

        'full_name' =>
            (string)
            $row['full_names'],

        'full_names' =>
            (string)
            $row['full_names'],

        'gender' =>
            (string)
            $row['gender'],

        'email_verified' =>
            (bool)
            $row['email_verified'],

        'identity_verified' =>
            (bool)
            $row['identity_verified'],

        'age_verified' =>
            (bool)
            $row['age_verified'],

        'country_id' =>
            $row['country_id'] !== null
                ?
                (int)
                $row['country_id']
                :
                null,

        'country_name' =>
            $row['country_name'] !== null
                ?
                (string)
                $row['country_name']
                :
                null,

        'country_iso2' =>
            $row['country_iso2'] !== null
                ?
                strtoupper(
                    (string)
                    $row['country_iso2']
                )
                :
                null,

        'date_of_birth' =>
            $row['date_of_birth'] !== null
                ?
                (string)
                $row['date_of_birth']
                :
                null,

        'display_name' =>
            $row['display_name'] !== null
                ?
                (string)
                $row['display_name']
                :
                null,

        'bio' =>
            $row['bio'] !== null
                ?
                (string)
                $row['bio']
                :
                null,

        'occupation' =>
            $row['occupation'] !== null
                ?
                (string)
                $row['occupation']
                :
                null,

        'city' =>
            $row['city'] !== null
                ?
                (string)
                $row['city']
                :
                null,

        'interests' =>
            $row['interests'] !== null
                ?
                (string)
                $row['interests']
                :
                null,

        'profile_photo' =>
            $row['profile_photo'] !== null
                ?
                (string)
                $row['profile_photo']
                :
                null,

        'profile_thumbnail' =>
            $row['profile_thumbnail'] !== null
                ?
                (string)
                $row['profile_thumbnail']
                :
                null,

        'photo_url' =>
            $row['profile_photo'] !== null
                ?
                (string)
                $row['profile_photo']
                :
                null,

        /*
         * These are deliberately kept so the existing
         * Discover JavaScript remains compatible.
         */

        'like_count' =>
            0,

        'dislike_count' =>
            0,

        'comment_count' =>
            0,

        'my_reaction' =>
            null,

        /*
         * All approved media belonging to this post.
         */

        'media' =>
            $media,

        /*
         * Compatibility fields when one media item exists.
         */

        'media_url' =>
            !empty($media)
                ?
                $media[0]['url']
                :
                null,

        'mime_type' =>
            !empty($media)
                ?
                $media[0]['mime_type']
                :
                null,

        'file_name' =>
            !empty($media)
                ?
                $media[0]['file_name']
                :
                null

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

discoverFeedResponse(
    true,
    'Approved public posts loaded successfully.',
    [

        'count' =>
            count($posts),

        'posts' =>
            $posts,

        'data' =>
            $posts

    ]
);