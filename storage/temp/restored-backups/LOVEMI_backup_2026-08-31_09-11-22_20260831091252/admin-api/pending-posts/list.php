<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - PENDING POSTS LIST
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

function pendingPostsListResponse(
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

    error_log(
        '[LOVEMI PENDING POSTS DB] '
        .
        $e->getMessage()
    );


    pendingPostsListResponse(
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

    pendingPostsListResponse(
        false,
        'You must log in first.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
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
| ADMIN AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                r.name AS role_name,

                r.slug AS role_slug

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions p
                ON p.id = rp.permission_id

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


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING POSTS AUTH] '
        .
        $e->getMessage()
    );


    pendingPostsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    pendingPostsListResponse(
        false,
        'You do not have permission to manage posts.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/*
|--------------------------------------------------------------------------
| PARAMETERS
|--------------------------------------------------------------------------
*/

$page =
    max(
        1,
        (int)(
            $_GET['page']
            ??
            1
        )
    );


$limit =
    max(
        5,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                20
            )
        )
    );


$offset =
    (
        $page - 1
    )
    *
    $limit;


$search =
    trim(
        (string)(
            $_GET['search']
            ??
            ''
        )
    );


$media =
    strtolower(
        trim(
            (string)(
                $_GET['media']
                ??
                ''
            )
        )
    );


$sort =
    strtolower(
        trim(
            (string)(
                $_GET['sort']
                ??
                'oldest'
            )
        )
    );


/*
|--------------------------------------------------------------------------
| CONDITIONS
|--------------------------------------------------------------------------
*/

$where =
    [

        "
        LOWER(
            p.approval_status
        ) = 'pending'
        ",

        "
        p.deleted_at IS NULL
        "

    ];


$params =
    [];


/*
|--------------------------------------------------------------------------
| SEARCH
|--------------------------------------------------------------------------
*/

if (
    $search !== ''
) {

    $where[] =
        "
        (
            p.content LIKE :content

            OR u.username LIKE :username

            OR u.full_names LIKE :full_names

            OR CAST(
                p.id AS CHAR
            ) LIKE :post_id
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[':content'] =
        $like;


    $params[':username'] =
        $like;


    $params[':full_names'] =
        $like;


    $params[':post_id'] =
        $like;

}


/*
|--------------------------------------------------------------------------
| MEDIA FILTER
|--------------------------------------------------------------------------
|
| Post media is represented through post_photos -> photos.
|
*/

switch (
    $media
) {

    case 'with_media':

        $where[] =
            "
            EXISTS
            (
                SELECT 1

                FROM post_photos ppx

                INNER JOIN photos phx
                    ON phx.id = ppx.photo_id

                WHERE
                    ppx.post_id = p.id

                  AND LOWER(
                        phx.approval_status
                      )
                      =
                      'approved'
            )
            ";

        break;


    case 'text_only':

        $where[] =
            "
            NOT EXISTS
            (
                SELECT 1

                FROM post_photos ppx

                INNER JOIN photos phx
                    ON phx.id = ppx.photo_id

                WHERE
                    ppx.post_id = p.id

                  AND LOWER(
                        phx.approval_status
                      )
                      =
                      'approved'
            )
            ";

        break;


    case 'image':

        $where[] =
            "
            EXISTS
            (
                SELECT 1

                FROM post_photos ppx

                INNER JOIN photos phx
                    ON phx.id = ppx.photo_id

                WHERE

                    ppx.post_id = p.id

                    AND LOWER(
                        phx.approval_status
                    ) = 'approved'

                    AND LOWER(
                        phx.mime_type
                    ) LIKE 'image/%'
            )
            ";

        break;


    case 'video':

        $where[] =
            "
            EXISTS
            (
                SELECT 1

                FROM post_photos ppx

                INNER JOIN photos phx
                    ON phx.id = ppx.photo_id

                WHERE

                    ppx.post_id = p.id

                    AND LOWER(
                        phx.approval_status
                    ) = 'approved'

                    AND LOWER(
                        phx.mime_type
                    ) LIKE 'video/%'
            )
            ";

        break;

}


/*
|--------------------------------------------------------------------------
| WHERE
|--------------------------------------------------------------------------
*/

$whereSql =
    'WHERE '
    .
    implode(
        ' AND ',
        $where
    );


/*
|--------------------------------------------------------------------------
| SORT
|--------------------------------------------------------------------------
*/

$orderBy =
    $sort ===
    'newest'
        ?
        'p.created_at DESC, p.id DESC'
        :
        'p.created_at ASC, p.id ASC';


/*
|--------------------------------------------------------------------------
| TOTAL
|--------------------------------------------------------------------------
*/

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT
                COUNT(*)

            FROM posts p

            INNER JOIN users u
                ON u.id = p.user_id

            {$whereSql}
            "
        );


    $countStmt->execute(
        $params
    );


    $total =
        (int)
        $countStmt->fetchColumn();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING POSTS COUNT] '
        .
        $e->getMessage()
    );


    pendingPostsListResponse(
        false,
        'Unable to count pending posts.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| POSTS
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

                u.username,

                u.full_names,

                (
                    SELECT
                        ph.file_path

                    FROM post_photos ppx

                    INNER JOIN photos ph
                        ON ph.id =
                            ppx.photo_id

                    WHERE

                        ppx.post_id =
                            p.id

                        AND LOWER(
                            ph.approval_status
                        ) =
                        'approved'

                        AND LOWER(
                            ph.mime_type
                        ) LIKE 'image/%'

                    ORDER BY
                        ppx.display_order ASC,
                        ppx.id ASC

                    LIMIT 1

                ) AS thumbnail_url,

                (
                    SELECT
                        ph.file_path

                    FROM post_photos ppx

                    INNER JOIN photos ph
                        ON ph.id =
                            ppx.photo_id

                    WHERE

                        ppx.post_id =
                            p.id

                        AND LOWER(
                            ph.approval_status
                        ) =
                        'approved'

                    ORDER BY
                        ppx.display_order ASC,
                        ppx.id ASC

                    LIMIT 1

                ) AS media_url,

                (
                    SELECT
                        CASE

                            WHEN LOWER(
                                ph.mime_type
                            ) LIKE 'video/%'
                            THEN 'video'

                            WHEN LOWER(
                                ph.mime_type
                            ) LIKE 'image/%'
                            THEN 'image'

                            ELSE 'media'

                        END

                    FROM post_photos ppx

                    INNER JOIN photos ph
                        ON ph.id =
                            ppx.photo_id

                    WHERE

                        ppx.post_id =
                            p.id

                        AND LOWER(
                            ph.approval_status
                        ) =
                        'approved'

                    ORDER BY
                        ppx.display_order ASC,
                        ppx.id ASC

                    LIMIT 1

                ) AS media_type,

                (
                    EXISTS
                    (
                        SELECT 1

                        FROM post_photos ppx2

                        INNER JOIN photos ph2
                            ON ph2.id =
                                ppx2.photo_id

                        WHERE

                            ppx2.post_id =
                                p.id

                            AND LOWER(
                                ph2.approval_status
                            ) =
                            'approved'
                    )
                ) AS has_media

            FROM posts p

            INNER JOIN users u
                ON u.id =
                    p.user_id

            {$whereSql}

            ORDER BY
                {$orderBy}

            LIMIT :limit

            OFFSET :offset
            "
        );


    foreach (
        $params as $key => $value
    ) {

        $stmt->bindValue(
            $key,
            $value
        );

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


    $posts =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING POSTS QUERY] '
        .
        $e->getMessage()
    );


    pendingPostsListResponse(
        false,
        'Unable to load pending posts.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| CAN APPROVE
|--------------------------------------------------------------------------
*/

foreach (
    $posts as &$post
) {

    /*
     * A pending post with valid user account is approvable.
     */

    $post['can_approve'] =
        true;

}


unset(
    $post
);


/*
|--------------------------------------------------------------------------
| SUMMARY
|--------------------------------------------------------------------------
*/

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS pending,

                SUM(
                    DATE(
                        created_at
                    ) =
                    CURRENT_DATE
                ) AS today,

                SUM(
                    EXISTS
                    (
                        SELECT 1

                        FROM post_photos ppx

                        INNER JOIN photos phx
                            ON phx.id =
                                ppx.photo_id

                        WHERE

                            ppx.post_id =
                                posts.id

                            AND LOWER(
                                phx.approval_status
                            ) =
                            'approved'
                    )
                ) AS with_media,

                SUM(
                    is_featured =
                    1
                ) AS featured_pending

            FROM posts

            WHERE

                LOWER(
                    approval_status
                ) =
                'pending'

                AND deleted_at IS NULL
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary =
        [

            'pending' =>
                0,

            'today' =>
                0,

            'with_media' =>
                0,

            'featured_pending' =>
                0

        ];

}


/*
|--------------------------------------------------------------------------
| ADMIN AVATAR
|--------------------------------------------------------------------------
*/

$adminAvatar =
    null;


try {

    $avatarStmt =
        $pdo->prepare(
            "
            SELECT
                file_path

            FROM photos

            WHERE

                user_id =
                    :user_id

                AND photo_type =
                    'profile'

                AND is_primary =
                    1

                AND approval_status =
                    'approved'

            ORDER BY
                id DESC

            LIMIT 1
            "
        );


    $avatarStmt->execute(
        [
            ':user_id' =>
                $adminId
        ]
    );


    $adminAvatar =
        $avatarStmt->fetchColumn()
        ?:
        null;

} catch (
    Throwable $e
) {

}


/*
|--------------------------------------------------------------------------
| SESSION ACTIVITY
|--------------------------------------------------------------------------
*/

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE

                id =
                    :session_id

                AND user_id =
                    :user_id

            LIMIT 1
            "
        );


    $activity->execute(
        [

            ':session_id' =>
                $sessionId,

            ':user_id' =>
                $adminId

        ]
    );

} catch (
    Throwable $e
) {

}


/*
|--------------------------------------------------------------------------
| PAGINATION
|--------------------------------------------------------------------------
*/

$pages =
    $total > 0
        ?
        (int)
        ceil(
            $total / $limit
        )
        :
        1;


pendingPostsListResponse(
    true,
    'Pending posts loaded successfully.',
    [

        'admin' => [

            'id' =>
                (int)
                $admin['id'],

            'username' =>
                $admin['username'],

            'full_names' =>
                $admin['full_names'],

            'email' =>
                $admin['email'],

            'role_name' =>
                $admin['role_name'],

            'role_slug' =>
                $admin['role_slug'],

            'avatar_url' =>
                $adminAvatar

        ],

        'summary' => [

            'pending' =>
                (int)(
                    $summary['pending']
                    ??
                    0
                ),

            'today' =>
                (int)(
                    $summary['today']
                    ??
                    0
                ),

            'with_media' =>
                (int)(
                    $summary['with_media']
                    ??
                    0
                ),

            'featured_pending' =>
                (int)(
                    $summary['featured_pending']
                    ??
                    0
                )

        ],

        'posts' =>
            $posts,

        'pagination' => [

            'page' =>
                $page,

            'limit' =>
                $limit,

            'total' =>
                $total,

            'pages' =>
                $pages

        ]

    ]
);