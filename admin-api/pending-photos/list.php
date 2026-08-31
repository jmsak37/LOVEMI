<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - PENDING PHOTOS LIST
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

function pendingPhotosListResponse(
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
    !empty(
        $_SERVER['HTTPS']
    )
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
        '[LOVEMI PENDING PHOTOS DB] '
        .
        $e->getMessage()
    );


    pendingPhotosListResponse(
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

    pendingPhotosListResponse(
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
                    'photos.manage'

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
        '[LOVEMI PENDING PHOTOS AUTH] '
        .
        $e->getMessage()
    );


    pendingPhotosListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    pendingPhotosListResponse(
        false,
        'You do not have permission to manage photos.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
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


$type =
    strtolower(
        trim(
            (string)(
                $_GET['type']
                ??
                ''
            )
        )
    );


$photoType =
    strtolower(
        trim(
            (string)(
                $_GET['photo_type']
                ??
                ''
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
            ph.approval_status
        ) = 'pending'
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
            ph.file_name LIKE :file_name

            OR u.username LIKE :username

            OR u.full_names LIKE :full_names

            OR CAST(
                ph.id AS CHAR
            ) LIKE :photo_id
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[':file_name'] =
        $like;

    $params[':username'] =
        $like;

    $params[':full_names'] =
        $like;

    $params[':photo_id'] =
        $like;

}


/*
|--------------------------------------------------------------------------
| MEDIA TYPE
|--------------------------------------------------------------------------
*/

if (
    $type ===
    'image'
) {

    $where[] =
        "
        LOWER(
            ph.mime_type
        ) LIKE 'image/%'
        ";

}


if (
    $type ===
    'video'
) {

    $where[] =
        "
        LOWER(
            ph.mime_type
        ) LIKE 'video/%'
        ";

}


/*
|--------------------------------------------------------------------------
| PHOTO CATEGORY
|--------------------------------------------------------------------------
*/

if (
    $photoType !== ''
) {

    $where[] =
        "
        LOWER(
            ph.photo_type
        ) =
        :photo_type
        ";


    $params[':photo_type'] =
        $photoType;

}


$whereSql =
    'WHERE '
    .
    implode(
        ' AND ',
        $where
    );


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

            FROM photos ph

            INNER JOIN users u
                ON u.id =
                    ph.user_id

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
        '[LOVEMI PENDING PHOTOS COUNT] '
        .
        $e->getMessage()
    );


    pendingPhotosListResponse(
        false,
        'Unable to count pending photos.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ROWS
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                ph.id,

                ph.user_id,

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

                ph.is_featured,

                ph.uploaded_at,

                ph.approved_at,

                ph.approved_by,

                u.username,

                u.full_names

            FROM photos ph

            INNER JOIN users u
                ON u.id =
                    ph.user_id

            {$whereSql}

            ORDER BY
                ph.uploaded_at ASC,
                ph.id ASC

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


    $photos =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PENDING PHOTOS QUERY] '
        .
        $e->getMessage()
    );


    pendingPhotosListResponse(
        false,
        'Unable to load pending photos.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| FLAGS
|--------------------------------------------------------------------------
*/

foreach (
    $photos as &$photo
) {

    $photo['can_approve'] =
        strtolower(
            (string)
            $photo['approval_status']
        )
        ===
        'pending';


    /*
     * Feature button is available after approval.
     */

    $photo['can_feature'] =
        strtolower(
            (string)
            $photo['approval_status']
        )
        ===
        'approved';

}


unset(
    $photo
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
                    LOWER(
                        mime_type
                    ) LIKE 'image/%'
                ) AS images,

                SUM(
                    LOWER(
                        mime_type
                    ) LIKE 'video/%'
                ) AS videos,

                SUM(
                    DATE(
                        uploaded_at
                    ) =
                    CURRENT_DATE
                ) AS today

            FROM photos

            WHERE
                LOWER(
                    approval_status
                ) =
                'pending'
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

            'images' =>
                0,

            'videos' =>
                0,

            'today' =>
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
| UPDATE ADMIN ACTIVITY
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


pendingPhotosListResponse(
    true,
    'Pending photos loaded successfully.',
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

            'images' =>
                (int)(
                    $summary['images']
                    ??
                    0
                ),

            'videos' =>
                (int)(
                    $summary['videos']
                    ??
                    0
                ),

            'today' =>
                (int)(
                    $summary['today']
                    ??
                    0
                )

        ],

        'photos' =>
            $photos,

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