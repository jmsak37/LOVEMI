<?php

declare(strict_types=1);


/* ============================================================
   LOVEMI - ADMIN PHOTOS LIST API
============================================================ */

require_once __DIR__ . '/../../config/database.php';


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

header(
    'X-Content-Type-Options: nosniff'
);


ini_set(
    'display_errors',
    '0'
);


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function photoListResponse(
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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;
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
        '[LOVEMI PHOTOS LIST DB] '
        .
        $e->getMessage()
    );


    photoListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   CURRENT SESSION
============================================================ */

$userId =
    (int)(
        $_SESSION[
            'lovemi_user_id'
        ]
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION[
            'lovemi_database_session_id'
        ]
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION[
            'lovemi_session_token'
        ]
        ??
        ''
    );


if (
    $userId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    photoListResponse(
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


/* ============================================================
   ADMIN AUTHENTICATION
============================================================ */

try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.role_id,

                u.username,

                u.full_names,

                u.email,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role,

                p.display_name,

                ph.file_path AS avatar_url

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            LEFT JOIN photos ph
                ON ph.user_id = u.id

                AND ph.photo_type = 'profile'

                AND ph.is_primary = 1

                AND ph.approval_status = 'approved'

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

            LIMIT 1
            "
        );


    $auth->execute(
        [
            ':user_id' =>
                $userId,

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
        '[LOVEMI PHOTOS ADMIN AUTH] '
        .
        $e->getMessage()
    );


    photoListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    photoListResponse(
        false,
        'Administrator access is required.',
        [
            'code' =>
                'ADMIN_ACCESS_REQUIRED'
        ],
        403
    );

}


/* ============================================================
   PERMISSION
============================================================ */

try {

    $permissionStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                rp.role_id =
                    :role_id

                AND p.slug =
                    'photos.manage'
            "
        );


    $permissionStmt->execute(
        [
            ':role_id' =>
                (int)
                $admin[
                    'role_id'
                ]
        ]
    );


    $allowed =
        (int)
        $permissionStmt->fetchColumn()
        >
        0;

} catch (
    Throwable $e
) {

    photoListResponse(
        false,
        'Unable to verify photo-management permission.',
        [],
        500
    );

}


if (
    !$allowed
) {

    photoListResponse(
        false,
        'You do not have permission to manage photos.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   INPUT
============================================================ */

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
        4,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                16
            )
        )
    );


$offset =
    (
        $page -
        1
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


$status =
    strtolower(
        trim(
            (string)(
                $_GET['status']
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


$validStatuses = [

    'pending',
    'approved',
    'rejected'

];


$validTypes = [

    'profile',
    'post',
    'gallery',
    'other'

];


if (
    !in_array(
        $status,
        $validStatuses,
        true
    )
) {

    $status = '';

}


if (
    !in_array(
        $photoType,
        $validTypes,
        true
    )
) {

    $photoType = '';

}


/* ============================================================
   FILTER CONDITIONS
============================================================ */

$where = [];

$params = [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            u.username LIKE :search
            OR u.full_names LIKE :search
            OR ph.file_name LIKE :search
        )
        ";

    $params[
        ':search'
    ] =
        '%' .
        $search .
        '%';

}


if (
    $status !== ''
) {

    $where[] =
        'ph.approval_status = :status';

    $params[
        ':status'
    ] =
        $status;

}


if (
    $photoType !== ''
) {

    $where[] =
        'ph.photo_type = :photo_type';

    $params[
        ':photo_type'
    ] =
        $photoType;

}


$whereSql =
    $where
        ?
        'WHERE ' .
        implode(
            ' AND ',
            $where
        )
        :
        '';


/* ============================================================
   TOTAL COUNT
============================================================ */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

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
        '[LOVEMI PHOTOS COUNT] '
        .
        $e->getMessage()
    );


    photoListResponse(
        false,
        'Unable to count photos.',
        [],
        500
    );

}


/* ============================================================
   LOAD PHOTOS
============================================================ */

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

                u.full_names,

                u.email,

                p.display_name,

                c.name AS country_name

            FROM photos ph

            INNER JOIN users u
                ON u.id =
                    ph.user_id

            LEFT JOIN profiles p
                ON p.user_id =
                    u.id

            LEFT JOIN countries c
                ON c.id =
                    u.country_id

            {$whereSql}

            ORDER BY

                CASE
                    WHEN ph.approval_status = 'pending'
                    THEN 0

                    WHEN ph.approval_status = 'approved'
                    THEN 1

                    ELSE 2

                END,

                ph.uploaded_at DESC

            LIMIT :limit

            OFFSET :offset
            "
        );


    foreach (
        $params as $key =>
        $value
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
        '[LOVEMI PHOTOS LOAD] '
        .
        $e->getMessage()
    );


    photoListResponse(
        false,
        'Unable to load photos.',
        [],
        500
    );

}


/* ============================================================
   SUMMARY
============================================================ */

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS total,

                SUM(
                    approval_status = 'pending'
                ) AS pending,

                SUM(
                    approval_status = 'approved'
                ) AS approved,

                SUM(
                    approval_status = 'rejected'
                ) AS rejected

            FROM photos
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary = [

        'total' =>
            0,

        'pending' =>
            0,

        'approved' =>
            0,

        'rejected' =>
            0

    ];

}


/* ============================================================
   UPDATE ACTIVITY
============================================================ */

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
                $userId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PHOTOS ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

$pages =
    $total > 0
        ?
        (int)ceil(
            $total /
            $limit
        )
        :
        1;


$adminAvatar =
    $admin[
        'avatar_url'
    ]
    ??
    null;


photoListResponse(
    true,
    'Photos loaded successfully.',
    [
        'current_admin' => [

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

        'photos' =>
            $photos,

        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ??
                    0
                ),

            'pending' =>
                (int)(
                    $summary['pending']
                    ??
                    0
                ),

            'approved' =>
                (int)(
                    $summary['approved']
                    ??
                    0
                ),

            'rejected' =>
                (int)(
                    $summary['rejected']
                    ??
                    0
                )

        ],

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