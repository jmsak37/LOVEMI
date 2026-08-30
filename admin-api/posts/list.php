<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN POSTS LIST API
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');

ini_set('display_errors', '0');


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

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


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function postsListResponse(
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


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS LIST DB] ' .
        $e->getMessage()
    );

    postsListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/*
|--------------------------------------------------------------------------
| AUTHENTICATION
|--------------------------------------------------------------------------
*/

$userId =
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
    $userId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    postsListResponse(
        false,
        'You must log in first.',
        [
            'code' => 'NOT_AUTHENTICATED'
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
| ADMIN + PERMISSION
|--------------------------------------------------------------------------
*/

try {

    $stmt =
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

                p.display_name,

                ph.file_path AS avatar_url

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

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

                AND pm.slug =
                    'posts.manage'

            LIMIT 1
            "
        );

    $stmt->execute([
        ':user_id' =>
            $userId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);

    $admin =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS LIST AUTH] ' .
        $e->getMessage()
    );

    postsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );
}


if (!$admin) {

    postsListResponse(
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
| INPUT
|--------------------------------------------------------------------------
*/

$page =
    max(
        1,
        (int)(
            $_GET['page'] ?? 1
        )
    );

$limit =
    max(
        5,
        min(
            100,
            (int)(
                $_GET['limit'] ?? 20
            )
        )
    );

$offset =
    (
        $page - 1
    ) * $limit;

$search =
    trim(
        (string)(
            $_GET['search'] ?? ''
        )
    );

$status =
    strtolower(
        trim(
            (string)(
                $_GET['status'] ?? ''
            )
        )
    );

$visibility =
    strtolower(
        trim(
            (string)(
                $_GET['visibility'] ?? ''
            )
        )
    );

$featuredRaw =
    trim(
        (string)(
            $_GET['featured'] ?? ''
        )
    );


$validStatuses = [
    'pending',
    'approved',
    'rejected'
];

$validVisibility = [
    'public',
    'private',
    'connections'
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
        $visibility,
        $validVisibility,
        true
    )
) {

    $visibility = '';

}


$featured =
    $featuredRaw === '1'
        ? 1
        :
        (
            $featuredRaw === '0'
                ? 0
                : null
        );


/*
|--------------------------------------------------------------------------
| CONDITIONS
|--------------------------------------------------------------------------
*/

$where = [
    'p.deleted_at IS NULL'
];

$params = [];


if ($search !== '') {

    $where[] =
        "
        (
            p.content LIKE :search

            OR u.username LIKE :search

            OR u.full_names LIKE :search
        )
        ";

    $params[':search'] =
        '%' .
        $search .
        '%';
}


if ($status !== '') {

    $where[] =
        'p.approval_status = :status';

    $params[':status'] =
        $status;
}


if ($visibility !== '') {

    $where[] =
        'p.visibility = :visibility';

    $params[':visibility'] =
        $visibility;
}


if ($featured !== null) {

    $where[] =
        'p.is_featured = :featured';

    $params[':featured'] =
        $featured;
}


$whereSql =
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

    $count =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM posts p

            INNER JOIN users u
                ON u.id = p.user_id

            WHERE
                {$whereSql}
            "
        );

    $count->execute(
        $params
    );

    $total =
        (int)
        $count->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS COUNT] ' .
        $e->getMessage()
    );

    postsListResponse(
        false,
        'Unable to count posts.',
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

                p.approved_at,

                p.approved_by,

                u.username,

                u.full_names,

                u.email,

                pr.display_name,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = p.user_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS avatar_url,

                (
                    SELECT COUNT(*)

                    FROM post_photos pp

                    WHERE
                        pp.post_id = p.id
                ) AS media_count

            FROM posts p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN profiles pr
                ON pr.user_id = p.user_id

            WHERE
                {$whereSql}

            ORDER BY

                CASE
                    WHEN p.approval_status = 'pending'
                    THEN 0

                    WHEN p.approval_status = 'approved'
                    THEN 1

                    ELSE 2
                END,

                p.created_at DESC

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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS LOAD] ' .
        $e->getMessage()
    );

    postsListResponse(
        false,
        'Unable to load posts.',
        [],
        500
    );
}


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

            FROM posts

            WHERE deleted_at IS NULL
            "
        );

    $summary =
        $summaryStmt->fetch();

} catch (Throwable $e) {

    $summary = [
        'total' => 0,
        'pending' => 0,
        'approved' => 0,
        'rejected' => 0
    ];
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

                id = :session_id

                AND user_id = :user_id

            LIMIT 1
            "
        );

    $activity->execute([
        ':session_id' =>
            $sessionId,

        ':user_id' =>
            $userId
    ]);

} catch (Throwable $e) {

    error_log(
        '[LOVEMI POSTS ACTIVITY] ' .
        $e->getMessage()
    );
}


/*
|--------------------------------------------------------------------------
| RESPONSE
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


postsListResponse(
    true,
    'Posts loaded successfully.',
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
                $admin['avatar_url']

        ],

        'posts' =>
            $posts,

        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ?? 0
                ),

            'pending' =>
                (int)(
                    $summary['pending']
                    ?? 0
                ),

            'approved' =>
                (int)(
                    $summary['approved']
                    ?? 0
                ),

            'rejected' =>
                (int)(
                    $summary['rejected']
                    ?? 0
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