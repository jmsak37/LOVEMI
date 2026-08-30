<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - BLOCKED USERS LIST
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

ini_set(
    'display_errors',
    '0'
);


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


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function blockedListResponse(
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
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE
        |
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

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BLOCK LIST DB] '
        .
        $e->getMessage()
    );


    blockedListResponse(
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

    blockedListResponse(
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

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'blocks.manage'

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

    blockedListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    blockedListResponse(
        false,
        'You do not have permission to manage blocked users.',
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


$dateFilter =
    strtolower(
        trim(
            (string)(
                $_GET['date']
                ??
                ''
            )
        )
    );


/*
|--------------------------------------------------------------------------
| SEARCH USERNAME / NAMES / REASON
|--------------------------------------------------------------------------
*/

$where =
    [];

$params =
    [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            blocker.username LIKE :search_blocker_username

            OR blocker.full_names LIKE :search_blocker_names

            OR blocked.username LIKE :search_blocked_username

            OR blocked.full_names LIKE :search_blocked_names

            OR bu.reason LIKE :search_reason
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[
        ':search_blocker_username'
    ] =
        $like;


    $params[
        ':search_blocker_names'
    ] =
        $like;


    $params[
        ':search_blocked_username'
    ] =
        $like;


    $params[
        ':search_blocked_names'
    ] =
        $like;


    $params[
        ':search_reason'
    ] =
        $like;

}


/*
|--------------------------------------------------------------------------
| DATE FILTER
|--------------------------------------------------------------------------
*/

if (
    $dateFilter === 'today'
) {

    $where[] =
        "
        bu.created_at >=
        CURRENT_DATE
        ";

}


if (
    in_array(
        $dateFilter,
        [
            '7',
            '30',
            '90'
        ],
        true
    )
) {

    $days =
        (int)
        $dateFilter;


    $where[] =
        "
        bu.created_at >=
        DATE_SUB(
            CURRENT_TIMESTAMP,
            INTERVAL {$days} DAY
        )
        ";

}


$whereSql =
    $where
        ?
        'WHERE '
        .
        implode(
            ' AND ',
            $where
        )
        :
        '';


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

            FROM blocked_users bu

            INNER JOIN users blocker
                ON blocker.id =
                    bu.user_id

            INNER JOIN users blocked
                ON blocked.id =
                    bu.blocked_user_id

            {$whereSql}
            "
        );


    $count->execute(
        $params
    );


    $total =
        (int)
        $count->fetchColumn();

} catch (
    Throwable $e
) {

    blockedListResponse(
        false,
        'Unable to count block records.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| RECORDS
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                bu.id,

                bu.user_id,

                bu.blocked_user_id,

                bu.reason,

                bu.created_at,

                blocker.username
                    AS blocker_username,

                blocker.full_names
                    AS blocker_full_names,

                blocked.username
                    AS blocked_username,

                blocked.full_names
                    AS blocked_full_names,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            blocker.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY p.id DESC

                    LIMIT 1

                ) AS blocker_avatar,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            blocked.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY p.id DESC

                    LIMIT 1

                ) AS blocked_avatar

            FROM blocked_users bu

            INNER JOIN users blocker
                ON blocker.id =
                    bu.user_id

            INNER JOIN users blocked
                ON blocked.id =
                    bu.blocked_user_id

            {$whereSql}

            ORDER BY
                bu.created_at DESC,
                bu.id DESC

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


    $blocks =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BLOCK LIST QUERY] '
        .
        $e->getMessage()
    );


    blockedListResponse(
        false,
        'Unable to load blocked users.',
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

                COUNT(
                    DISTINCT user_id
                ) AS unique_blockers,

                COUNT(
                    DISTINCT blocked_user_id
                ) AS unique_blocked,

                COALESCE(
                    SUM(
                        created_at >=
                        DATE_SUB(
                            CURRENT_TIMESTAMP,
                            INTERVAL 7 DAY
                        )
                    ),
                    0
                ) AS recent

            FROM blocked_users
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

        'unique_blockers' =>
            0,

        'unique_blocked' =>
            0,

        'recent' =>
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

            ORDER BY id DESC

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

    $adminAvatar =
        null;

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

    error_log(
        '[LOVEMI BLOCK SESSION ACTIVITY] '
        .
        $e->getMessage()
    );

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


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

blockedListResponse(
    true,
    'Blocked users loaded successfully.',
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

        'blocks' =>
            $blocks,

        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ??
                    0
                ),

            'unique_blockers' =>
                (int)(
                    $summary['unique_blockers']
                    ??
                    0
                ),

            'unique_blocked' =>
                (int)(
                    $summary['unique_blocked']
                    ??
                    0
                ),

            'recent' =>
                (int)(
                    $summary['recent']
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