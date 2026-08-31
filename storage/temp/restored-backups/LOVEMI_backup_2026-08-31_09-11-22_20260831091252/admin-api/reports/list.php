<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - REPORTS LIST API
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

function reportsListResponse(
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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    reportsListResponse(
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

    reportsListResponse(
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

                AND pm.slug = 'reports.manage'

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

    reportsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    reportsListResponse(
        false,
        'You do not have permission to manage reports.',
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


$reason =
    strtolower(
        trim(
            (string)(
                $_GET['reason']
                ??
                ''
            )
        )
    );


$allowedStatuses = [
    'pending',
    'reviewing',
    'reviewed',
    'resolved',
    'rejected',
    'dismissed'
];


if (
    !in_array(
        $status,
        $allowedStatuses,
        true
    )
) {

    $status =
        '';

}


$allowedTypes = [
    'user',
    'post',
    'message'
];


if (
    !in_array(
        $type,
        $allowedTypes,
        true
    )
) {

    $type =
        '';

}


/*
|--------------------------------------------------------------------------
| WHERE CONDITIONS
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
            reporter.username LIKE :search_reporter_username

            OR reporter.full_names LIKE :search_reporter_names

            OR reported.username LIKE :search_reported_username

            OR reported.full_names LIKE :search_reported_names

            OR r.reason LIKE :search_reason

            OR r.description LIKE :search_description
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[
        ':search_reporter_username'
    ] =
        $like;


    $params[
        ':search_reporter_names'
    ] =
        $like;


    $params[
        ':search_reported_username'
    ] =
        $like;


    $params[
        ':search_reported_names'
    ] =
        $like;


    $params[
        ':search_reason'
    ] =
        $like;


    $params[
        ':search_description'
    ] =
        $like;

}


if (
    $status !== ''
) {

    $where[] =
        'r.status = :status';


    $params[
        ':status'
    ] =
        $status;

}


if (
    $reason !== ''
) {

    $where[] =
        'LOWER(r.reason) = :reason';


    $params[
        ':reason'
    ] =
        $reason;

}


if (
    $type === 'user'
) {

    $where[] =
        "
        r.reported_user_id IS NOT NULL
        AND
        r.post_id IS NULL
        AND
        r.message_id IS NULL
        ";

}


if (
    $type === 'post'
) {

    $where[] =
        "
        r.post_id IS NOT NULL
        ";

}


if (
    $type === 'message'
) {

    $where[] =
        "
        r.message_id IS NOT NULL
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
| COUNT
|--------------------------------------------------------------------------
*/

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM reports r

            INNER JOIN users reporter
                ON reporter.id = r.reporter_id

            LEFT JOIN users reported
                ON reported.id = r.reported_user_id

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

    reportsListResponse(
        false,
        'Unable to count reports.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| REPORTS
|--------------------------------------------------------------------------
*/

try {

    $query =
        "
        SELECT

            r.id,

            r.reporter_id,

            r.reported_user_id,

            r.post_id,

            r.message_id,

            r.reason,

            r.description,

            r.status,

            r.reviewed_by,

            r.reviewed_at,

            r.resolution,

            r.created_at,

            reporter.username AS reporter_username,

            reporter.full_names AS reporter_full_names,

            reported.username AS reported_username,

            reported.full_names AS reported_full_names,

            (
                SELECT
                    ph.file_path

                FROM photos ph

                WHERE

                    ph.user_id =
                        reporter.id

                    AND ph.photo_type =
                        'profile'

                    AND ph.is_primary =
                        1

                    AND ph.approval_status =
                        'approved'

                ORDER BY ph.id DESC

                LIMIT 1

            ) AS reporter_avatar,

            (
                SELECT
                    ph.file_path

                FROM photos ph

                WHERE

                    ph.user_id =
                        reported.id

                    AND ph.photo_type =
                        'profile'

                    AND ph.is_primary =
                        1

                    AND ph.approval_status =
                        'approved'

                ORDER BY ph.id DESC

                LIMIT 1

            ) AS reported_avatar

        FROM reports r

        INNER JOIN users reporter
            ON reporter.id = r.reporter_id

        LEFT JOIN users reported
            ON reported.id = r.reported_user_id

        {$whereSql}

        ORDER BY

            CASE
                WHEN r.status = 'pending'
                    THEN 1

                WHEN r.status = 'reviewing'
                    THEN 2

                WHEN r.status = 'reviewed'
                    THEN 3

                ELSE 4

            END,

            r.created_at DESC,

            r.id DESC

        LIMIT :limit

        OFFSET :offset
        ";


    $stmt =
        $pdo->prepare(
            $query
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


    $reports =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT LIST] '
        .
        $e->getMessage()
    );


    reportsListResponse(
        false,
        'Unable to load reports.',
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

                COALESCE(
                    SUM(
                        status = 'pending'
                    ),
                    0
                ) AS pending,

                COALESCE(
                    SUM(
                        status IN (
                            'reviewing',
                            'reviewed'
                        )
                    ),
                    0
                ) AS reviewing,

                COALESCE(
                    SUM(
                        status = 'resolved'
                    ),
                    0
                ) AS resolved,

                COALESCE(
                    SUM(
                        status IN (
                            'rejected',
                            'dismissed'
                        )
                    ),
                    0
                ) AS closed

            FROM reports
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary = [
        'total' => 0,
        'pending' => 0,
        'reviewing' => 0,
        'resolved' => 0,
        'closed' => 0
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
            SELECT file_path

            FROM photos

            WHERE

                user_id = :user_id

                AND photo_type = 'profile'

                AND is_primary = 1

                AND approval_status = 'approved'

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

                id = :session_id

                AND user_id = :user_id

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
        '[LOVEMI REPORT SESSION ACTIVITY] '
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

reportsListResponse(
    true,
    'Reports loaded successfully.',
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

        'reports' =>
            $reports,

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

            'reviewing' =>
                (int)(
                    $summary['reviewing']
                    ??
                    0
                ),

            'resolved' =>
                (int)(
                    $summary['resolved']
                    ??
                    0
                ),

            'closed' =>
                (int)(
                    $summary['closed']
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