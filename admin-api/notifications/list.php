<?php

declare(strict_types=1);

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


/* =========================================================
   RESPONSE
========================================================= */

function notificationsListResponse(
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


/* =========================================================
   SESSION
========================================================= */

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


/* =========================================================
   DATABASE
========================================================= */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN NOTIFICATIONS DB] '
        .
        $e->getMessage()
    );


    notificationsListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   ADMIN SESSION
========================================================= */

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

    notificationsListResponse(
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


/* =========================================================
   ADMIN AUTHORIZATION
========================================================= */

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
                    'notifications.manage'

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
        '[LOVEMI ADMIN NOTIFICATIONS AUTH] '
        .
        $e->getMessage()
    );


    notificationsListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    notificationsListResponse(
        false,
        'You do not have permission to manage notifications.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* =========================================================
   PARAMETERS
========================================================= */

$specificId =
    (int)(
        $_GET['id']
        ??
        0
    );


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
    trim(
        (string)(
            $_GET['type']
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


/* =========================================================
   CONDITIONS
========================================================= */

$where =
    [
        '1 = 1'
    ];


$params =
    [];


if (
    $specificId > 0
) {

    $where[] =
        '
        n.id =
        :specific_id
        ';


    $params[':specific_id'] =
        $specificId;

}


if (
    $search !== ''
) {

    $where[] =
        "
        (
            n.title LIKE :search_title

            OR n.message LIKE :search_message

            OR u.username LIKE :search_username

            OR u.full_names LIKE :search_full_names
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[':search_title'] =
        $like;

    $params[':search_message'] =
        $like;

    $params[':search_username'] =
        $like;

    $params[':search_full_names'] =
        $like;

}


if (
    $type !== ''
) {

    $where[] =
        "
        nt.slug =
        :type
        ";


    $params[':type'] =
        $type;

}


if (
    $status === 'read'
) {

    $where[] =
        "
        n.is_read =
        1
        ";

}


if (
    $status === 'unread'
) {

    $where[] =
        "
        n.is_read =
        0
        ";

}


$whereSql =
    'WHERE '
    .
    implode(
        ' AND ',
        $where
    );


/* =========================================================
   TOTAL
========================================================= */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT
                COUNT(*)

            FROM notifications n

            INNER JOIN users u
                ON u.id =
                    n.user_id

            LEFT JOIN notification_types nt
                ON nt.id =
                    n.notification_type_id

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

    notificationsListResponse(
        false,
        'Unable to count notifications.',
        [],
        500
    );

}


/* =========================================================
   NOTIFICATIONS
========================================================= */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                n.id,

                n.user_id,

                n.notification_type_id,

                n.sender_id,

                n.title,

                n.message,

                n.reference_type,

                n.reference_id,

                n.audio_id,

                n.is_read,

                n.read_at,

                n.created_at,

                u.username
                    AS recipient_username,

                u.full_names
                    AS recipient_name,

                nt.name
                    AS notification_type_name,

                nt.slug
                    AS notification_type_slug,

                na.name
                    AS audio_name,

                na.file_name
                    AS audio_file_name,

                na.file_path
                    AS audio_path

            FROM notifications n

            INNER JOIN users u
                ON u.id =
                    n.user_id

            LEFT JOIN notification_types nt
                ON nt.id =
                    n.notification_type_id

            LEFT JOIN notification_audio na
                ON na.id =
                    n.audio_id

            {$whereSql}

            ORDER BY
                n.created_at DESC,
                n.id DESC

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


    $notifications =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN NOTIFICATIONS LIST] '
        .
        $e->getMessage()
    );


    notificationsListResponse(
        false,
        'Unable to load notifications.',
        [],
        500
    );

}


/* =========================================================
   SUMMARY
========================================================= */

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS total,

                SUM(
                    is_read = 0
                ) AS unread,

                SUM(
                    DATE(
                        created_at
                    ) =
                    CURRENT_DATE
                ) AS today,

                COUNT(
                    DISTINCT notification_type_id
                ) AS types

            FROM notifications
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary =
        [

            'total' =>
                0,

            'unread' =>
                0,

            'today' =>
                0,

            'types' =>
                0

        ];

}


/* =========================================================
   TYPES
========================================================= */

try {

    $typesStmt =
        $pdo->query(
            "
            SELECT

                id,

                name,

                slug,

                description,

                sound_enabled

            FROM notification_types

            ORDER BY
                name ASC
            "
        );


    $notificationTypes =
        $typesStmt->fetchAll();

} catch (
    Throwable $e
) {

    $notificationTypes =
        [];

}


/* =========================================================
   AUDIO
========================================================= */

try {

    $audioStmt =
        $pdo->query(
            "
            SELECT

                id,

                notification_type_id,

                name,

                file_name,

                file_path,

                mime_type,

                sort_order

            FROM notification_audio

            WHERE
                is_active =
                1

            ORDER BY

                sort_order ASC,

                id ASC
            "
        );


    $audio =
        $audioStmt->fetchAll();

} catch (
    Throwable $e
) {

    $audio =
        [];

}


/* =========================================================
   MEMBERS
   Limited to safe fields required by the admin selector.
========================================================= */

try {

    $membersStmt =
        $pdo->query(
            "
            SELECT

                id,

                username,

                full_names

            FROM users

            WHERE

                is_deleted =
                    0

                AND is_active =
                    1

                AND is_suspended =
                    0

            ORDER BY
                full_names ASC,

                username ASC

            LIMIT 5000
            "
        );


    $members =
        $membersStmt->fetchAll();

} catch (
    Throwable $e
) {

    $members =
        [];

}


/* =========================================================
   ADMIN AVATAR
========================================================= */

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


/* =========================================================
   SESSION ACTIVITY
========================================================= */

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


/* =========================================================
   PAGINATION
========================================================= */

$pages =
    $total > 0
        ?
        (int)
        ceil(
            $total / $limit
        )
        :
        1;


notificationsListResponse(
    true,
    'Notifications loaded successfully.',
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

            'total' =>
                (int)(
                    $summary['total']
                    ??
                    0
                ),

            'unread' =>
                (int)(
                    $summary['unread']
                    ??
                    0
                ),

            'today' =>
                (int)(
                    $summary['today']
                    ??
                    0
                ),

            'types' =>
                (int)(
                    $summary['types']
                    ??
                    0
                )

        ],

        'notifications' =>
            $notifications,

        'notification_types' =>
            $notificationTypes,

        'audio' =>
            $audio,

        'members' =>
            $members,

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