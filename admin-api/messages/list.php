<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - MESSAGE LIST API
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
| RESPONSE
|--------------------------------------------------------------------------
*/

function messageListResponse(
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

    error_log(
        '[LOVEMI MESSAGE LIST DB] '
        .
        $e->getMessage()
    );


    messageListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| SESSION VALUES
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

    messageListResponse(
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

                AND pm.slug = 'messages.manage'

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
        '[LOVEMI MESSAGE LIST AUTH] '
        .
        $e->getMessage()
    );


    messageListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    messageListResponse(
        false,
        'You do not have permission to manage messages.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN AVATAR
|--------------------------------------------------------------------------
*/

$adminAvatar =
    null;


try {

    $photo =
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


    $photo->execute(
        [
            ':user_id' =>
                $adminId
        ]
    );


    $adminAvatar =
        $photo->fetchColumn()
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


$messageType =
    strtolower(
        trim(
            (string)(
                $_GET['message_type']
                ??
                ''
            )
        )
    );


$readStatus =
    strtolower(
        trim(
            (string)(
                $_GET['read_status']
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
                'latest'
            )
        )
    );


$allowedTypes = [
    'text',
    'image',
    'video',
    'audio',
    'file'
];


if (
    !in_array(
        $messageType,
        $allowedTypes,
        true
    )
) {

    $messageType =
        '';

}


if (
    !in_array(
        $readStatus,
        [
            'read',
            'unread'
        ],
        true
    )
) {

    $readStatus =
        '';

}


if (
    !in_array(
        $sort,
        [
            'latest',
            'oldest'
        ],
        true
    )
) {

    $sort =
        'latest';

}


/*
|--------------------------------------------------------------------------
| WHERE
|--------------------------------------------------------------------------
*/

$where = [];

$params = [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            m.message_text LIKE :search
            OR m.attachment_name LIKE :search_attachment

            OR su.username LIKE :search_sender_username
            OR su.full_names LIKE :search_sender_name

            OR ru.username LIKE :search_receiver_username
            OR ru.full_names LIKE :search_receiver_name
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[':search'] =
        $like;

    $params[':search_attachment'] =
        $like;

    $params[':search_sender_username'] =
        $like;

    $params[':search_sender_name'] =
        $like;

    $params[':search_receiver_username'] =
        $like;

    $params[':search_receiver_name'] =
        $like;

}


if (
    $messageType !== ''
) {

    $where[] =
        'm.message_type = :message_type';


    $params[':message_type'] =
        $messageType;

}


if (
    $readStatus === 'read'
) {

    $where[] =
        'm.is_read = 1';

}


if (
    $readStatus === 'unread'
) {

    $where[] =
        'm.is_read = 0';

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


$orderSql =
    $sort === 'oldest'
        ?
        'm.created_at ASC, m.id ASC'
        :
        'm.created_at DESC, m.id DESC';


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

            FROM messages m

            INNER JOIN users su
                ON su.id = m.sender_id

            INNER JOIN users ru
                ON ru.id = m.receiver_id

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

    error_log(
        '[LOVEMI MESSAGE COUNT] '
        .
        $e->getMessage()
    );


    messageListResponse(
        false,
        'Unable to count messages.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| MESSAGE LIST
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                m.id,

                m.conversation_id,

                m.sender_id,

                m.receiver_id,

                m.message_type,

                m.message_text,

                m.attachment_path,

                m.attachment_name,

                m.attachment_mime,

                m.is_read,

                m.read_at,

                m.deleted_by_sender,

                m.deleted_by_receiver,

                m.created_at,

                su.username
                    AS sender_username,

                su.full_names
                    AS sender_full_name,

                ru.username
                    AS receiver_username,

                ru.full_names
                    AS receiver_full_name,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = su.id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS sender_avatar,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = ru.id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS receiver_avatar

            FROM messages m

            INNER JOIN users su
                ON su.id = m.sender_id

            INNER JOIN users ru
                ON ru.id = m.receiver_id

            {$whereSql}

            ORDER BY
                {$orderSql}

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


    $messages =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MESSAGE LOAD] '
        .
        $e->getMessage()
    );


    messageListResponse(
        false,
        'Unable to load messages.',
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
                    SUM(is_read = 0),
                    0
                ) AS unread,

                COALESCE(
                    SUM(message_type = 'text'),
                    0
                ) AS text_count,

                COALESCE(
                    SUM(
                        message_type <> 'text'
                    ),
                    0
                ) AS media_count,

                COALESCE(
                    SUM(
                        created_at >=
                        CURDATE()
                    ),
                    0
                ) AS today

            FROM messages
            "
        );


    $summaryRow =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summaryRow = [
        'total' =>
            0,

        'unread' =>
            0,

        'text_count' =>
            0,

        'media_count' =>
            0,

        'today' =>
            0
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
        '[LOVEMI MESSAGE LIST ACTIVITY] '
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

messageListResponse(
    true,
    'Messages loaded successfully.',
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


        'messages' =>
            $messages,


        'summary' => [

            'total' =>
                (int)(
                    $summaryRow['total']
                    ??
                    0
                ),

            'unread' =>
                (int)(
                    $summaryRow['unread']
                    ??
                    0
                ),

            'text' =>
                (int)(
                    $summaryRow['text_count']
                    ??
                    0
                ),

            'media' =>
                (int)(
                    $summaryRow['media_count']
                    ??
                    0
                ),

            'today' =>
                (int)(
                    $summaryRow['today']
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