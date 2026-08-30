<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');


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


if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


function conversationListResponse(
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

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION LIST DB] '
        .
        $e->getMessage()
    );

    conversationListResponse(
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
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    conversationListResponse(
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
| ADMIN + PERMISSION
|--------------------------------------------------------------------------
*/

try {

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.email,

                r.id AS role_id,
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

                AND pm.slug = 'conversations.manage'

            LIMIT 1
            "
        );


    $authStmt->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    $admin =
        $authStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION LIST AUTH] '
        .
        $e->getMessage()
    );

    conversationListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    conversationListResponse(
        false,
        'You do not have permission to manage conversations.',
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

$adminAvatar = null;


try {

    $photoStmt =
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


    $photoStmt->execute([
        ':user_id' =>
            $adminId
    ]);


    $adminAvatar =
        $photoStmt->fetchColumn()
        ?: null;

} catch (
    Throwable $e
) {

    $adminAvatar = null;

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


$allowedStatuses = [
    'active',
    'closed',
    'archived',
    'blocked'
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


$allowedSorts = [
    'latest',
    'oldest',
    'messages'
];


if (
    !in_array(
        $sort,
        $allowedSorts,
        true
    )
) {

    $sort =
        'latest';

}


/*
|--------------------------------------------------------------------------
| FILTER
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
            u1.username LIKE :search
            OR u1.full_names LIKE :search
            OR u2.username LIKE :search
            OR u2.full_names LIKE :search

            OR EXISTS
            (
                SELECT 1

                FROM messages sm

                WHERE

                    sm.conversation_id = c.id

                    AND sm.message_text LIKE :message_search

            )
        )
        ";


    $params[':search'] =
        '%'
        .
        $search
        .
        '%';


    $params[':message_search'] =
        '%'
        .
        $search
        .
        '%';

}


if (
    $status !== ''
) {

    $where[] =
        'c.status = :status';


    $params[':status'] =
        $status;

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
    match (
        $sort
    ) {

        'oldest' =>
            'c.created_at ASC',

        'messages' =>
            'message_count DESC, c.updated_at DESC',

        default =>
            'c.updated_at DESC'

    };


/*
|--------------------------------------------------------------------------
| TOTAL
|--------------------------------------------------------------------------
*/

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM conversations c

            INNER JOIN users u1
                ON u1.id = c.user_one_id

            INNER JOIN users u2
                ON u2.id = c.user_two_id

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
        '[LOVEMI CONVERSATION COUNT] '
        .
        $e->getMessage()
    );

    conversationListResponse(
        false,
        'Unable to count conversations.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| CONVERSATIONS
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                c.id,

                c.connection_id,

                c.user_one_id,

                c.user_two_id,

                c.status,

                c.created_at,

                c.updated_at,

                u1.username
                    AS user_one_username,

                u1.full_names
                    AS user_one_full_name,

                u2.username
                    AS user_two_username,

                u2.full_names
                    AS user_two_full_name,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = c.user_one_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS user_one_avatar,

                (
                    SELECT ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id = c.user_two_id

                        AND ph.photo_type = 'profile'

                        AND ph.is_primary = 1

                        AND ph.approval_status = 'approved'

                    ORDER BY ph.id DESC

                    LIMIT 1

                ) AS user_two_avatar,

                (

                    SELECT COUNT(*)

                    FROM messages m

                    WHERE
                        m.conversation_id = c.id

                ) AS message_count,

                lm.message_type
                    AS last_message_type,

                lm.message_text
                    AS last_message_text,

                lm.attachment_name
                    AS last_attachment_name,

                lm.created_at
                    AS last_message_at

            FROM conversations c

            INNER JOIN users u1
                ON u1.id = c.user_one_id

            INNER JOIN users u2
                ON u2.id = c.user_two_id

            LEFT JOIN messages lm
                ON lm.id =
                (
                    SELECT m2.id

                    FROM messages m2

                    WHERE
                        m2.conversation_id = c.id

                    ORDER BY
                        m2.created_at DESC,
                        m2.id DESC

                    LIMIT 1
                )

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


    $conversations =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION LOAD] '
        .
        $e->getMessage()
    );

    conversationListResponse(
        false,
        'Unable to load conversations.',
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
                        status = 'active'
                    ),
                    0
                ) AS active,

                COALESCE(
                    SUM(
                        status IN
                        ('closed','blocked','archived')
                    ),
                    0
                ) AS closed_or_blocked

            FROM conversations
            "
        );


    $summary =
        $summaryStmt->fetch();


    $messageConversationStmt =
        $pdo->query(
            "
            SELECT COUNT(*)

            FROM
            (
                SELECT
                    conversation_id

                FROM messages

                GROUP BY
                    conversation_id

            ) x
            "
        );


    $withMessages =
        (int)
        $messageConversationStmt->fetchColumn();

} catch (
    Throwable $e
) {

    $summary = [
        'total' => 0,
        'active' => 0,
        'closed_or_blocked' => 0
    ];

    $withMessages = 0;

}


/*
|--------------------------------------------------------------------------
| UPDATE SESSION ACTIVITY
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
            $adminId
    ]);

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONVERSATION ACTIVITY] '
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

conversationListResponse(
    true,
    'Conversations loaded successfully.',
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


        'conversations' =>
            $conversations,


        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ??
                    0
                ),

            'active' =>
                (int)(
                    $summary['active']
                    ??
                    0
                ),

            'with_messages' =>
                $withMessages,

            'closed_or_blocked' =>
                (int)(
                    $summary['closed_or_blocked']
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