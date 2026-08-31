<?php

declare(strict_types=1);


/* =========================================================
   ERROR HANDLING
========================================================= */

error_reporting(E_ALL);

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'display_startup_errors',
    '0'
);


/* =========================================================
   DATABASE
========================================================= */

require_once
    __DIR__
    . '/../../config/database.php';


/* =========================================================
   HEADERS
========================================================= */

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

function loginLogsResponse(
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
        |
        JSON_INVALID_UTF8_SUBSTITUTE
    );


    exit;

}


/* =========================================================
   METHOD
========================================================= */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    loginLogsResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

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


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

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


    session_start();

}


/* =========================================================
   DB
========================================================= */

try {

    $pdo =
        db();


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOGIN LOGS DATABASE] '
        .
        $e->getMessage()
    );


    loginLogsResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   AUTH
========================================================= */

$adminId =
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
    trim(
        (string)(
            $_SESSION[
                'lovemi_session_token'
            ]
            ??
            ''
        )
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    loginLogsResponse(
        false,
        'Administrator authentication is required.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/* =========================================================
   ADMIN PERMISSION
========================================================= */

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
                    'login_logs.view'

            LIMIT 1
            "
        );


    $authStmt->execute(
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
        $authStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOGIN LOG AUTH] '
        .
        $e->getMessage()
    );


    loginLogsResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    loginLogsResponse(
        false,
        'You do not have permission to view login logs.',
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


$period =
    strtolower(
        trim(
            (string)(
                $_GET['period']
                ??
                ''
            )
        )
    );


$where =
    [
        '1 = 1'
    ];


$params =
    [];


/* =========================================================
   SEARCH
========================================================= */

if (
    $search !== ''
) {

    $where[] =
        "
        (
            l.identifier LIKE :identifier

            OR l.ip_address LIKE :ip

            OR l.user_agent LIKE :agent

            OR l.failure_reason LIKE :reason

            OR u.username LIKE :username

            OR u.full_names LIKE :full_names

            OR u.email LIKE :email
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[
        ':identifier'
    ] =
        $like;


    $params[
        ':ip'
    ] =
        $like;


    $params[
        ':agent'
    ] =
        $like;


    $params[
        ':reason'
    ] =
        $like;


    $params[
        ':username'
    ] =
        $like;


    $params[
        ':full_names'
    ] =
        $like;


    $params[
        ':email'
    ] =
        $like;

}


/* =========================================================
   STATUS
========================================================= */

if (
    $status ===
    'failed'
) {

    $where[] =
        "
        LOWER(l.login_status) =
        'failed'
        ";

}


if (
    $status ===
    'blocked'
) {

    $where[] =
        "
        LOWER(l.login_status) =
        'blocked'
        ";

}


if (
    $status ===
    'success'
) {

    $where[] =
        "
        LOWER(l.login_status)
        IN
        (
            'success',
            'verified',
            'password_verified_2fa_pending'
        )
        ";

}


/* =========================================================
   PERIOD
========================================================= */

if (
    $period ===
    'today'
) {

    $where[] =
        "
        l.created_at >=
        CURRENT_DATE
        ";

}


if (
    in_array(
        $period,
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
        $period;


    $where[] =
        "
        l.created_at >=
        DATE_SUB(
            CURRENT_TIMESTAMP,
            INTERVAL {$days} DAY
        )
        ";

}


$whereSql =
    implode(
        ' AND ',
        $where
    );


/* =========================================================
   COUNT
========================================================= */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT
                COUNT(*)

            FROM login_logs l

            LEFT JOIN users u
                ON u.id =
                    l.user_id

            WHERE
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

    loginLogsResponse(
        false,
        'Unable to count login records.',
        [],
        500
    );

}


/* =========================================================
   DATA
========================================================= */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                l.id,

                l.user_id,

                l.identifier,

                l.login_status,

                l.failure_reason,

                l.ip_address,

                l.user_agent,

                l.created_at,

                u.username,

                u.full_names AS user_name,

                u.email

            FROM login_logs l

            LEFT JOIN users u
                ON u.id =
                    l.user_id

            WHERE

                {$whereSql}

            ORDER BY

                l.created_at DESC,

                l.id DESC

            LIMIT :limit

            OFFSET :offset
            "
        );


    foreach (
        $params
        as $key =>
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


    $items =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOGIN LOG DATA] '
        .
        $e->getMessage()
    );


    loginLogsResponse(
        false,
        'Unable to load login logs.',
        [],
        500
    );

}


/* =========================================================
   SUMMARY
========================================================= */

try {

    $auditTotal =
        (int)
        $pdo->query(
            "
            SELECT COUNT(*)
            FROM audit_logs
            "
        )->fetchColumn();


    $loginTotal =
        (int)
        $pdo->query(
            "
            SELECT COUNT(*)
            FROM login_logs
            "
        )->fetchColumn();


    $failedTotal =
        (int)
        $pdo->query(
            "
            SELECT COUNT(*)

            FROM login_logs

            WHERE LOWER(login_status)
            IN
            (
                'failed',
                'blocked'
            )
            "
        )->fetchColumn();


    $activeSessions =
        (int)
        $pdo->query(
            "
            SELECT COUNT(*)

            FROM user_sessions

            WHERE

                revoked_at IS NULL

                AND expires_at >
                    CURRENT_TIMESTAMP
            "
        )->fetchColumn();


    $sessionTotal =
        (int)
        $pdo->query(
            "
            SELECT COUNT(*)
            FROM user_sessions
            "
        )->fetchColumn();

} catch (
    Throwable $e
) {

    $auditTotal =
        0;

    $loginTotal =
        0;

    $failedTotal =
        0;

    $activeSessions =
        0;

    $sessionTotal =
        0;

}


/* =========================================================
   AVATAR
========================================================= */

$avatar =
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


    $avatar =
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

    $updateActivity =
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


    $updateActivity->execute(
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


/* =========================================================
   RESPONSE
========================================================= */

loginLogsResponse(
    true,
    'Login logs loaded successfully.',
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
                $avatar

        ],

        'items' =>
            $items,

        'summary' => [

            'audit_total' =>
                $auditTotal,

            'login_total' =>
                $loginTotal,

            'failed_logins' =>
                $failedTotal,

            'active_sessions' =>
                $activeSessions,

            'session_total' =>
                $sessionTotal

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