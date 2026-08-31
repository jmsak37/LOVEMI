<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN DASHBOARD API
|--------------------------------------------------------------------------
|
| File:
| C:\xampp\htdocs\LOVEMI\admin-api\dashboard.php
|
| Purpose:
|
|   Return dashboard statistics directly from MySQL.
|
| Security:
|
|   - Requires authenticated LOVEMI session.
|   - Requires database-backed active session.
|   - Requires two_factor_passed = TRUE.
|   - Requires active, non-suspended account.
|   - Requires a role with is_admin_role = TRUE.
|
|--------------------------------------------------------------------------
*/


/* ============================================================
   DATABASE
============================================================ */

require_once
    __DIR__
    . '/../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

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


/* ============================================================
   ERROR HANDLING
============================================================ */

ini_set(
    'display_errors',
    '0'
);

error_reporting(
    E_ALL
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


/* ============================================================
   RESPONSE HELPER
============================================================ */

function adminDashboardResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    adminDashboardResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   SESSION IDENTIFIERS
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ?
        (string)
        $_SESSION['lovemi_session_token']
        :
        '';


$databaseSessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


if (
    $userId <= 0
    ||
    $sessionToken === ''
    ||
    $databaseSessionId <= 0
) {

    adminDashboardResponse(
        false,
        'You must log in before accessing the admin dashboard.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
        401
    );

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
        '[LOVEMI ADMIN DASHBOARD DB] '
        .
        $e->getMessage()
    );


    adminDashboardResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   VERIFY DATABASE SESSION + ADMIN ROLE
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role,

                s.id AS session_id,

                s.two_factor_passed,

                s.expires_at,

                s.revoked_at

            FROM users u

            INNER JOIN roles r

                ON r.id =
                   u.role_id

            INNER JOIN user_sessions s

                ON s.user_id =
                   u.id

            WHERE

                u.id =
                    :user_id

                AND

                s.id =
                    :session_id

                AND

                s.session_token_hash =
                    :token_hash

                AND

                s.two_factor_passed =
                    1

                AND

                s.revoked_at IS NULL

                AND

                s.expires_at >
                    CURRENT_TIMESTAMP

                AND

                u.is_active =
                    1

                AND

                u.is_suspended =
                    0

                AND

                u.is_deleted =
                    0

                AND

                r.is_admin_role =
                    1

            LIMIT 1
            "
        );


    $authStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':session_id' =>
                $databaseSessionId,

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
        '[LOVEMI ADMIN AUTH QUERY] '
        .
        $e->getMessage()
    );


    adminDashboardResponse(
        false,
        'Unable to verify your administrator session.',
        [
            'code' =>
                'ADMIN_AUTH_QUERY_FAILED'
        ],
        500
    );

}


/* ============================================================
   ADMIN ACCESS DENIED
============================================================ */

if (
    !$admin
) {

    adminDashboardResponse(
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
   REFRESH SESSION ACTIVITY
============================================================ */

try {

    $activityStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET

                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE id =
                :session_id

              AND user_id =
                :user_id

            LIMIT 1
            "
        );


    $activityStmt->execute(
        [

            ':session_id' =>
                $databaseSessionId,

            ':user_id' =>
                $userId

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN SESSION ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   UPDATE PHP SESSION ROLE
============================================================ */

$_SESSION[
    'lovemi_role_slug'
] =
    strtolower(
        (string)
        $admin['role_slug']
    );


/* ============================================================
   SAFE QUERY HELPER
============================================================ */

function scalarCount(
    PDO $pdo,
    string $sql,
    array $params = []
): int {

    try {

        $stmt =
            $pdo->prepare(
                $sql
            );


        $stmt->execute(
            $params
        );


        return max(
            0,
            (int)
            $stmt->fetchColumn()
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI ADMIN COUNT] '
            .
            $e->getMessage()
        );


        return 0;

    }

}


/* ============================================================
   TOTAL USERS
============================================================ */

$totalUsers =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM users

        WHERE is_deleted = 0
        "
    );


/* ============================================================
   ACTIVE USERS
============================================================ */

$activeUsers =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM users

        WHERE is_deleted = 0

          AND is_active = 1

          AND is_suspended = 0
        "
    );


/* ============================================================
   ACTIVE PREMIUM
============================================================ */

$activePremium =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM subscriptions

        WHERE status = 'active'

          AND end_at >
              CURRENT_TIMESTAMP
        "
    );


/* ============================================================
   SUCCESSFUL PAYMENTS
============================================================ */

$successfulPayments =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM payments

        WHERE status =
            'paid'
        "
    );


/* ============================================================
   PENDING ACCOUNTS
============================================================ */

$pendingAccounts =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM users

        WHERE account_status =
            'pending'

          AND is_deleted =
              0
        "
    );


/* ============================================================
   PENDING PHOTOS
============================================================ */

$pendingPhotos =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM photos

        WHERE approval_status =
            'pending'
        "
    );


/* ============================================================
   PENDING POSTS
============================================================ */

$pendingPosts =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM posts

        WHERE approval_status =
            'pending'

          AND deleted_at IS NULL
        "
    );


/* ============================================================
   PENDING REPORTS
============================================================ */

$pendingReports =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM reports

        WHERE status =
            'pending'
        "
    );


/* ============================================================
   PENDING PAYMENTS
============================================================ */

$pendingPayments =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM payments

        WHERE status =
            'pending'
        "
    );


/* ============================================================
   EXPIRING PREMIUM
============================================================ */

$expiringPremium =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM subscriptions

        WHERE status =
            'active'

          AND end_at >
              CURRENT_TIMESTAMP

          AND end_at <=
              DATE_ADD(
                  CURRENT_TIMESTAMP,
                  INTERVAL 7 DAY
              )
        "
    );


/* ============================================================
   ACTIVE SESSIONS
============================================================ */

$activeSessions =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM user_sessions

        WHERE revoked_at IS NULL

          AND expires_at >
              CURRENT_TIMESTAMP
        "
    );


/* ============================================================
   UNREAD NOTIFICATIONS
============================================================ */

$unreadNotifications =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM notifications

        WHERE is_read = 0
        "
    );


/* ============================================================
   SERVICES
============================================================ */

$activeServices =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM services

        WHERE is_active = 1
        "
    );


/* ============================================================
   CONNECTIONS
============================================================ */

$activeConnections =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM connections

        WHERE status IN
            (
                'accepted',
                'connected'
            )
        "
    );


/* ============================================================
   MESSAGES
============================================================ */

$totalMessages =
    scalarCount(
        $pdo,
        "
        SELECT COUNT(*)

        FROM messages

        WHERE
            deleted_by_sender = 0

            OR

            deleted_by_receiver = 0
        "
    );


/* ============================================================
   RECENT USERS
============================================================ */

$recentUsers =
    [];


try {

    $usersStmt =
        $pdo->query(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.account_status,

                u.created_at,

                r.name AS role_name,

                r.slug AS role_slug,

                c.name AS country_name,

                c.iso2,

                p.display_name,

                ph.file_path AS avatar_url

            FROM users u

            LEFT JOIN roles r

                ON r.id =
                   u.role_id

            LEFT JOIN countries c

                ON c.id =
                   u.country_id

            LEFT JOIN profiles p

                ON p.user_id =
                   u.id

            LEFT JOIN photos ph

                ON ph.user_id =
                   u.id

                AND ph.is_primary =
                    1

                AND ph.approval_status =
                    'approved'

            WHERE

                u.is_deleted =
                    0

            ORDER BY

                u.created_at DESC

            LIMIT 8
            "
        );


    $recentUsers =
        $usersStmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN RECENT USERS] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RECENT PAYMENTS
============================================================ */

$recentPayments =
    [];


try {

    $paymentsStmt =
        $pdo->query(
            "
            SELECT

                p.id,

                p.payment_reference,

                p.gateway,

                p.status,

                p.currency_id,

                p.base_amount_usd,

                p.amount_expected,

                p.amount_paid,

                p.paid_at,

                p.created_at,

                u.username,

                u.full_names,

                u.email,

                c.code AS currency

            FROM payments p

            INNER JOIN users u

                ON u.id =
                   p.user_id

            LEFT JOIN currencies c

                ON c.id =
                   p.currency_id

            ORDER BY

                p.created_at DESC

            LIMIT 8
            "
        );


    $recentPayments =
        $paymentsStmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN RECENT PAYMENTS] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RECENT ACTIVITY
============================================================ */

$recentActivity =
    [];


try {

    $activityStmt =
        $pdo->query(
            "
            SELECT

                al.id,

                al.user_id,

                al.action,

                al.entity_type,

                al.entity_id,

                al.created_at,

                u.username,

                u.full_names

            FROM audit_logs al

            LEFT JOIN users u

                ON u.id =
                   al.user_id

            ORDER BY

                al.created_at DESC

            LIMIT 8
            "
        );


    $recentActivity =
        $activityStmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   ACTIVITY ICONS / DESCRIPTIONS
============================================================ */

foreach (
    $recentActivity
    as &$activity
) {

    $action =
        strtolower(
            trim(
                (string)
                (
                    $activity['action']
                    ??
                    ''
                )
            )
        );


    $icon =
        'fa-solid fa-circle';


    if (
        str_contains(
            $action,
            'registration'
        )
    ) {

        $icon =
            'fa-solid fa-user-plus';

    } elseif (
        str_contains(
            $action,
            'login'
        )
    ) {

        $icon =
            'fa-solid fa-right-to-bracket';

    } elseif (
        str_contains(
            $action,
            'photo'
        )
    ) {

        $icon =
            'fa-solid fa-image';

    } elseif (
        str_contains(
            $action,
            'post'
        )
    ) {

        $icon =
            'fa-solid fa-newspaper';

    } elseif (
        str_contains(
            $action,
            'payment'
        )
    ) {

        $icon =
            'fa-solid fa-credit-card';

    } elseif (
        str_contains(
            $action,
            'premium'
        )
    ) {

        $icon =
            'fa-solid fa-crown';

    } elseif (
        str_contains(
            $action,
            'admin'
        )
        ||
        str_contains(
            $action,
            'role'
        )
    ) {

        $icon =
            'fa-solid fa-user-shield';

    } elseif (
        str_contains(
            $action,
            'delete'
        )
        ||
        str_contains(
            $action,
            'suspend'
        )
    ) {

        $icon =
            'fa-solid fa-triangle-exclamation';

    }


    $activity['icon'] =
        $icon;


    $name =
        trim(
            (string)
            (
                $activity['full_names']
                ??
                $activity['username']
                ??
                ''
            )
        );


    if (
        $name === ''
    ) {

        $name =
            'System';

    }


    $activity['description'] =
        ucfirst(
            (string)
            (
                $activity['action']
                ??
                'Activity'
            )
        )
        .
        (
            $activity['entity_type']
                ?
                ' • '
                .
                ucfirst(
                    (string)
                    $activity['entity_type']
                )
                :
                ''
        )
        .
        ' • '
        .
        $name;

}

unset(
    $activity
);


/* ============================================================
   SERVER TIME
============================================================ */

$serverTime =
    date(
        'Y-m-d H:i:s'
    );


/* ============================================================
   RESPONSE
============================================================ */

adminDashboardResponse(
    true,
    'Admin dashboard loaded successfully.',
    [

        'data' => [

            'server_time' =>
                $serverTime,


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

                'role_id' =>
                    (int)
                    $admin['role_id'],

                'role_name' =>
                    $admin['role_name'],

                'role_slug' =>
                    $admin['role_slug']

            ],


            'stats' => [

                'total_users' =>
                    $totalUsers,

                'active_users' =>
                    $activeUsers,

                'active_premium' =>
                    $activePremium,

                'successful_payments' =>
                    $successfulPayments,

                'active_connections' =>
                    $activeConnections,

                'total_messages' =>
                    $totalMessages,

                'active_services' =>
                    $activeServices

            ],


            'moderation' => [

                'pending_accounts' =>
                    $pendingAccounts,

                'pending_photos' =>
                    $pendingPhotos,

                'pending_posts' =>
                    $pendingPosts,

                'pending_reports' =>
                    $pendingReports,

                'pending_payments' =>
                    $pendingPayments,

                'expiring_premium' =>
                    $expiringPremium

            ],


            'system' => [

                'database' =>
                    'Connected',

                'active_sessions' =>
                    $activeSessions,

                'premium' =>
                    'Operational',

                'payments' =>
                    'Operational',

                'notifications' =>
                    $unreadNotifications
                    .
                    ' unread',

                'active_services' =>
                    $activeServices

            ],


            'recent_users' =>
                $recentUsers,


            'recent_payments' =>
                $recentPayments,


            'recent_activity' =>
                $recentActivity

        ]

    ]
);