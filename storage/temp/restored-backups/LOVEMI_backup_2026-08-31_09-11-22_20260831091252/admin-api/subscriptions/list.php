<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - SUBSCRIPTIONS LIST
|--------------------------------------------------------------------------
*/

require_once
    __DIR__ . '/../../config/database.php';


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
    !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function response(
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

    $pdo = db();

} catch (
    Throwable $e
) {

    response(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| SESSION AUTH
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


$token =
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
    $token === ''
) {

    response(
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
        $token
    );


/*
|--------------------------------------------------------------------------
| ADMIN PERMISSION
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

            INNER JOIN permissions p
                ON p.id = rp.permission_id

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

                AND p.slug = 'premium.manage'

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

    response(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    response(
        false,
        'You do not have permission to manage subscriptions.',
        [
            'code' => 'PERMISSION_DENIED'
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


$serviceId =
    (int)(
        $_GET['service_id']
        ??
        0
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
    'pending',
    'expired',
    'cancelled',
    'inactive'
];


if (
    !in_array(
        $status,
        $allowedStatuses,
        true
    )
) {

    $status = '';

}


if (
    !in_array(
        $sort,
        [
            'latest',
            'oldest',
            'ending'
        ],
        true
    )
) {

    $sort = 'latest';

}


/*
|--------------------------------------------------------------------------
| WHERE
|--------------------------------------------------------------------------
*/

$where = [];

$params = [];


if ($search !== '') {

    $where[] =
        "
        (
            u.username LIKE :username
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


    $params[':username'] =
        $like;

    $params[':full_names'] =
        $like;

    $params[':email'] =
        $like;

}


if ($status !== '') {

    $where[] =
        's.status = :status';


    $params[':status'] =
        $status;

}


if ($serviceId > 0) {

    $where[] =
        's.service_id = :service_id';


    $params[':service_id'] =
        $serviceId;

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
            's.created_at ASC, s.id ASC',

        'ending' =>
            "
            CASE
                WHEN s.end_at IS NULL
                    THEN 1
                ELSE 0
            END ASC,
            s.end_at ASC,
            s.id ASC
            ",

        default =>
            's.created_at DESC, s.id DESC'

    };


/*
|--------------------------------------------------------------------------
| TOTAL
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM subscriptions s

            INNER JOIN users u
                ON u.id = s.user_id

            INNER JOIN services sv
                ON sv.id = s.service_id

            {$whereSql}
            "
        );


    $stmt->execute(
        $params
    );


    $total =
        (int)
        $stmt->fetchColumn();

} catch (
    Throwable $e
) {

    response(
        false,
        'Unable to count subscriptions.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| LIST
|--------------------------------------------------------------------------
*/

try {

    $sql =
        "
        SELECT

            s.id,
            s.user_id,
            s.service_id,
            s.status,
            s.start_at,
            s.end_at,
            s.base_amount_usd,
            s.amount_paid,
            s.currency_id,
            s.exchange_rate,
            s.payment_id,
            s.usage_limit,
            s.usage_used,
            s.created_at,
            s.updated_at,

            u.username,
            u.full_names,
            u.email,

            sv.name AS service_name,
            sv.slug AS service_slug,
            sv.duration_days,
            sv.max_usage,
            sv.base_price_usd,

            c.code AS currency_code,
            c.name AS currency_name,

            (
                SELECT ph.file_path

                FROM photos ph

                WHERE

                    ph.user_id = u.id

                    AND ph.photo_type = 'profile'

                    AND ph.is_primary = 1

                    AND ph.approval_status = 'approved'

                ORDER BY
                    ph.id DESC

                LIMIT 1

            ) AS avatar_url

        FROM subscriptions s

        INNER JOIN users u
            ON u.id = s.user_id

        INNER JOIN services sv
            ON sv.id = s.service_id

        LEFT JOIN currencies c
            ON c.id = s.currency_id

        {$whereSql}

        ORDER BY
            {$orderSql}

        LIMIT :limit
        OFFSET :offset
        ";


    $stmt =
        $pdo->prepare(
            $sql
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


    $subscriptions =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SUBSCRIPTIONS LIST] '
        .
        $e->getMessage()
    );


    response(
        false,
        'Unable to load subscriptions.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| SERVICES
|--------------------------------------------------------------------------
*/

try {

    $servicesStmt =
        $pdo->query(
            "
            SELECT

                id,
                name,
                slug,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium,
                is_active

            FROM services

            WHERE is_premium = 1

            ORDER BY
                sort_order ASC,
                name ASC
            "
        );


    $services =
        $servicesStmt->fetchAll();

} catch (
    Throwable $e
) {

    $services = [];

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
                        AND end_at > CURRENT_TIMESTAMP
                    ),
                    0
                ) AS active,

                COALESCE(
                    SUM(
                        status = 'pending'
                    ),
                    0
                ) AS pending,

                COALESCE(
                    SUM(
                        status = 'expired'
                        OR (
                            status = 'active'
                            AND end_at <= CURRENT_TIMESTAMP
                        )
                    ),
                    0
                ) AS expired,

                COALESCE(
                    SUM(
                        status = 'active'
                        AND end_at > CURRENT_TIMESTAMP
                        AND end_at <=
                            DATE_ADD(
                                CURRENT_TIMESTAMP,
                                INTERVAL 7 DAY
                            )
                    ),
                    0
                ) AS expiring_soon

            FROM subscriptions
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary = [
        'total' => 0,
        'active' => 0,
        'pending' => 0,
        'expired' => 0,
        'expiring_soon' => 0
    ];

}


/*
|--------------------------------------------------------------------------
| ADMIN AVATAR
|--------------------------------------------------------------------------
*/

$adminAvatar = null;


try {

    $avatar =
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


    $avatar->execute(
        [
            ':user_id' =>
                $adminId
        ]
    );


    $adminAvatar =
        $avatar->fetchColumn()
        ?:
        null;

} catch (
    Throwable $e
) {
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


response(
    true,
    'Subscriptions loaded successfully.',
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


        'subscriptions' =>
            $subscriptions,


        'services' =>
            $services,


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

            'pending' =>
                (int)(
                    $summary['pending']
                    ??
                    0
                ),

            'expired' =>
                (int)(
                    $summary['expired']
                    ??
                    0
                ),

            'expiring_soon' =>
                (int)(
                    $summary['expiring_soon']
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