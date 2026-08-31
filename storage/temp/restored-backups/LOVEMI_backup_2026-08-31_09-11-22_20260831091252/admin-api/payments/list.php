<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - PAYMENTS LIST API
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

function paymentListResponse(
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

    paymentListResponse(
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
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    paymentListResponse(
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

                AND pm.slug = 'payments.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [
            ':admin_id' => $adminId,
            ':session_id' => $sessionId,
            ':token_hash' => $tokenHash
        ]
    );


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    paymentListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    paymentListResponse(
        false,
        'You do not have permission to manage payments.',
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


$gateway =
    strtolower(
        trim(
            (string)(
                $_GET['gateway']
                ??
                ''
            )
        )
    );


$allowedStatuses = [
    'paid',
    'pending',
    'failed',
    'processing',
    'refunded',
    'cancelled'
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


$allowedGateways = [
    'mpesa',
    'card',
    'paypal'
];


if (
    !in_array(
        $gateway,
        $allowedGateways,
        true
    )
) {

    $gateway =
        '';

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
            p.payment_reference LIKE :search_reference

            OR u.username LIKE :search_username

            OR u.full_names LIKE :search_names

            OR u.email LIKE :search_email

            OR p.gateway_transaction_id LIKE :search_gateway_transaction

            OR p.checkout_reference LIKE :search_checkout
        )
        ";


    $like =
        '%'
        .
        $search
        .
        '%';


    $params[':search_reference'] =
        $like;

    $params[':search_username'] =
        $like;

    $params[':search_names'] =
        $like;

    $params[':search_email'] =
        $like;

    $params[':search_gateway_transaction'] =
        $like;

    $params[':search_checkout'] =
        $like;

}


if (
    $status !== ''
) {

    $where[] =
        'p.status = :status';


    $params[':status'] =
        $status;

}


if (
    $gateway !== ''
) {

    $where[] =
        'LOWER(p.gateway) = :gateway';


    $params[':gateway'] =
        $gateway;

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

    $count =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM payments p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN services sv
                ON sv.id = p.service_id

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

    paymentListResponse(
        false,
        'Unable to count payment records.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| PAYMENTS
|--------------------------------------------------------------------------
*/

try {

    $sql =
        "
        SELECT

            p.id,

            p.user_id,

            p.service_id,

            p.subscription_id,

            p.payment_reference,

            p.gateway,

            p.gateway_transaction_id,

            p.payment_method,

            p.status,

            p.currency_id,

            p.base_amount_usd,

            p.exchange_rate,

            p.amount_expected,

            p.amount_paid,

            p.gateway_fee,

            p.phone_number,

            p.checkout_reference,

            p.paid_at,

            p.created_at,

            p.updated_at,

            u.username,

            u.full_names,

            u.email,

            sv.name AS service_name,

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

                ORDER BY ph.id DESC

                LIMIT 1

            ) AS avatar_url

        FROM payments p

        INNER JOIN users u
            ON u.id = p.user_id

        LEFT JOIN services sv
            ON sv.id = p.service_id

        LEFT JOIN currencies c
            ON c.id = p.currency_id

        {$whereSql}

        ORDER BY
            p.created_at DESC,
            p.id DESC

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


    $payments =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI ADMIN PAYMENT LIST] '
        .
        $e->getMessage()
    );


    paymentListResponse(
        false,
        'Unable to load payments.',
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
                    SUM(status = 'paid'),
                    0
                ) AS paid,

                COALESCE(
                    SUM(status = 'pending'),
                    0
                ) AS pending,

                COALESCE(
                    SUM(status = 'failed'),
                    0
                ) AS failed,

                COALESCE(
                    SUM(status = 'refunded'),
                    0
                ) AS refunded

            FROM payments
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary = [
        'total' => 0,
        'paid' => 0,
        'pending' => 0,
        'failed' => 0,
        'refunded' => 0
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

            SET last_activity_at =
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
        '[LOVEMI PAYMENT SESSION ACTIVITY] '
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

paymentListResponse(
    true,
    'Payments loaded successfully.',
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

        'payments' =>
            $payments,

        'summary' => [

            'total' =>
                (int)(
                    $summary['total']
                    ??
                    0
                ),

            'paid' =>
                (int)(
                    $summary['paid']
                    ??
                    0
                ),

            'pending' =>
                (int)(
                    $summary['pending']
                    ??
                    0
                ),

            'failed' =>
                (int)(
                    $summary['failed']
                    ??
                    0
                ),

            'refunded' =>
                (int)(
                    $summary['refunded']
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