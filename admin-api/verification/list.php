<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - VERIFICATION LIST
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

function verificationListResponse(
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
        '[LOVEMI VERIFICATION LIST DB] '
        .
        $e->getMessage()
    );


    verificationListResponse(
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

    verificationListResponse(
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
| ADMIN PERMISSION
|--------------------------------------------------------------------------
|
| users.manage is used because the database permission set does
| not contain a separate verification.manage permission.
|
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
                    'users.manage'

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
        '[LOVEMI VERIFICATION AUTH] '
        .
        $e->getMessage()
    );


    verificationListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    verificationListResponse(
        false,
        'You do not have permission to manage verification.',
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


$filter =
    strtolower(
        trim(
            (string)(
                $_GET['filter']
                ??
                ''
            )
        )
    );


/*
|--------------------------------------------------------------------------
| CONDITIONS
|--------------------------------------------------------------------------
*/

$where =
    [
        'u.is_deleted = 0'
    ];


$params =
    [];


if (
    $search !== ''
) {

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


/*
|--------------------------------------------------------------------------
| FILTERS
|--------------------------------------------------------------------------
*/

switch (
    $filter
) {

    case 'email_unverified':

        $where[] =
            'u.email_verified = 0';

        break;


    case 'phone_unverified':

        $where[] =
            'u.phone_verified = 0';

        break;


    case 'identity_unverified':

        $where[] =
            'u.identity_verified = 0';

        break;


    case 'age_unverified':

        $where[] =
            'u.age_verified = 0';

        break;


    case 'account_pending':

        $where[] =
            "
            LOWER(
                u.account_status
            ) NOT IN (
                'approved',
                'active'
            )
            ";

        break;


    case 'fully_verified':

        $where[] =
            "
            u.email_verified = 1

            AND u.phone_verified = 1

            AND u.identity_verified = 1

            AND u.age_verified = 1

            AND LOWER(
                u.account_status
            ) = 'approved'
            ";

        break;

}


$whereSql =
    'WHERE '
    .
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

    $countStmt =
        $pdo->prepare(
            "
            SELECT
                COUNT(*)

            FROM users u

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

    verificationListResponse(
        false,
        'Unable to count verification records.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| USERS
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.phone_number,

                u.phone_e164,

                u.date_of_birth,

                u.email_verified,

                u.phone_verified,

                u.identity_verified,

                u.age_verified,

                u.account_status,

                u.updated_at,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            u.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY
                        p.id DESC

                    LIMIT 1

                ) AS avatar

            FROM users u

            {$whereSql}

            ORDER BY
                u.created_at DESC,
                u.id DESC

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


    $users =
        $stmt->fetchAll();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFICATION USER QUERY] '
        .
        $e->getMessage()
    );


    verificationListResponse(
        false,
        'Unable to load verification records.',
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

                COALESCE(
                    SUM(
                        email_verified = 1
                    ),
                    0
                )
                AS email_verified,

                COALESCE(
                    SUM(
                        phone_verified = 1
                    ),
                    0
                )
                AS phone_verified,

                COALESCE(
                    SUM(
                        identity_verified = 1
                    ),
                    0
                )
                AS identity_verified,

                COALESCE(
                    SUM(
                        age_verified = 1
                    ),
                    0
                )
                AS age_verified,

                COALESCE(
                    SUM(
                        LOWER(
                            account_status
                        )
                        =
                        'approved'
                    ),
                    0
                )
                AS approved

            FROM users

            WHERE
                is_deleted = 0
            "
        );


    $summary =
        $summaryStmt->fetch();

} catch (
    Throwable $e
) {

    $summary = [

        'email_verified' =>
            0,

        'phone_verified' =>
            0,

        'identity_verified' =>
            0,

        'age_verified' =>
            0,

        'approved' =>
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
        '[LOVEMI VERIFICATION SESSION] '
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


verificationListResponse(
    true,
    'Verification records loaded successfully.',
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

        'users' =>
            $users,

        'summary' => [

            'email_verified' =>
                (int)(
                    $summary['email_verified']
                    ??
                    0
                ),

            'phone_verified' =>
                (int)(
                    $summary['phone_verified']
                    ??
                    0
                ),

            'identity_verified' =>
                (int)(
                    $summary['identity_verified']
                    ??
                    0
                ),

            'age_verified' =>
                (int)(
                    $summary['age_verified']
                    ??
                    0
                ),

            'approved' =>
                (int)(
                    $summary['approved']
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