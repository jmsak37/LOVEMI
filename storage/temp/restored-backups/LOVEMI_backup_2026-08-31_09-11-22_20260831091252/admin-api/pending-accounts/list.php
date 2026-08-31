<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - PENDING ACCOUNTS LIST
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


function pendingListResponse(
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
        '[LOVEMI PENDING LIST DB] '
        .
        $e->getMessage()
    );


    pendingListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTH
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

    pendingListResponse(
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

            INNER JOIN permissions p
                ON p.id = rp.permission_id

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
        '[LOVEMI PENDING LIST AUTH] '
        .
        $e->getMessage()
    );


    pendingListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    pendingListResponse(
        false,
        'You do not have permission to manage pending accounts.',
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


$sort =
    strtolower(
        trim(
            (string)(
                $_GET['sort']
                ??
                'oldest'
            )
        )
    );


/*
|--------------------------------------------------------------------------
| REQUIREMENT SETTINGS
|--------------------------------------------------------------------------
*/

$requireEmail =
    true;

$requirePhone =
    true;

$requireIdentity =
    true;


/*
 * Age is required for account approval in this LOVEMI flow.
 */

$requireAge =
    true;


try {

    $settingStmt =
        $pdo->query(
            "
            SELECT
                setting_key,
                setting_value

            FROM system_settings

            WHERE
                setting_key IN
                (
                    'require_email_verification',
                    'require_phone_verification',
                    'require_identity_verification'
                )
            "
        );


    while (
        $row =
            $settingStmt->fetch()
    ) {

        $key =
            $row['setting_key'];


        $value =
            filter_var(
                $row['setting_value'],
                FILTER_VALIDATE_BOOLEAN
            );


        if (
            $key ===
            'require_email_verification'
        ) {

            $requireEmail =
                $value;

        }


        if (
            $key ===
            'require_phone_verification'
        ) {

            $requirePhone =
                $value;

        }


        if (
            $key ===
            'require_identity_verification'
        ) {

            $requireIdentity =
                $value;

        }

    }

} catch (
    Throwable $e
) {

    /*
     * Existing safe defaults remain active.
     */

}


/*
|--------------------------------------------------------------------------
| AGE
|--------------------------------------------------------------------------
*/

$minimumAge =
    18;


try {

    $ageStmt =
        $pdo->prepare(
            "
            SELECT
                setting_value

            FROM system_settings

            WHERE
                setting_key =
                    'minimum_age'

            LIMIT 1
            "
        );


    $ageStmt->execute();


    $ageValue =
        $ageStmt->fetchColumn();


    if (
        is_numeric(
            $ageValue
        )
    ) {

        $minimumAge =
            (int)
            $ageValue;

    }

} catch (
    Throwable $e
) {

    $minimumAge =
        18;

}


/*
|--------------------------------------------------------------------------
| CONDITIONS
|--------------------------------------------------------------------------
*/

$where =
    [
        "
        LOWER(
            u.account_status
        ) NOT IN
        (
            'approved',
            'active'
        )
        ",

        "u.is_deleted = 0"
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


    $params[':username'] =
        $like;

    $params[':full_names'] =
        $like;

    $params[':email'] =
        $like;

}


switch (
    $filter
) {

    case 'ready':

        $where[] =
            "
            u.email_verified = 1

            AND u.phone_verified = 1

            AND u.identity_verified = 1

            AND u.age_verified = 1
            ";

        break;


    case 'needs_verification':

        $where[] =
            "
            (
                u.email_verified = 0

                OR u.phone_verified = 0

                OR u.identity_verified = 0

                OR u.age_verified = 0
            )
            ";

        break;

}


/*
|--------------------------------------------------------------------------
| ORDER
|--------------------------------------------------------------------------
*/

$orderBy =
    $sort ===
    'newest'
        ?
        'u.created_at DESC, u.id DESC'
        :
        'u.created_at ASC, u.id ASC';


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

    error_log(
        '[LOVEMI PENDING COUNT] '
        .
        $e->getMessage()
    );


    pendingListResponse(
        false,
        'Unable to count pending accounts.',
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

                u.date_of_birth,

                u.email_verified,

                u.phone_verified,

                u.identity_verified,

                u.age_verified,

                u.account_status,

                u.created_at,

                u.updated_at,

                (
                    SELECT
                        ph.file_path

                    FROM photos ph

                    WHERE

                        ph.user_id =
                            u.id

                        AND ph.photo_type =
                            'profile'

                        AND ph.is_primary =
                            1

                        AND ph.approval_status =
                            'approved'

                    ORDER BY
                        ph.id DESC

                    LIMIT 1

                ) AS avatar

            FROM users u

            {$whereSql}

            ORDER BY
                {$orderBy}

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
        '[LOVEMI PENDING USERS] '
        .
        $e->getMessage()
    );


    pendingListResponse(
        false,
        'Unable to load pending accounts.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| CAN APPROVE
|--------------------------------------------------------------------------
*/

foreach (
    $users as &$user
) {

    $user['can_approve'] =
        (
            !$requireEmail
            ||
            (bool)
            $user['email_verified']
        )
        &&
        (
            !$requirePhone
            ||
            (bool)
            $user['phone_verified']
        )
        &&
        (
            !$requireIdentity
            ||
            (bool)
            $user['identity_verified']
        )
        &&
        (
            !$requireAge
            ||
            (bool)
            $user['age_verified']
        );

}


unset(
    $user
);


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
                        LOWER(
                            account_status
                        ) NOT IN
                        (
                            'approved',
                            'active'
                        )
                        AND is_deleted = 0
                    ),
                    0
                ) AS pending,

                COALESCE(
                    SUM(
                        LOWER(
                            account_status
                        ) NOT IN
                        (
                            'approved',
                            'active'
                        )
                        AND is_deleted = 0
                        AND email_verified = 1
                    ),
                    0
                ) AS email_ready,

                COALESCE(
                    SUM(
                        LOWER(
                            account_status
                        ) NOT IN
                        (
                            'approved',
                            'active'
                        )
                        AND is_deleted = 0
                        AND email_verified = 1
                        AND phone_verified = 1
                        AND identity_verified = 1
                        AND age_verified = 1
                    ),
                    0
                ) AS fully_verified

            FROM users
            "
        );


    $summary =
        $summaryStmt->fetch();


    $pendingTotal =
        (int)(
            $summary['pending']
            ??
            0
        );


    $fullyVerified =
        (int)(
            $summary['fully_verified']
            ??
            0
        );


    $summary['needs_review'] =
        max(
            0,
            $pendingTotal
            -
            $fullyVerified
        );

} catch (
    Throwable $e
) {

    $summary =
        [
            'pending' =>
                0,

            'email_ready' =>
                0,

            'fully_verified' =>
                0,

            'needs_review' =>
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

    $avatar =
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


pendingListResponse(
    true,
    'Pending accounts loaded successfully.',
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

            'pending' =>
                (int)
                ($summary['pending'] ?? 0),

            'email_ready' =>
                (int)
                ($summary['email_ready'] ?? 0),

            'fully_verified' =>
                (int)
                ($summary['fully_verified'] ?? 0),

            'needs_review' =>
                (int)
                ($summary['needs_review'] ?? 0)

        ],

        'users' =>
            $users,

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