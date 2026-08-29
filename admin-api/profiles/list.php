<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN PROFILES LIST API
|--------------------------------------------------------------------------
|
| GET /admin-api/profiles/list.php
|
| Parameters:
|
| page
| limit
| search
| visibility
| allow_messages
|
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../config/database.php';


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


/* ============================================================
   RESPONSE
============================================================ */

function profilesListResponse(
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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    profilesListResponse(
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
   SESSION VALUES
============================================================ */

$adminId =
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


$sessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


if (
    $adminId <= 0
    ||
    $sessionToken === ''
    ||
    $sessionId <= 0
) {

    profilesListResponse(
        false,
        'You must log in first.',
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
        '[LOVEMI PROFILES LIST DB] '
        .
        $e->getMessage()
    );


    profilesListResponse(
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
   ADMIN AUTH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role,

                p_admin.display_name AS admin_display_name,

                ph_admin.file_path AS avatar_url

            FROM users u

            INNER JOIN roles r
                ON r.id =
                   u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                   u.id

            LEFT JOIN profiles p_admin
                ON p_admin.user_id =
                   u.id

            LEFT JOIN photos ph_admin
                ON ph_admin.user_id =
                   u.id

                AND ph_admin.photo_type =
                    'profile'

                AND ph_admin.is_primary =
                    1

                AND ph_admin.approval_status =
                    'approved'

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
        '[LOVEMI PROFILES LIST AUTH] '
        .
        $e->getMessage()
    );


    profilesListResponse(
        false,
        'Unable to verify administrator access.',
        [
            'code' =>
                'ADMIN_AUTH_FAILED'
        ],
        500
    );

}


if (
    !$admin
) {

    profilesListResponse(
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
   PERMISSION
============================================================ */

try {

    $permissionCheck =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id =
                   rp.permission_id

            WHERE

                rp.role_id =
                    :role_id

                AND p.slug =
                    'profiles.manage'
            "
        );


    $permissionCheck->execute(
        [
            ':role_id' =>
                (int)
                $admin['role_id']
        ]
    );


    $allowed =
        (
            (int)
            $permissionCheck->fetchColumn()
        )
        >
        0;

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILES PERMISSION] '
        .
        $e->getMessage()
    );


    profilesListResponse(
        false,
        'Unable to verify profile management permission.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


if (
    !$allowed
) {

    profilesListResponse(
        false,
        'You do not have permission to manage profiles.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   INPUT
============================================================ */

$page =
    max(
        1,
        (int)
        (
            $_GET['page']
            ??
            1
        )
    );


$limit =
    (int)
    (
        $_GET['limit']
        ??
        20
    );


$limit =
    max(
        5,
        min(
            100,
            $limit
        )
    );


$offset =
    (
        $page -
        1
    )
    *
    $limit;


$search =
    trim(
        (string)
        (
            $_GET['search']
            ??
            ''
        )
    );


$visibility =
    strtolower(
        trim(
            (string)
            (
                $_GET['visibility']
                ??
                ''
            )
        )
    );


$allowMessagesRaw =
    isset(
        $_GET['allow_messages']
    )
        ?
        (string)
        $_GET['allow_messages']
        :
        '';


/* ============================================================
   VALID VISIBILITY
============================================================ */

$validVisibility =
    [
        '',
        'public',
        'private',
        'friends'
    ];


if (
    !in_array(
        $visibility,
        $validVisibility,
        true
    )
) {

    profilesListResponse(
        false,
        'Invalid visibility filter.',
        [
            'code' =>
                'INVALID_VISIBILITY'
        ],
        422
    );

}


/* ============================================================
   BUILD WHERE
============================================================ */

$where =
    [
        '1 = 1'
    ];


$params =
    [];


if (
    $search !== ''
) {

    $where[] =
        "
        (
            u.username LIKE :search

            OR u.full_names LIKE :search

            OR u.email LIKE :search

            OR p.display_name LIKE :search

            OR p.city LIKE :search

            OR p.occupation LIKE :search

            OR c.name LIKE :search
        )
        ";

    $params[
        ':search'
    ] =
        '%' .
        $search .
        '%';

}


if (
    $visibility !== ''
) {

    $where[] =
        'p.profile_visibility = :visibility';

    $params[
        ':visibility'
    ] =
        $visibility;

}


if (
    $allowMessagesRaw === '0'
    ||
    $allowMessagesRaw === '1'
) {

    $where[] =
        'p.allow_messages = :allow_messages';

    $params[
        ':allow_messages'
    ] =
        (int)
        $allowMessagesRaw;

}


/* ============================================================
   COUNT
============================================================ */

$whereSql =
    implode(
        ' AND ',
        $where
    );


try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM profiles p

            INNER JOIN users u
                ON u.id =
                   p.user_id

            LEFT JOIN countries c
                ON c.id =
                   u.country_id

            WHERE
                {$whereSql}

              AND u.is_deleted =
                  0
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
        '[LOVEMI PROFILES COUNT] '
        .
        $e->getMessage()
    );


    profilesListResponse(
        false,
        'Unable to count profiles.',
        [
            'code' =>
                'COUNT_FAILED'
        ],
        500
    );

}


/* ============================================================
   PROFILE LIST
============================================================ */

try {

    $sql =
        "
        SELECT

            p.id AS profile_id,

            p.user_id,

            p.display_name,

            p.bio,

            p.occupation,

            p.education,

            p.city,

            p.relationship_status,

            p.looking_for,

            p.interests,

            p.profile_visibility,

            p.show_online_status,

            p.allow_messages,

            p.created_at,

            p.updated_at,

            u.username,

            u.full_names,

            u.email,

            u.gender,

            u.account_status,

            u.email_verified,

            u.phone_verified,

            u.identity_verified,

            u.age_verified,

            c.name AS country_name,

            c.iso2 AS country_iso2,

            ph.file_path AS avatar_url,

            ph.thumbnail_path AS avatar_thumbnail

        FROM profiles p

        INNER JOIN users u
            ON u.id =
               p.user_id

        LEFT JOIN countries c
            ON c.id =
               u.country_id

        LEFT JOIN photos ph
            ON ph.user_id =
               u.id

            AND ph.photo_type =
                'profile'

            AND ph.is_primary =
                1

            AND ph.approval_status =
                'approved'

        WHERE

            {$whereSql}

            AND u.is_deleted =
                0

        ORDER BY
            p.updated_at DESC,
            p.id DESC

        LIMIT
            :limit

        OFFSET
            :offset
        ";


    $stmt =
        $pdo->prepare(
            $sql
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


    $profiles =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILES LIST QUERY] '
        .
        $e->getMessage()
    );


    profilesListResponse(
        false,
        'Unable to load profiles.',
        [
            'code' =>
                'PROFILE_LIST_FAILED'
        ],
        500
    );

}


/* ============================================================
   SUMMARY
============================================================ */

try {

    $summaryStmt =
        $pdo->query(
            "
            SELECT

                COUNT(*) AS total_profiles,

                SUM(
                    CASE
                        WHEN profile_visibility = 'public'
                        THEN 1
                        ELSE 0
                    END
                ) AS public_profiles,

                SUM(
                    CASE
                        WHEN allow_messages = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS messages_allowed,

                SUM(
                    CASE
                        WHEN show_online_status = 1
                        THEN 1
                        ELSE 0
                    END
                ) AS online_visible

            FROM profiles
            "
        );


    $summary =
        $summaryStmt->fetch()
        ?:
        [];

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILES SUMMARY] '
        .
        $e->getMessage()
    );


    $summary =
        [
            'total_profiles' =>
                0,

            'public_profiles' =>
                0,

            'messages_allowed' =>
                0,

            'online_visible' =>
                0
        ];

}


/* ============================================================
   ACTIVITY
============================================================ */

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

    error_log(
        '[LOVEMI PROFILES ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   PAGES
============================================================ */

$pages =
    $total > 0
        ?
        (int)
        ceil(
            $total /
            $limit
        )
        :
        1;


/* ============================================================
   RESPONSE
============================================================ */

profilesListResponse(
    true,
    'Profiles loaded successfully.',
    [
        'data' => [

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

                'role_id' =>
                    (int)
                    $admin['role_id'],

                'role_name' =>
                    $admin['role_name'],

                'role_slug' =>
                    $admin['role_slug'],

                'avatar_url' =>
                    $admin['avatar_url']
                    ??
                    null

            ],

            'profiles' =>
                $profiles,

            'summary' =>
                [

                    'total_profiles' =>
                        (int)
                        (
                            $summary[
                                'total_profiles'
                            ]
                            ??
                            0
                        ),

                    'public_profiles' =>
                        (int)
                        (
                            $summary[
                                'public_profiles'
                            ]
                            ??
                            0
                        ),

                    'messages_allowed' =>
                        (int)
                        (
                            $summary[
                                'messages_allowed'
                            ]
                            ??
                            0
                        ),

                    'online_visible' =>
                        (int)
                        (
                            $summary[
                                'online_visible'
                            ]
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

    ]
);