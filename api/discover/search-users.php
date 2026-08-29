<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - SEARCH USERS
|--------------------------------------------------------------------------
|
| GET examples:
|
|   search-users.php?q=john
|
|   search-users.php?q=nairobi
|
|   search-users.php?q=KE
|
|   search-users.php?q=254
|
| Returns public-safe profile information only.
|
|--------------------------------------------------------------------------
*/


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


if (
    session_status() !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* =========================================================================
   RESPONSE
========================================================================= */

function searchUsersResponse(
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


/* =========================================================================
   METHOD
========================================================================= */

if (
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    searchUsersResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* =========================================================================
   OPTIONAL AUTH
========================================================================= */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


/* =========================================================================
   INPUT
========================================================================= */

$query =
    trim(
        (string)
        (
            $_GET['q']
            ??
            $_GET['search']
            ??
            ''
        )
    );


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


$requestedLimit =
    (int)
    (
        $_GET['limit']
        ??
        20
    );


$limit =
    min(
        50,
        max(
            1,
            $requestedLimit
        )
    );


$offset =
    (
        $page -
        1
    )
    *
    $limit;


/* =========================================================================
   DATABASE
========================================================================= */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SEARCH USERS DB] '
        .
        $e->getMessage()
    );


    searchUsersResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* =========================================================================
   SEARCH CONDITION
========================================================================= */

$where = [

    "
    u.is_active = 1
    ",

    "
    u.is_suspended = 0
    ",

    "
    u.is_deleted = 0
    ",

    "
    p.profile_visibility = 'public'
    "

];


$params = [];


/*
|--------------------------------------------------------------------------
| Never show current user in discovery.
|--------------------------------------------------------------------------
*/

if (
    $currentUserId >
    0
) {

    $where[] =
        "
        u.id <>
        :current_user_id
        ";

    $params[
        ':current_user_id'
    ] =
        $currentUserId;

}


/*
|--------------------------------------------------------------------------
| Exclude users blocked by current user and users who blocked
| current user.
|--------------------------------------------------------------------------
*/

if (
    $currentUserId >
    0
) {

    $where[] =
        "
        NOT EXISTS
        (
            SELECT 1

            FROM blocked_users b1

            WHERE b1.user_id =
                  :blocker_id

              AND b1.blocked_user_id =
                  u.id
        )
        ";


    $params[
        ':blocker_id'
    ] =
        $currentUserId;


    $where[] =
        "
        NOT EXISTS
        (
            SELECT 1

            FROM blocked_users b2

            WHERE b2.user_id =
                  u.id

              AND b2.blocked_user_id =
                  :blocked_by_user
        )
        ";


    $params[
        ':blocked_by_user'
    ] =
        $currentUserId;

}


/*
|--------------------------------------------------------------------------
| Search.
|--------------------------------------------------------------------------
*/

if (
    $query !==
    ''
) {

    $where[] =
        "
        (
            u.username LIKE :search_username

            OR

            u.full_names LIKE :search_full_names

            OR

            p.display_name LIKE :search_display_name

            OR

            p.city LIKE :search_city

            OR

            c.name LIKE :search_country

            OR

            c.iso2 LIKE :search_iso2

            OR

            c.iso3 LIKE :search_iso3

            OR

            c.phone_code LIKE :search_phone_code
        )
        ";


    $search =
        '%' .
        $query .
        '%';


    $params[
        ':search_username'
    ] =
        $search;

    $params[
        ':search_full_names'
    ] =
        $search;

    $params[
        ':search_display_name'
    ] =
        $search;

    $params[
        ':search_city'
    ] =
        $search;

    $params[
        ':search_country'
    ] =
        $search;

    $params[
        ':search_iso2'
    ] =
        $search;

    $params[
        ':search_iso3'
    ] =
        $search;

    $params[
        ':search_phone_code'
    ] =
        $search;

}


/* =========================================================================
   QUERY
========================================================================= */

$sql =
    "
    SELECT

        u.id,
        u.username,
        u.full_names,
        u.gender,
        u.country_id,

        c.name AS country_name,
        c.iso2,
        c.iso3,

        p.display_name,
        p.bio,
        p.occupation,
        p.education,
        p.city,
        p.relationship_status,
        p.looking_for,
        p.interests,

        p.show_online_status,
        p.allow_messages,

        up.is_online,
        up.last_seen_at

    FROM users u

    INNER JOIN profiles p
        ON p.user_id =
           u.id

    LEFT JOIN countries c
        ON c.id =
           u.country_id

    LEFT JOIN user_presence up
        ON up.user_id =
           u.id

    WHERE
        "
    .
    implode(
        ' AND ',
        $where
    )
    .
    "

    ORDER BY

        CASE
            WHEN up.is_online = 1
            THEN 0
            ELSE 1
        END,

        u.created_at DESC,
        u.id DESC

    LIMIT
        :limit

    OFFSET
        :offset
    ";


/* =========================================================================
   EXECUTE
========================================================================= */

try {

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


    $rows =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SEARCH USERS QUERY] '
        .
        $e->getMessage()
    );


    searchUsersResponse(
        false,
        'Unable to search LOVEMI members.',
        [
            'code' =>
                'SEARCH_FAILED'
        ],
        500
    );

}


/* =========================================================================
   BUILD RESULTS
========================================================================= */

$users = [];


foreach (
    $rows
    as $row
) {


    /*
    |--------------------------------------------------------------------------
    | Online state should also respect last_seen_at.
    |--------------------------------------------------------------------------
    */

    $online =
        (bool)
        $row['is_online'];


    if (
        (int)
        $row['show_online_status']
        !==
        1
    ) {

        $online =
            false;

    }


    if (
        !empty(
            $row['last_seen_at']
        )
    ) {

        $lastSeen =
            strtotime(
                (string)
                $row['last_seen_at']
            );


        if (
            $lastSeen !==
            false
            &&
            (
                time() -
                $lastSeen
            )
            <=
            300
            &&
            (
                (int)
                $row['show_online_status']
            )
            ===
            1
        ) {

            $online =
                true;

        }

    }


    /*
    |--------------------------------------------------------------------------
    | Approved primary photo.
    |--------------------------------------------------------------------------
    */

    $photo =
        null;


    try {

        $photoStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    file_name,
                    file_path,
                    thumbnail_path,
                    mime_type

                FROM photos

                WHERE user_id =
                      :user_id

                  AND approval_status =
                      'approved'

                  AND photo_type IN
                      (
                          'profile',
                          'post'
                      )

                ORDER BY

                    is_primary DESC,
                    is_featured DESC,
                    uploaded_at DESC,
                    id DESC

                LIMIT 1
                "
            );


        $photoStmt->execute(
            [
                ':user_id' =>
                    (int)
                    $row['id']
            ]
        );


        $photoRow =
            $photoStmt->fetch();


        if (
            $photoRow
        ) {

            $photo = [

                'id' =>
                    (int)
                    $photoRow['id'],

                'file_name' =>
                    $photoRow['file_name'],

                'file_path' =>
                    $photoRow['file_path'],

                'thumbnail_path' =>
                    $photoRow['thumbnail_path'],

                'mime_type' =>
                    $photoRow['mime_type']

            ];

        }

    } catch (
        Throwable $e
    ) {

        $photo =
            null;

    }


    $users[] = [

        'id' =>
            (int)
            $row['id'],

        'username' =>
            $row['username'],

        'full_names' =>
            $row['full_names'],

        'display_name' =>
            $row['display_name']
            ??
            $row['full_names'],

        'gender' =>
            $row['gender'],

        'country' => [

            'id' =>
                $row['country_id']
                !==
                null
                    ?
                    (int)
                    $row['country_id']
                    :
                    null,

            'name' =>
                $row['country_name'],

            'iso2' =>
                $row['iso2'],

            'iso3' =>
                $row['iso3']

        ],

        'bio' =>
            $row['bio'],

        'occupation' =>
            $row['occupation'],

        'education' =>
            $row['education'],

        'city' =>
            $row['city'],

        'relationship_status' =>
            $row['relationship_status'],

        'looking_for' =>
            $row['looking_for'],

        'interests' =>
            $row['interests'],

        'allow_messages' =>
            (bool)
            $row['allow_messages'],

        'online' =>
            $online,

        'last_seen_at' =>
            (
                $row['show_online_status']
                ?
                $row['last_seen_at']
                :
                null
            ),

        'photo' =>
            $photo

    ];

}


/* =========================================================================
   RESPONSE
========================================================================= */

searchUsersResponse(
    true,
    'Users found successfully.',
    [

        'query' =>
            $query,

        'page' =>
            $page,

        'limit' =>
            $limit,

        'count' =>
            count(
                $users
            ),

        'users' =>
            $users

    ]
);