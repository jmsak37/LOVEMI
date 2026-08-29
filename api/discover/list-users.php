<?php
/**
 * ============================================================
 * LOVEMI - DISCOVER USERS API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\discover\list-users.php
 *
 * Returns approved/active member profiles.
 * Phone and private identity information are NEVER returned.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function discoverResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $extra
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    discoverResponse(
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
   INPUT
============================================================ */

$search =
    trim(
        (string)(
            $_GET['search']
            ?? ''
        )
    );


$gender =
    trim(
        (string)(
            $_GET['gender']
            ?? ''
        )
    );


$countryId =
    isset(
        $_GET['country_id']
    )
        ? (int)
          $_GET['country_id']
        : 0;


$country =
    trim(
        (string)(
            $_GET['country']
            ?? ''
        )
    );


$limit =
    (int)(
        $_GET['limit']
        ?? 50
    );


$limit =
    max(
        1,
        min(
            100,
            $limit
        )
    );


$offset =
    (int)(
        $_GET['offset']
        ?? 0
    );


$offset =
    max(
        0,
        $offset
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER DB] '
        . $e->getMessage()
    );


    discoverResponse(
        false,
        'Unable to connect to the database.',
        [
            'users' =>
                []
        ],
        500
    );
}


/* ============================================================
   CURRENT USER
============================================================ */

if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


/* ============================================================
   DYNAMIC WHERE
============================================================ */

$where = [

    "
    u.email_verified = TRUE
    ",

    "
    u.is_active = TRUE
    ",

    "
    u.is_suspended = FALSE
    ",

    "
    u.is_deleted = FALSE
    ",

    "
    (
        pr.profile_status IS NULL
        OR
        pr.profile_status = 'approved'
    )
    "

];


$params = [];


/* ============================================================
   EXCLUDE SELF
============================================================ */

if (
    $currentUserId > 0
) {

    $where[] =
        "u.id <> :current_user_id";


    $params[':current_user_id'] =
        $currentUserId;

}


/* ============================================================
   SEARCH
============================================================ */

if (
    $search !== ''
) {

    $where[] = "

        (
            LOWER(u.username)
                LIKE
            LOWER(:search1)

            OR

            LOWER(u.full_names)
                LIKE
            LOWER(:search2)
        )

    ";


    $searchValue =
        '%'
        .
        $search
        .
        '%';


    $params[':search1'] =
        $searchValue;


    $params[':search2'] =
        $searchValue;

}


/* ============================================================
   GENDER
============================================================ */

if (
    $gender !== ''
) {

    $allowedGenders = [

        'Male',
        'Female',
        'Other'

    ];


    if (
        in_array(
            $gender,
            $allowedGenders,
            true
        )
    ) {

        $where[] =
            "u.gender = :gender";


        $params[':gender'] =
            $gender;

    }

}


/* ============================================================
   COUNTRY ID
============================================================ */

if (
    $countryId > 0
) {

    $where[] =
        "u.country_id = :country_id";


    $params[':country_id'] =
        $countryId;

}


/* ============================================================
   COUNTRY NAME
============================================================ */

if (
    $country !== ''
    &&
    $countryId <= 0
) {

    $where[] =
        "LOWER(c.name) = LOWER(:country)";


    $params[':country'] =
        $country;

}


/* ============================================================
   QUERY
============================================================ */

$sql = "

    SELECT

        u.id,
        u.username,
        u.full_names,
        u.gender,
        u.email_verified,

        c.id AS country_id,
        c.name AS country_name,
        c.iso2 AS country_iso2,

        pr.profile_photo,
        pr.profile_status,

        CASE

            WHEN EXISTS
            (

                SELECT 1

                FROM user_sessions us

                WHERE us.user_id = u.id

                  AND us.revoked_at IS NULL

                  AND us.two_factor_passed = TRUE

                  AND us.expires_at >
                      CURRENT_TIMESTAMP

                  AND us.last_activity_at >=
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL 10 MINUTE
                      )

            )

            THEN TRUE

            ELSE FALSE

        END AS is_online

    FROM users u

    LEFT JOIN countries c
        ON c.id = u.country_id

    LEFT JOIN profiles pr
        ON pr.user_id = u.id

    WHERE
        "
        .
        implode(
            ' AND ',
            $where
        )
        . "

    ORDER BY

        is_online DESC,

        u.created_at DESC,

        u.id DESC

    LIMIT :limit
    OFFSET :offset

";


/* ============================================================
   RUN QUERY
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            $sql
        );


    foreach (
        $params as $key => $value
    ) {

        if (
            $key ===
            ':current_user_id'
            ||
            $key ===
            ':country_id'
        ) {

            $stmt->bindValue(
                $key,
                (int)
                $value,
                PDO::PARAM_INT
            );

        } else {

            $stmt->bindValue(
                $key,
                $value,
                PDO::PARAM_STR
            );

        }

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


} catch (Throwable $e) {

    error_log(
        '[LOVEMI DISCOVER QUERY] '
        .
        $e->getMessage()
    );


    discoverResponse(
        false,
        'Profiles could not be loaded.',
        [
            'code' =>
                'DISCOVER_QUERY_ERROR',

            'users' =>
                []
        ],
        500
    );
}


/* ============================================================
   CLEAN RESPONSE
============================================================ */

$cleanUsers = [];


foreach (
    $users as $user
) {

    $cleanUsers[] = [

        'id' =>
            (int)
            $user['id'],

        'username' =>
            (string)
            $user['username'],

        'full_name' =>
            (string)
            $user['full_names'],

        'gender' =>
            (string)
            $user['gender'],

        'email_verified' =>
            (bool)
            $user['email_verified'],

        'country_id' =>
            $user['country_id'] !== null
                ? (int)
                  $user['country_id']
                : null,

        'country_name' =>
            $user['country_name'] !== null
                ? (string)
                  $user['country_name']
                : null,

        'country_iso2' =>
            $user['country_iso2'] !== null
                ? strtoupper(
                    (string)
                    $user['country_iso2']
                )
                : null,

        'profile_photo' =>
            $user['profile_photo'] !== null
                ? (string)
                  $user['profile_photo']
                : null,

        'photo_url' =>
            $user['profile_photo'] !== null
                ? (string)
                  $user['profile_photo']
                : null,

        'is_online' =>
            (bool)
            $user['is_online'],

        'profile_status' =>
            $user['profile_status'] !== null
                ? (string)
                  $user['profile_status']
                : null

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

discoverResponse(
    true,
    'Approved profiles loaded successfully.',
    [
        'count' =>
            count(
                $cleanUsers
            ),

        'users' =>
            $cleanUsers,

        'data' =>
            $cleanUsers
    ]
);