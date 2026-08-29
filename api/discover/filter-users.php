<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - FILTER USERS
|--------------------------------------------------------------------------
|
| GET examples:
|
| filter-users.php?country_id=1
|
| filter-users.php?gender=Female
|
| filter-users.php?min_age=25&max_age=35
|
| filter-users.php?city=Nairobi
|
| filter-users.php?online=1
|
| Multiple filters can be combined.
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

function filterUsersResponse(
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

    filterUsersResponse(
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
   AUTH
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

$countryId =
    (int)
    (
        $_GET['country_id']
        ??
        0
    );


$countrySearch =
    trim(
        (string)
        (
            $_GET['country']
            ??
            ''
        )
    );


$gender =
    trim(
        (string)
        (
            $_GET['gender']
            ??
            ''
        )
    );


$city =
    trim(
        (string)
        (
            $_GET['city']
            ??
            ''
        )
    );


$lookingFor =
    trim(
        (string)
        (
            $_GET['looking_for']
            ??
            ''
        )
    );


$relationshipStatus =
    trim(
        (string)
        (
            $_GET['relationship_status']
            ??
            ''
        )
    );


$minAge =
    (int)
    (
        $_GET['min_age']
        ??
        0
    );


$maxAge =
    (int)
    (
        $_GET['max_age']
        ??
        0
    );


$online =
    isset(
        $_GET['online']
    )
        ?
        (
            (int)
            $_GET['online']
        )
        :
        -1;


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
   VALIDATE AGE
========================================================================= */

if (
    $minAge < 0
) {

    $minAge =
        0;

}


if (
    $maxAge < 0
) {

    $maxAge =
        0;

}


if (
    $minAge >
    0
    &&
    $maxAge >
    0
    &&
    $minAge >
    $maxAge
) {

    $swap =
        $minAge;

    $minAge =
        $maxAge;

    $maxAge =
        $swap;

}


/* =========================================================================
   VALIDATE ONLINE
========================================================================= */

if (
    !in_array(
        $online,
        [
            -1,
            0,
            1
        ],
        true
    )
) {

    $online =
        -1;

}


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
        '[LOVEMI FILTER USERS DB] '
        .
        $e->getMessage()
    );


    filterUsersResponse(
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
   BUILD WHERE
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


/* -------------------------------------------------------------------------
   Current user exclusion
------------------------------------------------------------------------- */

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


/* -------------------------------------------------------------------------
   Country ID
------------------------------------------------------------------------- */

if (
    $countryId >
    0
) {

    $where[] =
        "
        u.country_id =
        :country_id
        ";

    $params[
        ':country_id'
    ] =
        $countryId;

}


/* -------------------------------------------------------------------------
   Country name / ISO / phone code
------------------------------------------------------------------------- */

if (
    $countrySearch !==
    ''
) {

    $where[] =
        "
        (
            c.name LIKE :country_name

            OR

            c.iso2 LIKE :country_iso2

            OR

            c.iso3 LIKE :country_iso3

            OR

            c.phone_code LIKE :country_phone
        )
        ";


    $countryLike =
        '%' .
        $countrySearch .
        '%';


    $params[
        ':country_name'
    ] =
        $countryLike;


    $params[
        ':country_iso2'
    ] =
        $countryLike;


    $params[
        ':country_iso3'
    ] =
        $countryLike;


    $params[
        ':country_phone'
    ] =
        $countryLike;

}


/* -------------------------------------------------------------------------
   Gender
------------------------------------------------------------------------- */

if (
    $gender !==
    ''
) {

    $where[] =
        "
        LOWER(u.gender) =
        LOWER(:gender)
        ";

    $params[
        ':gender'
    ] =
        $gender;

}


/* -------------------------------------------------------------------------
   City
------------------------------------------------------------------------- */

if (
    $city !==
    ''
) {

    $where[] =
        "
        p.city LIKE :city
        ";

    $params[
        ':city'
    ] =
        '%' .
        $city .
        '%';

}


/* -------------------------------------------------------------------------
   Looking for
------------------------------------------------------------------------- */

if (
    $lookingFor !==
    ''
) {

    $where[] =
        "
        p.looking_for LIKE :looking_for
        ";

    $params[
        ':looking_for'
    ] =
        '%' .
        $lookingFor .
        '%';

}


/* -------------------------------------------------------------------------
   Relationship status
------------------------------------------------------------------------- */

if (
    $relationshipStatus !==
    ''
) {

    $where[] =
        "
        p.relationship_status =
        :relationship_status
        ";

    $params[
        ':relationship_status'
    ] =
        $relationshipStatus;

}


/* -------------------------------------------------------------------------
   Age
------------------------------------------------------------------------- */

if (
    $minAge >
    0
) {

    $where[] =
        "
        u.date_of_birth IS NOT NULL

        AND

        TIMESTAMPDIFF(
            YEAR,
            u.date_of_birth,
            CURDATE()
        ) >=
        :min_age
        ";

    $params[
        ':min_age'
    ] =
        $minAge;

}


if (
    $maxAge >
    0
) {

    $where[] =
        "
        u.date_of_birth IS NOT NULL

        AND

        TIMESTAMPDIFF(
            YEAR,
            u.date_of_birth,
            CURDATE()
        ) <=
        :max_age
        ";

    $params[
        ':max_age'
    ] =
        $maxAge;

}


/* -------------------------------------------------------------------------
   Online
------------------------------------------------------------------------- */

if (
    $online ===
    1
) {

    $where[] =
        "
        (
            up.is_online = 1

            OR

            (
                up.last_seen_at IS NOT NULL

                AND

                up.last_seen_at >=
                    DATE_SUB(
                        CURRENT_TIMESTAMP,
                        INTERVAL 5 MINUTE
                    )
            )
        )
        ";

}


if (
    $online ===
    0
) {

    $where[] =
        "
        (
            up.is_online = 0

            OR

            up.is_online IS NULL

            OR

            up.last_seen_at IS NULL

            OR

            up.last_seen_at <
                DATE_SUB(
                    CURRENT_TIMESTAMP,
                    INTERVAL 5 MINUTE
                )
        )
        ";

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

        CASE
            WHEN
                u.date_of_birth IS NULL
            THEN
                NULL
            ELSE
                TIMESTAMPDIFF(
                    YEAR,
                    u.date_of_birth,
                    CURDATE()
                )
        END AS age,

        c.name AS country_name,
        c.iso2,
        c.iso3,
        c.phone_code,

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

        CASE
            WHEN p.is_featured_profile = 1
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


/*
|--------------------------------------------------------------------------
| Compatibility:
| Some installations may not contain a featured-profile column.
| Therefore retry without that ordering if MySQL reports the column
| does not exist.
|--------------------------------------------------------------------------
*/

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
    Throwable $firstException
) {

    /*
    |--------------------------------------------------------------------------
    | Retry with the actual saved profiles schema.
    |--------------------------------------------------------------------------
    */

    $sql =
        str_replace(
            "
            CASE
                WHEN p.is_featured_profile = 1
                THEN 0
                ELSE 1
            END,
            ",
            "",
            $sql
        );


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
        Throwable $secondException
    ) {

        error_log(
            '[LOVEMI FILTER USERS QUERY] '
            .
            $secondException->getMessage()
        );


        filterUsersResponse(
            false,
            'Unable to filter LOVEMI members.',
            [
                'code' =>
                    'FILTER_FAILED'
            ],
            500
        );

    }

}


/* =========================================================================
   RESULTS
========================================================================= */

$users = [];


foreach (
    $rows
    as $row
) {

    /*
    |--------------------------------------------------------------------------
    | Respect show_online_status.
    |--------------------------------------------------------------------------
    */

    $isOnline =
        (bool)
        $row['is_online'];


    if (
        (int)
        $row['show_online_status']
        !==
        1
    ) {

        $isOnline =
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

            $isOnline =
                true;

        }

    }


    /*
    |--------------------------------------------------------------------------
    | Approved primary photo
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

        'age' =>
            $row['age']
            !==
            null
                ?
                (int)
                $row['age']
                :
                null,

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
                $row['iso3'],

            'phone_code' =>
                $row['phone_code']

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
            $isOnline,

        'last_seen_at' =>
            (
                (int)
                $row['show_online_status']
                ===
                1
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

filterUsersResponse(
    true,
    'Users filtered successfully.',
    [

        'filters' => [

            'country_id' =>
                $countryId > 0
                    ?
                    $countryId
                    :
                    null,

            'country' =>
                $countrySearch !== ''
                    ?
                    $countrySearch
                    :
                    null,

            'gender' =>
                $gender !== ''
                    ?
                    $gender
                    :
                    null,

            'city' =>
                $city !== ''
                    ?
                    $city
                    :
                    null,

            'looking_for' =>
                $lookingFor !== ''
                    ?
                    $lookingFor
                    :
                    null,

            'relationship_status' =>
                $relationshipStatus !== ''
                    ?
                    $relationshipStatus
                    :
                    null,

            'min_age' =>
                $minAge > 0
                    ?
                    $minAge
                    :
                    null,

            'max_age' =>
                $maxAge > 0
                    ?
                    $maxAge
                    :
                    null,

            'online' =>
                $online === -1
                    ?
                    null
                    :
                    (bool)
                    $online

        ],

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