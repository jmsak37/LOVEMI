<?php
/**
 * ============================================================
 * LOVEMI - GET USER API
 * ============================================================
 *
 * Returns safe account information.
 *
 * Default:
 *   Returns the currently authenticated user.
 *
 * Optional:
 *   ?user_id=123
 *
 * Important:
 *   Private security credentials and identity fields are never
 *   returned by this endpoint.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function getUserResponse(
    bool $success,
    string $message,
    array $data = [],
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    getUserResponse(
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
   AUTHENTICATION
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    getUserResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
        ],
        401
    );

}


/* ============================================================
   TARGET USER
============================================================ */

$requestedId =
    isset(
        $_GET['user_id']
    )
        ?
        (int)
        $_GET['user_id']
        :
        0;


$targetUserId =
    $requestedId > 0
        ?
        $requestedId
        :
        $currentUserId;


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET USER DB] '
        .
        $e->getMessage()
    );


    getUserResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   USER QUERY
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.role_id,

                u.username,
                u.full_names,
                u.gender,

                u.email,

                u.country_id,

                u.date_of_birth,

                u.two_factor_enabled,

                u.two_factor_verified_at,

                u.account_status,

                u.email_verified,
                u.phone_verified,
                u.identity_verified,
                u.age_verified,

                u.is_active,
                u.is_suspended,
                u.is_deleted,

                u.last_login_at,
                u.last_seen_at,

                u.created_at,
                u.updated_at,

                c.name AS country_name,
                c.iso2 AS country_iso2,
                c.iso3 AS country_iso3,
                c.phone_code AS country_phone_code,
                c.flag_code AS country_flag_code

            FROM users u

            LEFT JOIN countries c
                ON c.id =
                   u.country_id

            WHERE u.id = :user_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $targetUserId
        ]
    );


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET USER QUERY] '
        .
        $e->getMessage()
    );


    getUserResponse(
        false,
        'Unable to load the user account.',
        [
            'code' =>
                'USER_QUERY_FAILED'
        ],
        500
    );

}


/* ============================================================
   NOT FOUND
============================================================ */

if (
    !$user
) {

    getUserResponse(
        false,
        'User account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   DELETED USER
============================================================ */

if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    getUserResponse(
        false,
        'This account is no longer available.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        404
    );

}


/* ============================================================
   ONLINE STATUS
============================================================ */

$isOnline =
    false;


if (
    !empty(
        $user['last_seen_at']
    )
) {

    $lastSeen =
        strtotime(
            (string)
            $user['last_seen_at']
        );


    if (
        $lastSeen !== false
        &&
        (
            time()
            -
            $lastSeen
        )
        <=
        300
    ) {

        $isOnline =
            true;

    }

}


/* ============================================================
   SAFE RESPONSE
============================================================ */

/*
 * No ID number.
 * No password.
 * No encrypted identity data.
 * No phone number.
 * No secret 2FA key.
 */

getUserResponse(
    true,
    'User loaded successfully.',
    [

        'user' => [

            'id' =>
                (int)
                $user['id'],

            'role_id' =>
                (int)
                $user['role_id'],

            'username' =>
                $user['username'],

            'full_names' =>
                $user['full_names'],

            'gender' =>
                $user['gender'],

            'email' =>
                (
                    $targetUserId
                    ===
                    $currentUserId
                )
                    ?
                    $user['email']
                    :
                    null,

            'country' => [

                'id' =>
                    $user['country_id'] !== null
                        ?
                        (int)
                        $user['country_id']
                        :
                        null,

                'name' =>
                    $user['country_name'],

                'iso2' =>
                    $user['country_iso2'],

                'iso3' =>
                    $user['country_iso3'],

                'phone_code' =>
                    $user['country_phone_code'],

                'flag_code' =>
                    $user['country_flag_code']

            ],

            'date_of_birth' =>
                (
                    $targetUserId
                    ===
                    $currentUserId
                )
                    ?
                    $user['date_of_birth']
                    :
                    null,

            'verification' => [

                'email_verified' =>
                    (bool)
                    $user['email_verified'],

                'phone_verified' =>
                    (
                        $targetUserId
                        ===
                        $currentUserId
                    )
                        ?
                        (bool)
                        $user['phone_verified']
                        :
                        null,

                'identity_verified' =>
                    (
                        $targetUserId
                        ===
                        $currentUserId
                    )
                        ?
                        (bool)
                        $user['identity_verified']
                        :
                        null,

                'age_verified' =>
                    (
                        $targetUserId
                        ===
                        $currentUserId
                    )
                        ?
                        (bool)
                        $user['age_verified']
                        :
                        null

            ],

            'two_factor' => [

                'enabled' =>
                    (
                        $targetUserId
                        ===
                        $currentUserId
                    )
                        ?
                        (bool)
                        $user['two_factor_enabled']
                        :
                        null,

                'verified_at' =>
                    (
                        $targetUserId
                        ===
                        $currentUserId
                    )
                        ?
                        $user['two_factor_verified_at']
                        :
                        null

            ],

            'account_status' =>
                $user['account_status'],

            'active' =>
                (bool)
                $user['is_active'],

            'suspended' =>
                (bool)
                $user['is_suspended'],

            'online' =>
                $isOnline,

            'last_seen_at' =>
                $user['last_seen_at'],

            'created_at' =>
                $user['created_at'],

            'updated_at' =>
                $user['updated_at']

        ]

    ]
);