<?php
/**
 * ============================================================
 * LOVEMI - CONNECTIONS LIST API
 * ============================================================
 *
 * Returns connections belonging to the authenticated user.
 *
 * GET:
 *
 * ?status=accepted
 * ?status=pending
 *
 * Private contact information is not returned by this API.
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

function connectionsListResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
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

    connectionsListResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   SESSION
============================================================ */

if (
    session_status() !== PHP_SESSION_ACTIVE
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


if (
    $currentUserId <= 0
) {

    connectionsListResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html?return=connections.html'
        ],
        401
    );
}


/* ============================================================
   FILTER
============================================================ */

$status =
    strtolower(
        trim(
            (string)(
                $_GET['status']
                ?? 'accepted'
            )
        )
    );


if (
    !in_array(
        $status,
        [
            'accepted',
            'pending',
            'rejected',
            'cancelled'
        ],
        true
    )
) {

    $status =
        'accepted';

}


$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit']
                ?? 50
            )
        )
    );


$offset =
    max(
        0,
        (int)(
            $_GET['offset']
            ?? 0
        )
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST DB] '
        .
        $e->getMessage()
    );

    connectionsListResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR',
            'connections' => []
        ],
        500
    );
}


/* ============================================================
   QUERY
============================================================ */

/*
 * A connection can have either direction:
 *
 * current user = requester
 * OR
 * current user = receiver
 *
 * We then return the OTHER member.
 */

$sql = "

    SELECT

        c.id AS connection_id,

        c.requester_id,
        c.receiver_id,

        c.status,

        c.created_at,
        c.updated_at,

        CASE
            WHEN c.requester_id = :current_user_id_1
                THEN c.receiver_id
            ELSE c.requester_id
        END AS user_id,

        u.username,

        u.full_names,

        u.gender,

        u.email_verified,

        u.is_active,

        u.is_suspended,

        u.is_deleted,

        co.id AS country_id,

        co.name AS country_name,

        co.iso2 AS country_iso2,

        pr.profile_photo,

        CASE

            WHEN EXISTS
            (

                SELECT 1

                FROM user_sessions us

                WHERE us.user_id =

                    CASE
                        WHEN c.requester_id = :current_user_id_2
                            THEN c.receiver_id
                        ELSE c.requester_id
                    END

                  AND us.revoked_at IS NULL

                  AND us.two_factor_passed = TRUE

                  AND us.expires_at > CURRENT_TIMESTAMP

                  AND us.last_activity_at >=
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL 10 MINUTE
                      )

            )

            THEN TRUE

            ELSE FALSE

        END AS is_online

    FROM connections c

    INNER JOIN users u

        ON u.id =
            CASE

                WHEN c.requester_id = :current_user_id_3
                    THEN c.receiver_id

                ELSE c.requester_id

            END

    LEFT JOIN countries co
        ON co.id = u.country_id

    LEFT JOIN profiles pr
        ON pr.user_id = u.id

    WHERE

        (
            c.requester_id = :current_user_id_4

            OR

            c.receiver_id = :current_user_id_5
        )

        AND c.status = :status

        AND u.is_active = TRUE

        AND u.is_suspended = FALSE

        AND u.is_deleted = FALSE

    ORDER BY

        c.updated_at DESC,

        c.id DESC

    LIMIT :limit
    OFFSET :offset

";


/* ============================================================
   EXECUTE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            $sql
        );


    $stmt->bindValue(
        ':current_user_id_1',
        $currentUserId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':current_user_id_2',
        $currentUserId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':current_user_id_3',
        $currentUserId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':current_user_id_4',
        $currentUserId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':current_user_id_5',
        $currentUserId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':status',
        $status,
        PDO::PARAM_STR
    );


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


} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST QUERY] '
        .
        $e->getMessage()
    );


    connectionsListResponse(
        false,
        'Connections could not be loaded.',
        [
            'code' =>
                'QUERY_ERROR',

            'connections' =>
                []
        ],
        500
    );
}


/* ============================================================
   CLEAN DATA
============================================================ */

$connections = [];


foreach (
    $rows as $row
) {

    $connections[] = [

        'connection_id' =>
            (int)
            $row['connection_id'],

        'user_id' =>
            (int)
            $row['user_id'],

        'username' =>
            (string)
            $row['username'],

        'full_name' =>
            (string)
            $row['full_names'],

        'gender' =>
            (string)
            $row['gender'],

        'email_verified' =>
            (bool)
            $row['email_verified'],

        'country_id' =>
            $row['country_id'] !== null
                ? (int)
                  $row['country_id']
                : null,

        'country_name' =>
            $row['country_name'] !== null
                ? (string)
                  $row['country_name']
                : null,

        'country_iso2' =>
            $row['country_iso2'] !== null
                ? strtoupper(
                    (string)
                    $row['country_iso2']
                )
                : null,

        'profile_photo' =>
            $row['profile_photo'] !== null
                ? (string)
                  $row['profile_photo']
                : null,

        'photo_url' =>
            $row['profile_photo'] !== null
                ? (string)
                  $row['profile_photo']
                : null,

        'is_online' =>
            (bool)
            $row['is_online'],

        'status' =>
            (string)
            $row['status'],

        'created_at' =>
            (string)
            $row['created_at'],

        'updated_at' =>
            (string)
            $row['updated_at']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

connectionsListResponse(
    true,
    'Connections loaded successfully.',
    [
        'status' =>
            $status,

        'count' =>
            count(
                $connections
            ),

        'connections' =>
            $connections,

        'data' =>
            $connections
    ]
);