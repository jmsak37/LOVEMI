<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function responseJson(
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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    responseJson(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );

}

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {

    responseJson(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'connections' => []
        ],
        401
    );

}

$status =
    strtolower(
        trim(
            (string)(
                $_GET['status']
                ??
                'accepted'
            )
        )
    );

$direction =
    strtolower(
        trim(
            (string)(
                $_GET['direction']
                ??
                ''
            )
        )
    );

$allowedStatuses = [
    'accepted',
    'connected',
    'pending',
    'rejected',
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
        'accepted';

}

$limit =
    max(
        1,
        min(
            100,
            (int)(
                $_GET['limit']
                ??
                50
            )
        )
    );

$offset =
    max(
        0,
        (int)(
            $_GET['offset']
            ??
            0
        )
    );

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST DB] '
        .
        $e->getMessage()
    );

    responseJson(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR',
            'connections' => []
        ],
        500
    );

}

$whereDirection = '';

if (
    $status === 'pending'
    &&
    $direction === 'received'
) {

    $whereDirection =
        "
        AND c.initiated_by <> :current_user_direction_received
        ";

} elseif (
    $status === 'pending'
    &&
    $direction === 'sent'
) {

    $whereDirection =
        "
        AND c.initiated_by = :current_user_direction_sent
        ";

}

$sql = "
    SELECT

        c.id AS connection_id,

        c.user_id,

        c.connected_user_id,

        c.initiated_by,

        c.status,

        c.connected_at,

        c.created_at,

        c.updated_at,

        CASE
            WHEN c.user_id = :current_user_case_1
                THEN c.connected_user_id
            ELSE c.user_id
        END AS other_user_id,

        CASE
            WHEN c.initiated_by = :current_user_direction_case
                THEN 'sent'
            ELSE 'received'
        END AS direction,

        u.username,

        u.full_names,

        u.gender,

        u.date_of_birth,

        u.email_verified,

        u.country_id,

        u.phone_number,

        u.phone_e164,

        co.name AS country_name,

        co.iso2 AS country_iso2,

        p.display_name,

        p.bio,

        p.city,

        p.relationship_status,

        p.looking_for,

        p.interests,

        p.allow_messages,

        p.show_online_status,

        (
            SELECT ph.file_path

            FROM photos ph

            WHERE ph.user_id =
                CASE
                    WHEN c.user_id = :current_user_case_2
                        THEN c.connected_user_id
                    ELSE c.user_id
                END

              AND ph.photo_type = 'profile'

              AND ph.approval_status = 'approved'

              AND ph.is_primary = 1

            ORDER BY
                ph.uploaded_at DESC,
                ph.id DESC

            LIMIT 1

        ) AS profile_photo_primary,

        (
            SELECT ph2.file_path

            FROM photos ph2

            WHERE ph2.user_id =
                CASE
                    WHEN c.user_id = :current_user_case_3
                        THEN c.connected_user_id
                    ELSE c.user_id
                END

              AND ph2.photo_type = 'profile'

              AND ph2.approval_status = 'approved'

            ORDER BY
                ph2.is_primary DESC,
                ph2.uploaded_at DESC,
                ph2.id DESC

            LIMIT 1

        ) AS profile_photo_fallback,

        CASE

            WHEN EXISTS
            (
                SELECT 1

                FROM user_presence up

                WHERE up.user_id =
                    CASE
                        WHEN c.user_id = :current_user_case_4
                            THEN c.connected_user_id
                        ELSE c.user_id
                    END

                  AND up.is_online = 1
            )

            THEN 1

            WHEN EXISTS
            (
                SELECT 1

                FROM user_sessions us

                WHERE us.user_id =
                    CASE
                        WHEN c.user_id = :current_user_case_5
                            THEN c.connected_user_id
                        ELSE c.user_id
                    END

                  AND us.revoked_at IS NULL

                  AND us.expires_at > CURRENT_TIMESTAMP

                  AND us.last_activity_at >=
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL 10 MINUTE
                      )
            )

            THEN 1

            ELSE 0

        END AS is_online

    FROM connections c

    INNER JOIN users u

        ON u.id =
            CASE

                WHEN c.user_id = :current_user_case_6

                    THEN c.connected_user_id

                ELSE c.user_id

            END

    LEFT JOIN countries co
        ON co.id = u.country_id

    LEFT JOIN profiles p
        ON p.user_id = u.id

    WHERE

        (
            c.user_id = :current_user_where_1

            OR

            c.connected_user_id = :current_user_where_2
        )

        AND c.status = :status

        AND u.is_active = 1

        AND u.is_suspended = 0

        AND u.is_deleted = 0

        $whereDirection

    ORDER BY

        c.updated_at DESC,

        c.id DESC

    LIMIT :limit

    OFFSET :offset
";

$countSql = "
    SELECT COUNT(*)

    FROM connections c

    INNER JOIN users u

        ON u.id =
            CASE

                WHEN c.user_id = :current_user_count_case

                    THEN c.connected_user_id

                ELSE c.user_id

            END

    WHERE

        (
            c.user_id = :current_user_count_where_1

            OR

            c.connected_user_id = :current_user_count_where_2
        )

        AND c.status = :status

        AND u.is_active = 1

        AND u.is_suspended = 0

        AND u.is_deleted = 0

        $whereDirection
";

try {

    $countStmt =
        $pdo->prepare(
            $countSql
        );

    $countStmt->bindValue(
        ':current_user_count_case',
        $currentUserId,
        PDO::PARAM_INT
    );

    $countStmt->bindValue(
        ':current_user_count_where_1',
        $currentUserId,
        PDO::PARAM_INT
    );

    $countStmt->bindValue(
        ':current_user_count_where_2',
        $currentUserId,
        PDO::PARAM_INT
    );

    $countStmt->bindValue(
        ':status',
        $status,
        PDO::PARAM_STR
    );

    if (
        $status === 'pending'
        &&
        $direction === 'received'
    ) {

        $countStmt->bindValue(
            ':current_user_direction_received',
            $currentUserId,
            PDO::PARAM_INT
        );

    } elseif (
        $status === 'pending'
        &&
        $direction === 'sent'
    ) {

        $countStmt->bindValue(
            ':current_user_direction_sent',
            $currentUserId,
            PDO::PARAM_INT
        );

    }

    $countStmt->execute();

    $count =
        (int)
        $countStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST COUNT] '
        .
        $e->getMessage()
    );

    responseJson(
        false,
        'Unable to count connections.',
        [
            'connections' => []
        ],
        500
    );

}

try {

    $stmt =
        $pdo->prepare(
            $sql
        );

    $stmt->bindValue(
        ':current_user_case_1',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_case_2',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_case_3',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_case_4',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_case_5',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_case_6',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_direction_case',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_where_1',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':current_user_where_2',
        $currentUserId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':status',
        $status,
        PDO::PARAM_STR
    );

    if (
        $status === 'pending'
        &&
        $direction === 'received'
    ) {

        $stmt->bindValue(
            ':current_user_direction_received',
            $currentUserId,
            PDO::PARAM_INT
        );

    } elseif (
        $status === 'pending'
        &&
        $direction === 'sent'
    ) {

        $stmt->bindValue(
            ':current_user_direction_sent',
            $currentUserId,
            PDO::PARAM_INT
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
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION LIST QUERY] '
        .
        $e->getMessage()
    );

    responseJson(
        false,
        'Connections could not be loaded.',
        [
            'code' => 'QUERY_ERROR',
            'connections' => []
        ],
        500
    );

}

$connections = [];

foreach (
    $rows as $row
) {

    $profilePhoto =
        !empty(
            $row['profile_photo_primary']
        )
            ?
            $row['profile_photo_primary']
            :
            (
                !empty(
                    $row['profile_photo_fallback']
                )
                    ?
                    $row['profile_photo_fallback']
                    :
                    null
            );

    $isIncoming =
        strtolower(
            (string)
            $row['direction']
        )
        ===
        'received';

    $isOutgoing =
        strtolower(
            (string)
            $row['direction']
        )
        ===
        'sent';

    $connections[] = [

        'connection_id' =>
            (int)
            $row['connection_id'],

        'user_id' =>
            (int)
            $row['other_user_id'],

        'username' =>
            (string)
            $row['username'],

        'full_name' =>
            (string)
            $row['full_names'],

        'gender' =>
            (string)
            $row['gender'],

        'date_of_birth' =>
            $row['date_of_birth'] !== null
                ?
                (string)
                $row['date_of_birth']
                :
                null,

        'email_verified' =>
            (bool)
            $row['email_verified'],

        'country_id' =>
            $row['country_id'] !== null
                ?
                (int)
                $row['country_id']
                :
                null,

        'country_name' =>
            $row['country_name'] !== null
                ?
                (string)
                $row['country_name']
                :
                null,

        'country_iso2' =>
            $row['country_iso2'] !== null
                ?
                strtoupper(
                    (string)
                    $row['country_iso2']
                )
                :
                null,

        'display_name' =>
            $row['display_name'] !== null
                ?
                (string)
                $row['display_name']
                :
                null,

        'bio' =>
            $row['bio'] !== null
                ?
                (string)
                $row['bio']
                :
                null,

        'city' =>
            $row['city'] !== null
                ?
                (string)
                $row['city']
                :
                null,

        'profile_photo' =>
            $profilePhoto,

        'photo_url' =>
            $profilePhoto,

        'avatar' =>
            $profilePhoto,

        'is_online' =>
            (bool)
            $row['is_online'],

        'status' =>
            (string)
            $row['status'],

        'direction' =>
            $isIncoming
                ?
                'received'
                :
                (
                    $isOutgoing
                        ?
                        'sent'
                        :
                        null
                ),

        'is_incoming' =>
            $isIncoming,

        'is_outgoing' =>
            $isOutgoing,

        'initiated_by' =>
            (int)
            $row['initiated_by'],

        'connected_at' =>
            $row['connected_at'] !== null
                ?
                (string)
                $row['connected_at']
                :
                null,

        'created_at' =>
            (string)
            $row['created_at'],

        'updated_at' =>
            (string)
            $row['updated_at']

    ];

}

responseJson(
    true,
    'Connections loaded successfully.',
    [

        'status' =>
            $status,

        'direction' =>
            $direction,

        'count' =>
            $count,

        'connections' =>
            $connections,

        'data' =>
            $connections

    ]
);