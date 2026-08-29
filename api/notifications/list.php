<?php
/**
 * ============================================================
 * LOVEMI - NOTIFICATIONS LIST API
 * ============================================================
 *
 * Returns notifications belonging ONLY to the authenticated
 * user.
 *
 * Optional query parameters:
 *
 *   ?limit=20
 *   ?offset=0
 *   ?unread_only=1
 *
 * Audio comes from notification_audio in the database.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function notificationsResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    notificationsResponse(
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
   USER
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    notificationsResponse(
        false,
        'Please log in to view notifications.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=notifications.html'
        ],
        401
    );
}


/* ============================================================
   PAGINATION
============================================================ */

$limit =
    isset($_GET['limit'])
        ? (int)
          $_GET['limit']
        : 20;


$offset =
    isset($_GET['offset'])
        ? (int)
          $_GET['offset']
        : 0;


$limit =
    max(
        1,
        min(
            100,
            $limit
        )
    );


$offset =
    max(
        0,
        $offset
    );


$unreadOnly =
    isset(
        $_GET['unread_only']
    )
    &&
    in_array(
        strtolower(
            (string)
            $_GET['unread_only']
        ),
        [
            '1',
            'true',
            'yes'
        ],
        true
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI NOTIFICATIONS DB] '
        .
        $e->getMessage()
    );


    notificationsResponse(
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
   USER PREFERENCES
============================================================ */

$preferences = [

    'email_notifications' =>
        true,

    'sms_notifications' =>
        true,

    'push_notifications' =>
        true,

    'connection_notifications' =>
        true,

    'message_notifications' =>
        true,

    'premium_notifications' =>
        true,

    'system_notifications' =>
        true,

    'sound_enabled' =>
        true

];


try {

    $prefStmt =
        $pdo->prepare(
            "
            SELECT

                email_notifications,
                sms_notifications,
                push_notifications,
                connection_notifications,
                message_notifications,
                premium_notifications,
                system_notifications,
                sound_enabled

            FROM notification_preferences

            WHERE user_id = :user_id

            LIMIT 1
            "
        );


    $prefStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $pref =
        $prefStmt->fetch();


    if (
        $pref
    ) {

        foreach (
            $preferences
            as $key => $defaultValue
        ) {

            if (
                array_key_exists(
                    $key,
                    $pref
                )
            ) {

                $preferences[$key] =
                    (bool)
                    $pref[$key];

            }

        }

    }

} catch (Throwable $e) {

    /*
     * Defaults remain enabled if a preferences row does not
     * yet exist.
     */

    error_log(
        '[LOVEMI NOTIFICATION PREFERENCES] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   WHERE
============================================================ */

$where =
    'n.user_id = :user_id';


if (
    $unreadOnly
) {

    $where .=
        ' AND n.is_read = 0';

}


/* ============================================================
   QUERY
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                n.id,
                n.user_id,
                n.notification_type_id,
                n.sender_id,

                n.title,
                n.message,

                n.reference_type,
                n.reference_id,

                n.audio_id,

                n.is_read,
                n.read_at,
                n.created_at,

                nt.name AS notification_type_name,
                nt.slug AS notification_type_slug,
                nt.description AS notification_type_description,
                nt.sound_enabled AS notification_type_sound_enabled,

                na.name AS audio_name,
                na.file_name AS audio_file_name,
                na.file_path AS audio_path,
                na.mime_type AS audio_mime_type,
                na.is_active AS audio_active

            FROM notifications n

            LEFT JOIN notification_types nt
                ON nt.id =
                   n.notification_type_id

            LEFT JOIN notification_audio na
                ON na.id =
                   n.audio_id

            WHERE {$where}

            ORDER BY
                n.created_at DESC,
                n.id DESC

            LIMIT {$limit}

            OFFSET {$offset}
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $rows =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI NOTIFICATIONS QUERY] '
        .
        $e->getMessage()
    );


    notificationsResponse(
        false,
        'Unable to load your notifications.',
        [
            'code' =>
                'NOTIFICATION_QUERY_ERROR'
        ],
        500
    );
}


/* ============================================================
   TOTAL
============================================================ */

try {

    $countSql =
        "
        SELECT COUNT(*)

        FROM notifications n

        WHERE
            n.user_id = :user_id
        ";


    if (
        $unreadOnly
    ) {

        $countSql .=
            " AND n.is_read = 0";

    }


    $countStmt =
        $pdo->prepare(
            $countSql
        );


    $countStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $total =
        (int)
        $countStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI NOTIFICATIONS COUNT] '
        .
        $e->getMessage()
    );


    $total =
        count(
            $rows
        );

}


/* ============================================================
   FORMAT NOTIFICATIONS
============================================================ */

$notifications =
    [];


foreach (
    $rows
    as $row
) {

    $typeSlug =
        strtolower(
            trim(
                (string)
                (
                    $row['notification_type_slug']
                    ??
                    'system'
                )
            )
        );


    /*
     * Determine whether this category is enabled.
     */

    $categoryEnabled =
        match (
            true
        ) {

            in_array(
                $typeSlug,
                [
                    'new_connection'
                ],
                true
            )
                =>
                $preferences[
                    'connection_notifications'
                ],

            in_array(
                $typeSlug,
                [
                    'new_message'
                ],
                true
            )
                =>
                $preferences[
                    'message_notifications'
                ],

            in_array(
                $typeSlug,
                [
                    'premium_activated',
                    'premium_expiring',
                    'premium_expired'
                ],
                true
            )
                =>
                $preferences[
                    'premium_notifications'
                ],

            default
                =>
                $preferences[
                    'system_notifications'
                ]

        };


    /*
     * The notification record itself remains visible to the user,
     * but audio is only returned when both preference switches
     * allow it.
     */

    $soundAllowed =
        $preferences['sound_enabled']
        &&
        $categoryEnabled
        &&
        (
            !isset(
                $row['notification_type_sound_enabled']
            )
            ||
            (bool)
            $row[
                'notification_type_sound_enabled'
            ]
        )
        &&
        (
            !isset(
                $row['audio_active']
            )
            ||
            (bool)
            $row['audio_active']
        );


    $audio =
        null;


    if (
        $soundAllowed
        &&
        !empty(
            $row['audio_path']
        )
    ) {

        $audio = [

            'id' =>
                $row['audio_id'] !== null
                    ?
                    (int)
                    $row['audio_id']
                    :
                    null,

            'name' =>
                $row['audio_name'],

            'file_name' =>
                $row['audio_file_name'],

            'path' =>
                $row['audio_path'],

            'mime_type' =>
                $row['audio_mime_type']
                ??
                'audio/mpeg'

        ];

    }


    $notifications[] = [

        'id' =>
            (int)
            $row['id'],

        'title' =>
            (string)
            $row['title'],

        'message' =>
            (string)
            $row['message'],

        'notification_type' => [

            'id' =>
                $row['notification_type_id'] !== null
                    ?
                    (int)
                    $row['notification_type_id']
                    :
                    null,

            'name' =>
                $row['notification_type_name']
                ??
                'System Notification',

            'slug' =>
                $typeSlug,

            'description' =>
                $row['notification_type_description']

        ],

        'sender_id' =>
            $row['sender_id'] !== null
                ?
                (int)
                $row['sender_id']
                :
                null,

        'reference' => [

            'type' =>
                $row['reference_type'],

            'id' =>
                $row['reference_id'] !== null
                    ?
                    (int)
                    $row['reference_id']
                    :
                    null

        ],

        'is_read' =>
            (bool)
            $row['is_read'],

        'read_at' =>
            $row['read_at'],

        'created_at' =>
            $row['created_at'],

        'audio' =>
            $audio

    ];

}


/* ============================================================
   UNREAD COUNT
============================================================ */

try {

    $unreadStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM notifications

            WHERE user_id = :user_id

              AND is_read = 0
            "
        );


    $unreadStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $unreadCount =
        (int)
        $unreadStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UNREAD COUNT] '
        .
        $e->getMessage()
    );


    $unreadCount =
        0;

}


/* ============================================================
   RESPONSE
============================================================ */

notificationsResponse(
    true,
    'Notifications loaded successfully.',
    [

        'notifications' =>
            $notifications,

        'pagination' => [

            'total' =>
                $total,

            'limit' =>
                $limit,

            'offset' =>
                $offset,

            'has_more' =>
                (
                    $offset
                    +
                    count(
                        $notifications
                    )
                )
                <
                $total

        ],

        'unread_count' =>
            $unreadCount,

        'preferences' =>
            $preferences

    ]
);