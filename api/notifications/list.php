<?php
declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI - NOTIFICATIONS LIST API
 * ============================================================
 */

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (
    session_status()
    !== PHP_SESSION_ACTIVE
) {
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
        JSON_UNESCAPED_UNICODE
        |
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
   AUTH
============================================================ */

$userId =
    (int) (
        $_SESSION[
            'lovemi_user_id'
        ]
        ?? 0
    );


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
    max(
        1,
        min(
            100,
            (int) (
                $_GET['limit']
                ?? 50
            )
        )
    );


$offset =
    max(
        0,
        (int) (
            $_GET['offset']
            ?? 0
        )
    );


$unreadOnly =
    in_array(
        strtolower(
            (string) (
                $_GET[
                    'unread_only'
                ]
                ?? ''
            )
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


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATIONS DB] '
        . $e->getMessage()
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
            $preferences as $key => $value
        ) {

            if (
                array_key_exists(
                    $key,
                    $pref
                )
            ) {

                $preferences[
                    $key
                ] =
                    (bool)
                    $pref[$key];

            }

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATION PREFERENCES] '
        . $e->getMessage()
    );

}


/* ============================================================
   WHERE
============================================================ */

$where =
    "
    n.user_id = :user_id
    ";


if (
    $unreadOnly
) {

    $where .=
        "
        AND n.is_read = 0
        ";

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
                ON nt.id = n.notification_type_id

            LEFT JOIN notification_audio na
                ON na.id = n.audio_id

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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATIONS QUERY] '
        . $e->getMessage()
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

        WHERE n.user_id = :user_id
        ";


    if (
        $unreadOnly
    ) {

        $countSql .=
            "
            AND n.is_read = 0
            ";

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

} catch (
    Throwable $e
) {

    $total =
        count(
            $rows
        );

}


/* ============================================================
   AUDIO URL
============================================================ */

function notificationAudioUrl(
    array $row,
    bool $soundAllowed
): ?string {

    if (
        !$soundAllowed
    ) {

        return null;

    }


    /*
     * Prefer the exact audio record assigned to the
     * notification.
     */
    $path =
        trim(
            (string) (
                $row[
                    'audio_path'
                ]
                ?? ''
            )
        );


    if (
        $path !== ''
        &&
        (
            (int) (
                $row[
                    'audio_active'
                ]
                ?? 1
            ) === 1
        )
    ) {

        /*
         * Only allow project-relative audio.
         */
        if (
            !preg_match(
                '#^https?://#i',
                $path
            )
            &&
            !str_starts_with(
                $path,
                '//'
            )
            &&
            !str_contains(
                $path,
                '../'
            )
            &&
            !str_contains(
                $path,
                '..\\'
            )
        ) {

            return ltrim(
                $path,
                '/'
            );

        }

    }


    /*
     * FALLBACK:
     *
     * When a notification does not have audio_id,
     * use notificationN.mp3 based on the notification type.
     *
     * LOVEMI currently has notification1.mp3 through
     * notification19.mp3.
     */
    $typeId =
        (int) (
            $row[
                'notification_type_id'
            ]
            ?? 0
        );


    if (
        $typeId >= 1
        &&
        $typeId <= 19
    ) {

        return
            'assets/audio/notification'
            . $typeId
            . '.mp3';

    }


    /*
     * Final fallback.
     */
    return
        'assets/audio/notification1.mp3';
}


/* ============================================================
   ACTION PATH
============================================================ */

function notificationActionPath(
    array $row
): string {

    $slug =
        strtolower(
            trim(
                (string) (
                    $row[
                        'notification_type_slug'
                    ]
                    ?? ''
                )
            )
        );


    $referenceType =
        strtolower(
            trim(
                (string) (
                    $row[
                        'reference_type'
                    ]
                    ?? ''
                )
            )
        );


    $referenceId =
        (int) (
            $row[
                'reference_id'
            ]
            ?? 0
        );


    if (
        $referenceType ===
        'conversation'
        && $referenceId > 0
    ) {

        return
            'messages.html?conversation_id='
            . rawurlencode(
                (string) $referenceId
            );

    }


    if (
        $slug ===
        'new_message'
    ) {

        return
            'messages.html';

    }


    if (
        in_array(
            $slug,
            [
                'new_connection',
                'connection_accepted'
            ],
            true
        )
        ||
        $referenceType ===
        'connection'
    ) {

        return
            'connections.html';

    }


    if (
        in_array(
            $slug,
            [
                'premium_activated',
                'premium_expiring',
                'premium_expired',
                'payment_successful',
                'payment_failed'
            ],
            true
        )
        ||
        in_array(
            $referenceType,
            [
                'payment',
                'subscription'
            ],
            true
        )
    ) {

        return
            'premium.html';

    }


    if (
        in_array(
            $slug,
            [
                'post_liked',
                'post_commented',
                'comment_reply',
                'followed_new_post'
            ],
            true
        )
        ||
        $referenceType ===
        'post'
    ) {

        if (
            $referenceId > 0
        ) {

            return
                'dashboard.html#post-'
                . rawurlencode(
                    (string) $referenceId
                );

        }


        return
            'dashboard.html';

    }


    if (
        $slug ===
        'photo_approved'
        ||
        $referenceType ===
        'photo'
    ) {

        return
            'photos.html';

    }


    if (
        $referenceType ===
        'profile'
    ) {

        return
            'profile.html';

    }


    $id =
        (int) (
            $row['id']
            ?? 0
        );


    return
        'notifications.html'
        . (
            $id > 0
                ? '#notification-' . $id
                : ''
        );
}


/* ============================================================
   ICON
============================================================ */

function notificationIcon(
    string $slug
): string {

    return match (
        strtolower(
            trim($slug)
        )
    ) {

        'new_connection',
        'connection_accepted'
            =>
            'fa-link',

        'new_message'
            =>
            'fa-message',

        'premium_activated'
            =>
            'fa-crown',

        'premium_expiring'
            =>
            'fa-clock',

        'premium_expired'
            =>
            'fa-triangle-exclamation',

        'payment_successful'
            =>
            'fa-circle-check',

        'payment_failed'
            =>
            'fa-circle-xmark',

        'post_approved',
        'account_approved'
            =>
            'fa-circle-check',

        'photo_approved'
            =>
            'fa-image',

        'post_liked'
            =>
            'fa-heart',

        'post_commented'
            =>
            'fa-comment',

        'comment_reply'
            =>
            'fa-reply',

        'followed_new_post'
            =>
            'fa-rss',

        default
            =>
            'fa-bell'

    };
}


/* ============================================================
   CATEGORY ENABLED
============================================================ */

function categoryEnabled(
    string $slug,
    array $preferences
): bool {

    $slug =
        strtolower(
            trim($slug)
        );


    if (
        in_array(
            $slug,
            [
                'new_connection',
                'connection_accepted'
            ],
            true
        )
    ) {

        return
            $preferences[
                'connection_notifications'
            ];

    }


    if (
        $slug ===
        'new_message'
    ) {

        return
            $preferences[
                'message_notifications'
            ];

    }


    if (
        in_array(
            $slug,
            [
                'premium_activated',
                'premium_expiring',
                'premium_expired',
                'payment_successful',
                'payment_failed'
            ],
            true
        )
    ) {

        return
            $preferences[
                'premium_notifications'
            ];

    }


    return
        $preferences[
            'system_notifications'
        ];
}


/* ============================================================
   FORMAT
============================================================ */

$notifications =
    [];


foreach (
    $rows as $row
) {

    $slug =
        strtolower(
            trim(
                (string) (
                    $row[
                        'notification_type_slug'
                    ]
                    ?? 'system'
                )
            )
        );


    $categoryEnabled =
        categoryEnabled(
            $slug,
            $preferences
        );


    $soundAllowed =
        $preferences[
            'sound_enabled'
        ]
        &&
        $categoryEnabled
        &&
        (
            (int) (
                $row[
                    'notification_type_sound_enabled'
                ]
                ?? 1
            )
            === 1
        );


    $audioUrl =
        notificationAudioUrl(
            $row,
            $soundAllowed
        );


    $actionPath =
        notificationActionPath(
            $row
        );


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
                $row[
                    'notification_type_id'
                ] !== null
                    ? (int)
                      $row[
                          'notification_type_id'
                      ]
                    : null,

            'name' =>
                $row[
                    'notification_type_name'
                ]
                ??
                'System Notification',

            'slug' =>
                $slug,

            'description' =>
                $row[
                    'notification_type_description'
                ]
                ??
                null

        ],

        'sender_id' =>
            $row[
                'sender_id'
            ] !== null
                ? (int)
                  $row[
                      'sender_id'
                  ]
                : null,

        'reference' => [

            'type' =>
                $row[
                    'reference_type'
                ],

            'id' =>
                $row[
                    'reference_id'
                ] !== null
                    ? (int)
                      $row[
                          'reference_id'
                      ]
                    : null

        ],

        'is_read' =>
            (bool)
            $row['is_read'],

        'read_at' =>
            $row['read_at'],

        'created_at' =>
            $row['created_at'],

        'action_url' =>
            $actionPath,

        'action_label' =>
            $slug === 'new_message'
                ? 'View message'
                : (
                    str_contains(
                        $slug,
                        'payment'
                    )
                        ? 'View payment'
                        : 'View notification'
                ),

        'icon' =>
            notificationIcon(
                $slug
            ),

        'audio' =>
            $audioUrl !== null
                ? [

                    'url' =>
                        $audioUrl,

                    'name' =>
                        $row[
                            'audio_name'
                        ]
                        ??
                        basename(
                            $audioUrl
                        ),

                    'file_name' =>
                        $row[
                            'audio_file_name'
                        ]
                        ??
                        basename(
                            $audioUrl
                        ),

                    'mime_type' =>
                        $row[
                            'audio_mime_type'
                        ]
                        ??
                        'audio/mpeg'

                ]
                : null

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

} catch (
    Throwable $e
) {

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

        'sound_enabled' =>
            $preferences[
                'sound_enabled'
            ],

        'email_enabled' =>
            $preferences[
                'email_notifications'
            ],

        'preferences' =>
            $preferences

    ]
);