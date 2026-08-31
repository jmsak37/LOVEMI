<?php
/**
 * ============================================================
 * LOVEMI - USER SETTINGS GET API
 * ============================================================
 *
 * GET:
 *
 *     /api/settings/get.php
 *
 * Returns:
 *
 *     - notification preferences
 *     - selected safe public system settings
 *
 * Never returns:
 *
 *     passwords
 *     ID-number data
 *     phone-number private data
 *     payment secrets
 *     SMTP credentials
 *     2FA secrets
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

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


/* ============================================================
   RESPONSE
============================================================ */

function settingsGetResponse(
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
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    settingsGetResponse(
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

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    settingsGetResponse(
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
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SETTINGS GET DB] '
        .
        $e->getMessage()
    );


    settingsGetResponse(
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
   VERIFY ACCOUNT
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                username,
                email,
                is_active,
                is_suspended,
                is_deleted,
                account_status

            FROM users

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SETTINGS USER] '
        .
        $e->getMessage()
    );


    settingsGetResponse(
        false,
        'Unable to load your account.',
        [
            'code' =>
                'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$user
) {

    settingsGetResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    settingsGetResponse(
        false,
        'Your account is no longer available.',
        [
            'code' =>
                'ACCOUNT_DELETED'
        ],
        403
    );
}


if (
    (int)
    $user['is_suspended']
    ===
    1
) {

    settingsGetResponse(
        false,
        'Your account is suspended.',
        [
            'code' =>
                'ACCOUNT_SUSPENDED'
        ],
        403
    );
}


if (
    (int)
    $user['is_active']
    !==
    1
) {

    settingsGetResponse(
        false,
        'Your account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );
}


/* ============================================================
   NOTIFICATION PREFERENCES
============================================================ */

$notificationDefaults = [

    'email_notifications' =>
        1,

    'sms_notifications' =>
        1,

    'push_notifications' =>
        1,

    'connection_notifications' =>
        1,

    'message_notifications' =>
        1,

    'premium_notifications' =>
        1,

    'system_notifications' =>
        1,

    'sound_enabled' =>
        1

];


try {

    $notificationStmt =
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
                sound_enabled,
                updated_at

            FROM notification_preferences

            WHERE user_id =
                :user_id

            LIMIT 1
            "
        );


    $notificationStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $notifications =
        $notificationStmt->fetch();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SETTINGS NOTIFICATION QUERY] '
        .
        $e->getMessage()
    );


    $notifications =
        false;

}


/*
 * A preference row is normally created by the users trigger.
 * This fallback creates it if an old account does not have one.
 */

if (
    !$notifications
) {

    try {

        $insertPreference =
            $pdo->prepare(
                "
                INSERT INTO notification_preferences
                (
                    user_id
                )
                VALUES
                (
                    :user_id
                )

                ON DUPLICATE KEY UPDATE
                    user_id = user_id
                "
            );


        $insertPreference->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $notifications =
            $notificationDefaults;

    } catch (
        Throwable $e
    ) {

        /*
         * Keep frontend functional with defaults.
         */

        $notifications =
            $notificationDefaults;

    }

}


/* ============================================================
   NORMALIZE NOTIFICATIONS
============================================================ */

$notificationSettings = [

    'email_notifications' =>
        isset(
            $notifications[
                'email_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'email_notifications'
            ]
            :
            1,

    'sms_notifications' =>
        isset(
            $notifications[
                'sms_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'sms_notifications'
            ]
            :
            1,

    'push_notifications' =>
        isset(
            $notifications[
                'push_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'push_notifications'
            ]
            :
            1,

    'connection_notifications' =>
        isset(
            $notifications[
                'connection_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'connection_notifications'
            ]
            :
            1,

    'message_notifications' =>
        isset(
            $notifications[
                'message_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'message_notifications'
            ]
            :
            1,

    'premium_notifications' =>
        isset(
            $notifications[
                'premium_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'premium_notifications'
            ]
            :
            1,

    'system_notifications' =>
        isset(
            $notifications[
                'system_notifications'
            ]
        )
            ?
            (int)
            $notifications[
                'system_notifications'
            ]
            :
            1,

    'sound_enabled' =>
        isset(
            $notifications[
                'sound_enabled'
            ]
        )
            ?
            (int)
            $notifications[
                'sound_enabled'
            ]
            :
            1,

    'updated_at' =>
        $notifications[
            'updated_at'
        ]
        ??
        null

];


/* ============================================================
   SAFE PUBLIC SYSTEM SETTINGS
============================================================ */

$publicSettingKeys = [

    'app_name',
    'base_currency',
    'kenya_currency',
    'premium_price_usd',
    'premium_duration_days',
    'minimum_age',
    'public_posts_enabled',
    'public_profiles_enabled',
    'default_profile_visibility',
    'require_email_verification',
    'require_phone_verification',
    'require_identity_verification',
    'notification_sound_enabled',
    'enable_registration',
    'maintenance_mode'

];


$systemSettings =
    [];


if (
    count(
        $publicSettingKeys
    )
    >
    0
) {

    /*
     * Build placeholders without interpolating user input.
     */

    $placeholders =
        implode(
            ',',
            array_fill(
                0,
                count(
                    $publicSettingKeys
                ),
                '?'
            )
        );


    try {

        $systemStmt =
            $pdo->prepare(
                "
                SELECT

                    setting_key,
                    setting_value,
                    value_type

                FROM system_settings

                WHERE is_public = 1

                  AND setting_key IN
                      (
                          {$placeholders}
                      )
                "
            );


        $systemStmt->execute(
            $publicSettingKeys
        );


        $systemRows =
            $systemStmt->fetchAll();


        foreach (
            $systemRows
            as $row
        ) {

            $key =
                (string)
                $row['setting_key'];


            $value =
                $row['setting_value'];


            $type =
                strtolower(
                    (string)
                    $row['value_type']
                );


            switch (
                $type
            ) {

                case 'integer':

                    $value =
                        (int)
                        $value;

                    break;


                case 'decimal':

                    $value =
                        (float)
                        $value;

                    break;


                case 'boolean':

                    $value =
                        (
                            (int)
                            $value
                        )
                        ===
                        1;

                    break;


                case 'json':

                    $decoded =
                        json_decode(
                            (string)
                            $value,
                            true
                        );


                    $value =
                        json_last_error()
                        ===
                        JSON_ERROR_NONE
                            ?
                            $decoded
                            :
                            $value;

                    break;


                default:

                    $value =
                        (string)
                        $value;

            }


            $systemSettings[
                $key
            ] =
                $value;

        }

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI SETTINGS SYSTEM QUERY] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   RESPONSE
============================================================ */

settingsGetResponse(
    true,
    'Settings loaded successfully.',
    [

        'account' => [

            'id' =>
                $userId,

            'username' =>
                $user['username'],

            'email' =>
                $user['email'],

            'account_status' =>
                $user['account_status']

        ],

        'notifications' =>
            $notificationSettings,

        'settings' => [

            'notifications' =>
                $notificationSettings,

            'system' =>
                $systemSettings

        ]

    ]
);