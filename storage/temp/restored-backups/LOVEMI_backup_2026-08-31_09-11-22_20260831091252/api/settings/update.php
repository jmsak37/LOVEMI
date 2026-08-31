<?php
/**
 * ============================================================
 * LOVEMI - USER SETTINGS UPDATE API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *     "email_notifications": 1,
 *     "sms_notifications": 0,
 *     "push_notifications": 1,
 *     "connection_notifications": 1,
 *     "message_notifications": 1,
 *     "premium_notifications": 1,
 *     "system_notifications": 1,
 *     "sound_enabled": 1
 * }
 *
 * Any omitted setting is left unchanged.
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

function settingsUpdateResponse(
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
    'POST'
) {

    settingsUpdateResponse(
        false,
        'Only POST requests are allowed.',
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

    settingsUpdateResponse(
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
   REQUEST BODY
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $raw,
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$allowedFields = [

    'email_notifications',
    'sms_notifications',
    'push_notifications',
    'connection_notifications',
    'message_notifications',
    'premium_notifications',
    'system_notifications',
    'sound_enabled'

];


$updates =
    [];


$params =
    [
        ':user_id' =>
            $userId
    ];


foreach (
    $allowedFields
    as $field
) {

    if (
        array_key_exists(
            $field,
            $input
        )
    ) {

        $value =
            $input[
                $field
            ];


        /*
         * Convert accepted boolean-like values to 0/1.
         */

        if (
            is_bool(
                $value
            )
        ) {

            $value =
                $value
                    ? 1
                    : 0;

        } elseif (
            is_string(
                $value
            )
        ) {

            $lower =
                strtolower(
                    trim(
                        $value
                    )
                );


            if (
                in_array(
                    $lower,
                    [
                        'true',
                        'yes',
                        'on'
                    ],
                    true
                )
            ) {

                $value =
                    1;

            } elseif (
                in_array(
                    $lower,
                    [
                        'false',
                        'no',
                        'off'
                    ],
                    true
                )
            ) {

                $value =
                    0;

            }

        }


        if (
            !in_array(
                (int)
                $value,
                [
                    0,
                    1
                ],
                true
            )
        ) {

            settingsUpdateResponse(
                false,
                "Invalid value for {$field}. Use 0 or 1.",
                [
                    'code' =>
                        'INVALID_SETTING_VALUE',

                    'field' =>
                        $field
                ],
                422
            );
        }


        $updates[] =
            "{$field} = :{$field}";


        $params[
            ":{$field}"
        ] =
            (int)
            $value;

    }

}


/* ============================================================
   NOTHING TO UPDATE
============================================================ */

if (
    count(
        $updates
    )
    ===
    0
) {

    settingsUpdateResponse(
        false,
        'No settings were supplied for update.',
        [
            'code' =>
                'NO_SETTINGS'
        ],
        422
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
        '[LOVEMI SETTINGS UPDATE DB] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
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
                is_active,
                is_suspended,
                is_deleted

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
        '[LOVEMI SETTINGS UPDATE USER] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
        false,
        'Unable to verify your account.',
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

    settingsUpdateResponse(
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

    settingsUpdateResponse(
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

    settingsUpdateResponse(
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

    settingsUpdateResponse(
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
   BUILD UPDATE QUERY
============================================================ */

$setClause =
    implode(
        ",\n",
        $updates
    );


$sql =
    "
        UPDATE notification_preferences

        SET

            {$setClause}

        WHERE user_id =
            :user_id

        LIMIT 1
    ";


/* ============================================================
   UPDATE
============================================================ */

try {

    /*
     * Ensure a row exists for old accounts before updating.
     */

    $ensureStmt =
        $pdo->prepare(
            "
            INSERT INTO notification_preferences
            (
                user_id
            )
            VALUES
            (
                :ensure_user_id
            )

            ON DUPLICATE KEY UPDATE
                user_id = user_id
            "
        );


    $ensureStmt->execute(
        [
            ':ensure_user_id' =>
                $userId
        ]
    );


    $stmt =
        $pdo->prepare(
            $sql
        );


    $stmt->execute(
        $params
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SETTINGS UPDATE QUERY] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
        false,
        'Unable to save your settings.',
        [
            'code' =>
                'SETTINGS_UPDATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   READ BACK SAVED VALUES
============================================================ */

try {

    $readStmt =
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


    $readStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $saved =
        $readStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SETTINGS READBACK] '
        .
        $e->getMessage()
    );


    $saved =
        null;

}


/* ============================================================
   RESPONSE
============================================================ */

settingsUpdateResponse(
    true,
    'Your settings have been saved successfully.',
    [

        'notifications' =>
            $saved
                ?

                [

                    'email_notifications' =>
                        (int)
                        $saved[
                            'email_notifications'
                        ],

                    'sms_notifications' =>
                        (int)
                        $saved[
                            'sms_notifications'
                        ],

                    'push_notifications' =>
                        (int)
                        $saved[
                            'push_notifications'
                        ],

                    'connection_notifications' =>
                        (int)
                        $saved[
                            'connection_notifications'
                        ],

                    'message_notifications' =>
                        (int)
                        $saved[
                            'message_notifications'
                        ],

                    'premium_notifications' =>
                        (int)
                        $saved[
                            'premium_notifications'
                        ],

                    'system_notifications' =>
                        (int)
                        $saved[
                            'system_notifications'
                        ],

                    'sound_enabled' =>
                        (int)
                        $saved[
                            'sound_enabled'
                        ],

                    'updated_at' =>
                        $saved[
                            'updated_at'
                        ]

                ]

                :

                null

    ]
);