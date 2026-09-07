<?php

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
    session_status()
    !==
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
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
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

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
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)$raw,
        true
    );


if (!is_array($input)) {
    $input = $_POST;
}


/* ============================================================
   ALLOWED FIELDS
============================================================ */

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


$updates = [];


$params = [

    ':user_id' =>
        $userId

];


foreach (
    $allowedFields
    as $field
) {

    if (
        !array_key_exists(
            $field,
            $input
        )
    ) {

        continue;

    }


    $value =
        $input[
            $field
        ];


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

        $value =
            strtolower(
                trim(
                    $value
                )
            );


        if (
            in_array(
                $value,
                [
                    'true',
                    'yes',
                    'on'
                ],
                true
            )
        ) {

            $value = 1;

        } elseif (
            in_array(
                $value,
                [
                    'false',
                    'no',
                    'off'
                ],
                true
            )
        ) {

            $value = 0;

        }

    }


    if (
        !in_array(
            (int)$value,
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
        (int)$value;

}


/* ============================================================
   NOTHING TO UPDATE
============================================================ */

if (!$updates) {

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

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SETTINGS UPDATE DB] '
        . $e->getMessage()
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
   VERIFY USER
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            '
            SELECT
                id,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :user_id

            LIMIT 1
            '
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

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


if (!$user) {

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
    (int)$user['is_deleted'] === 1
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
    (int)$user['is_suspended'] === 1
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
    (int)$user['is_active'] !== 1
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
   SAVE
============================================================ */

try {

    $ensureStmt =
        $pdo->prepare(
            '
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
            '
        );


    $ensureStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $setClause =
        implode(
            ",\n",
            $updates
        );


    $stmt =
        $pdo->prepare(
            "
            UPDATE notification_preferences

            SET
                {$setClause}

            WHERE user_id = :user_id

            LIMIT 1
            "
        );


    $stmt->execute(
        $params
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI SETTINGS UPDATE QUERY] '
        . $e->getMessage()
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
   READ BACK
============================================================ */

try {

    $readStmt =
        $pdo->prepare(
            '
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

            WHERE user_id = :user_id

            LIMIT 1
            '
        );


    $readStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $saved =
        $readStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    $saved = null;

}


settingsUpdateResponse(
    true,
    'Your settings have been saved successfully.',
    [

        'notifications' =>
            $saved
                ? [

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
                : null

    ]
);