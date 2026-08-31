<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - USER ONLINE STATUS API
|--------------------------------------------------------------------------
|
| POST JSON examples:
|
| {
|     "status": "online"
| }
|
| {
|     "status": "offline"
| }
|
| {
|     "status": "heartbeat"
| }
|
| This API updates both:
|
|   users.last_seen_at
|   user_presence.is_online
|   user_presence.last_seen_at
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

function onlineStatusResponse(
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
    'POST'
) {

    onlineStatusResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* =========================================================================
   AUTHENTICATION
========================================================================= */

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

    onlineStatusResponse(
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


/* =========================================================================
   REQUEST BODY
========================================================================= */

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


$status =
    strtolower(
        trim(
            (string)
            (
                $input['status']
                ??
                $input['action']
                ??
                'heartbeat'
            )
        )
    );


/*
|--------------------------------------------------------------------------
| Support common aliases
|--------------------------------------------------------------------------
*/

if (
    $status ===
    'online'
) {

    $isOnline =
        1;

} elseif (
    $status ===
    'offline'
) {

    $isOnline =
        0;

} elseif (
    $status ===
    'heartbeat'
) {

    $isOnline =
        1;

} else {

    onlineStatusResponse(
        false,
        'Invalid online status.',
        [
            'code' =>
                'INVALID_STATUS',

            'allowed' =>
                [
                    'online',
                    'offline',
                    'heartbeat'
                ]
        ],
        422
    );

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
        '[LOVEMI ONLINE STATUS DB] '
        .
        $e->getMessage()
    );


    onlineStatusResponse(
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
   VERIFY USER
========================================================================= */

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
        '[LOVEMI ONLINE USER QUERY] '
        .
        $e->getMessage()
    );


    onlineStatusResponse(
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

    onlineStatusResponse(
        false,
        'Account not found.',
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

    onlineStatusResponse(
        false,
        'This account has been deleted.',
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

    onlineStatusResponse(
        false,
        'This account is suspended.',
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

    onlineStatusResponse(
        false,
        'This account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );

}


/* =========================================================================
   UPDATE DATABASE
========================================================================= */

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | Update user last_seen_at
    |--------------------------------------------------------------------------
    */

    $userUpdate =
        $pdo->prepare(
            "
            UPDATE users

            SET
                last_seen_at =
                    CURRENT_TIMESTAMP

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $userUpdate->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Ensure presence record exists.
    |--------------------------------------------------------------------------
    */

    $presenceInsert =
        $pdo->prepare(
            "
            INSERT INTO user_presence
            (
                user_id,
                is_online,
                last_seen_at
            )
            VALUES
            (
                :user_id,
                :is_online,
                CURRENT_TIMESTAMP
            )

            ON DUPLICATE KEY UPDATE

                is_online =
                    VALUES(is_online),

                last_seen_at =
                    VALUES(last_seen_at),

                is_typing =
                    CASE
                        WHEN VALUES(is_online) = 0
                        THEN 0
                        ELSE is_typing
                    END,

                typing_conversation_id =
                    CASE
                        WHEN VALUES(is_online) = 0
                        THEN NULL
                        ELSE typing_conversation_id
                    END
            "
        );


    $presenceInsert->execute(
        [
            ':user_id' =>
                $userId,

            ':is_online' =>
                $isOnline
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | When the user goes offline, clear typing state.
    |--------------------------------------------------------------------------
    */

    if (
        $isOnline ===
        0
    ) {

        $clearTyping =
            $pdo->prepare(
                "
                UPDATE user_presence

                SET

                    is_typing = 0,

                    typing_conversation_id = NULL

                WHERE user_id =
                    :user_id

                LIMIT 1
                "
            );


        $clearTyping->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );

    }


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI ONLINE STATUS UPDATE] '
        .
        $e->getMessage()
    );


    onlineStatusResponse(
        false,
        'Unable to update your online status.',
        [
            'code' =>
                'STATUS_UPDATE_FAILED'
        ],
        500
    );

}


/* =========================================================================
   RESPONSE
========================================================================= */

onlineStatusResponse(
    true,
    $isOnline === 1
        ? 'You are now online.'
        : 'You are now offline.',
    [

        'user_id' =>
            $userId,

        'is_online' =>
            (bool)
            $isOnline,

        'status' =>
            $isOnline === 1
                ? 'online'
                : 'offline',

        'last_seen_at' =>
            date(
                'Y-m-d H:i:s'
            )

    ]
);