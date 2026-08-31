<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - DELETE ACCOUNT API
|--------------------------------------------------------------------------
|
| POST JSON:
|
| {
|     "confirmation": "DELETE"
| }
|
| The account is soft-deleted rather than immediately destroying
| database relationships. This is safer for audit records,
| payments, reports, subscriptions and existing references.
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

function deleteAccountResponse(
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

    deleteAccountResponse(
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
   AUTH
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

    deleteAccountResponse(
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
   INPUT
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


$confirmation =
    strtoupper(
        trim(
            (string)
            (
                $input['confirmation']
                ??
                ''
            )
        )
    );


if (
    $confirmation !==
    'DELETE'
) {

    deleteAccountResponse(
        false,
        'Please confirm account deletion by entering DELETE.',
        [
            'code' =>
                'CONFIRMATION_REQUIRED'
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
        '[LOVEMI DELETE ACCOUNT DB] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
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
   LOAD ACCOUNT
========================================================================= */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                account_status,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DELETE ACCOUNT USER] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
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

    deleteAccountResponse(
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

    deleteAccountResponse(
        true,
        'This account has already been deleted.',
        [
            'already_deleted' =>
                true
        ]
    );

}


/* =========================================================================
   SOFT DELETE
========================================================================= */

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | Mark account deleted
    |--------------------------------------------------------------------------
    */

    $deleteStmt =
        $pdo->prepare(
            "
            UPDATE users

            SET

                account_status = 'deleted',

                is_active = 0,

                is_suspended = 0,

                is_deleted = 1,

                last_seen_at = NULL

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $deleteStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Hide profile
    |--------------------------------------------------------------------------
    */

    $profileStmt =
        $pdo->prepare(
            "
            UPDATE profiles

            SET

                profile_visibility = 'private',

                show_online_status = 0,

                allow_messages = 0

            WHERE user_id =
                :user_id
            "
        );


    $profileStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Force offline and clear typing
    |--------------------------------------------------------------------------
    */

    $presenceStmt =
        $pdo->prepare(
            "
            UPDATE user_presence

            SET

                is_online = 0,

                last_seen_at =
                    CURRENT_TIMESTAMP,

                is_typing = 0,

                typing_conversation_id = NULL

            WHERE user_id =
                :user_id
            "
        );


    $presenceStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Remove the user from future discovery by blocking
    | normal public profile visibility through the account flags.
    |--------------------------------------------------------------------------
    |
    | Existing connection/message/report/audit relationships are
    | preserved because the database has foreign keys depending
    | upon the user record.
    |--------------------------------------------------------------------------
    */


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
        '[LOVEMI DELETE ACCOUNT TRANSACTION] '
        .
        $e->getMessage()
    );


    deleteAccountResponse(
        false,
        'Unable to delete your account.',
        [
            'code' =>
                'DELETE_ACCOUNT_FAILED'
        ],
        500
    );

}


/* =========================================================================
   DESTROY SESSION
========================================================================= */

$_SESSION = [];


/*
|--------------------------------------------------------------------------
| Remove PHP session cookie
|--------------------------------------------------------------------------
*/

if (
    ini_get(
        'session.use_cookies'
    )
) {

    $params =
        session_get_cookie_params();


    setcookie(
        session_name(),
        '',
        time() - 42000,
        $params['path'],
        $params['domain'],
        $params['secure'],
        $params['httponly']
    );

}


session_destroy();


/* =========================================================================
   RESPONSE
========================================================================= */

deleteAccountResponse(
    true,
    'Your LOVEMI account has been deleted successfully.',
    [

        'deleted' =>
            true,

        'redirect' =>
            'index.html'

    ]
);