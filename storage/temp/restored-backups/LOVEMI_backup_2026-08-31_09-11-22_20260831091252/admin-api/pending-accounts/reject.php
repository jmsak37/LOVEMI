<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - REJECT PENDING ACCOUNT
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


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


function pendingRejectResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        [
            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' =>
            0,

        'path' =>
            '/',

        'secure' =>
            $isHttps,

        'httponly' =>
            true,

        'samesite' =>
            'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    pendingRejectResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    pendingRejectResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| SESSION DATA
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    pendingRejectResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT
                u.id,
                u.username,
                u.full_names

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
                    'users.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    pendingRejectResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    pendingRejectResponse(
        false,
        'You do not have permission to reject accounts.',
        [],
        403
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
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


$userId =
    (int)(
        $input['user_id']
        ??
        0
    );


$reason =
    trim(
        (string)(
            $input['reason']
            ??
            ''
        )
    );


if (
    $userId <= 0
) {

    pendingRejectResponse(
        false,
        'A valid account ID is required.',
        [],
        422
    );

}


if (
    $reason === ''
) {

    pendingRejectResponse(
        false,
        'A rejection reason is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| LIMIT REASON LENGTH
|--------------------------------------------------------------------------
*/

if (
    mb_strlen(
        $reason
    )
    >
    1000
) {

    pendingRejectResponse(
        false,
        'The rejection reason is too long.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| TRANSACTION
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
     * Lock account.
     */

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email,

                account_status,

                is_deleted

            FROM users

            WHERE

                id =
                    :user_id

            LIMIT 1

            FOR UPDATE
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


    if (
        !$user
    ) {

        throw new RuntimeException(
            'The requested account was not found.'
        );

    }


    if (
        (bool)
        $user['is_deleted']
    ) {

        throw new RuntimeException(
            'This account has been deleted.'
        );

    }


    if (
        strtolower(
            (string)
            $user['account_status']
        )
        ===
        'approved'
    ) {

        throw new RuntimeException(
            'An approved account cannot be rejected from the pending queue.'
        );

    }


    $oldValues =
        [

            'account_status' =>
                $user['account_status']

        ];


    /*
     * Store a rejected state.
     *
     * The login API only accepts approved accounts, so a rejected
     * account remains unable to enter the normal application flow.
     */

    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                account_status =
                    'rejected',

                is_active =
                    0,

                is_suspended =
                    1

            WHERE

                id =
                    :user_id

                AND is_deleted =
                    0

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    if (
        $update->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The account could not be rejected.'
        );

    }


    /*
     * Audit.
     */

    try {

        $audit =
            $pdo->prepare(
                "
                INSERT INTO audit_logs
                (
                    user_id,
                    action,
                    entity_type,
                    entity_id,
                    old_values,
                    new_values,
                    ip_address,
                    user_agent
                )
                VALUES
                (
                    :user_id,
                    'admin_reject_account',
                    'user',
                    :entity_id,
                    :old_values,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute(
            [

                ':user_id' =>
                    $adminId,

                ':entity_id' =>
                    $userId,

                ':old_values' =>
                    json_encode(
                        $oldValues,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [

                            'account_status' =>
                                'rejected',

                            'is_active' =>
                                false,

                            'is_suspended' =>
                                true,

                            'reason' =>
                                $reason,

                            'rejected_by' =>
                                $adminId,

                            'rejected_at' =>
                                date(
                                    'Y-m-d H:i:s'
                                )

                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null

            ]
        );

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI PENDING REJECT AUDIT] '
            .
            $auditError->getMessage()
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


    pendingRejectResponse(
        false,
        $e->getMessage(),
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

pendingRejectResponse(
    true,
    'The account has been rejected successfully.',
    [

        'user_id' =>
            $userId,

        'account_status' =>
            'rejected',

        'rejected' =>
            true

    ]
);