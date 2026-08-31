<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - CREATE BLOCK
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

ini_set(
    'display_errors',
    '0'
);


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
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
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
| RESPONSE
|--------------------------------------------------------------------------
*/

function blockedCreateResponse(
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
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

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

    blockedCreateResponse(
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

    blockedCreateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTH
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

    blockedCreateResponse(
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
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'blocks.manage'

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


    if (
        !$auth->fetch()
    ) {

        blockedCreateResponse(
            false,
            'You do not have permission to manage blocks.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    blockedCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
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
    !is_array($input)
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


$blockedUserId =
    (int)(
        $input['blocked_user_id']
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


/*
|--------------------------------------------------------------------------
| VALIDATION
|--------------------------------------------------------------------------
*/

if (
    $userId <= 0
    ||
    $blockedUserId <= 0
) {

    blockedCreateResponse(
        false,
        'Both users are required.',
        [],
        422
    );

}


if (
    $userId === $blockedUserId
) {

    blockedCreateResponse(
        false,
        'A user cannot block their own account.',
        [],
        422
    );

}


if (
    mb_strlen(
        $reason
    )
    >
    255
) {

    blockedCreateResponse(
        false,
        'The reason cannot exceed 255 characters.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| MAKE SURE USERS EXIST
|--------------------------------------------------------------------------
*/

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT
                id

            FROM users

            WHERE
                id IN (
                    :user_id,
                    :blocked_user_id
                )

                AND is_deleted = 0

            LIMIT 2
            "
        );


    $userStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':blocked_user_id' =>
                $blockedUserId

        ]
    );


    $foundUsers =
        $userStmt->fetchAll();


    if (
        count(
            $foundUsers
        )
        !==
        2
    ) {

        blockedCreateResponse(
            false,
            'One or both selected users do not exist or have been deleted.',
            [],
            404
        );

    }

} catch (
    Throwable $e
) {

    blockedCreateResponse(
        false,
        'Unable to verify the selected users.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| CREATE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
     * Prevent duplicate directional block records.
     */

    $existing =
        $pdo->prepare(
            "
            SELECT
                id

            FROM blocked_users

            WHERE

                user_id =
                    :user_id

                AND blocked_user_id =
                    :blocked_user_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $existing->execute(
        [

            ':user_id' =>
                $userId,

            ':blocked_user_id' =>
                $blockedUserId

        ]
    );


    $existingId =
        $existing->fetchColumn();


    if (
        $existingId
    ) {

        throw new RuntimeException(
            'This block relationship already exists.'
        );

    }


    $insert =
        $pdo->prepare(
            "
            INSERT INTO blocked_users
            (
                user_id,
                blocked_user_id,
                reason,
                created_at
            )
            VALUES
            (
                :user_id,
                :blocked_user_id,
                :reason,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insert->execute(
        [

            ':user_id' =>
                $userId,

            ':blocked_user_id' =>
                $blockedUserId,

            ':reason' =>
                $reason !== ''
                    ?
                    $reason
                    :
                    null

        ]
    );


    $blockId =
        (int)
        $pdo->lastInsertId();


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
                    'admin_create_block',
                    'blocked_user',
                    :entity_id,
                    NULL,
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
                    $blockId,

                ':new_values' =>
                    json_encode(
                        [

                            'user_id' =>
                                $userId,

                            'blocked_user_id' =>
                                $blockedUserId,

                            'reason' =>
                                $reason

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
            '[LOVEMI CREATE BLOCK AUDIT] '
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


    blockedCreateResponse(
        false,
        $e->getMessage(),
        [],
        409
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

blockedCreateResponse(
    true,
    'The block relationship was created successfully.',
    [

        'block_id' =>
            $blockId,

        'user_id' =>
            $userId,

        'blocked_user_id' =>
            $blockedUserId

    ]
);