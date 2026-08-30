<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET BLOCKED USER RECORD
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

function blockedGetResponse(
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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    blockedGetResponse(
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

    blockedGetResponse(
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

        blockedGetResponse(
            false,
            'You do not have permission to manage blocked users.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    blockedGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| USER SEARCH MODE
|--------------------------------------------------------------------------
|
| Used by the Add Block form.
|
*/

$userSearch =
    trim(
        (string)(
            $_GET['search_users']
            ??
            ''
        )
    );


if (
    $userSearch !== ''
) {

    if (
        mb_strlen(
            $userSearch
        )
        <
        2
    ) {

        blockedGetResponse(
            true,
            'Enter at least two characters.',
            [
                'users' =>
                    []
            ]
        );

    }


    try {

        $like =
            '%'
            .
            $userSearch
            .
            '%';


        $userStmt =
            $pdo->prepare(
                "
                SELECT

                    u.id,

                    u.username,

                    u.full_names,

                    (
                        SELECT
                            p.file_path

                        FROM photos p

                        WHERE

                            p.user_id =
                                u.id

                            AND p.photo_type =
                                'profile'

                            AND p.is_primary =
                                1

                            AND p.approval_status =
                                'approved'

                        ORDER BY p.id DESC

                        LIMIT 1

                    ) AS avatar

                FROM users u

                WHERE

                    u.is_deleted = 0

                    AND
                    (
                        u.username LIKE :username

                        OR u.full_names LIKE :full_names

                        OR u.email LIKE :email
                    )

                ORDER BY
                    u.full_names ASC

                LIMIT 20
                "
            );


        $userStmt->execute(
            [

                ':username' =>
                    $like,

                ':full_names' =>
                    $like,

                ':email' =>
                    $like

            ]
        );


        blockedGetResponse(
            true,
            'Users found.',
            [
                'users' =>
                    $userStmt->fetchAll()
            ]
        );

    } catch (
        Throwable $e
    ) {

        blockedGetResponse(
            false,
            'Unable to search users.',
            [],
            500
        );

    }

}


/*
|--------------------------------------------------------------------------
| RECORD ID
|--------------------------------------------------------------------------
*/

$blockId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $blockId <= 0
) {

    blockedGetResponse(
        false,
        'A valid block record ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| RECORD
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                bu.id,

                bu.user_id,

                bu.blocked_user_id,

                bu.reason,

                bu.created_at,

                blocker.username
                    AS blocker_username,

                blocker.full_names
                    AS blocker_full_names,

                blocker.email
                    AS blocker_email,

                blocker.gender
                    AS blocker_gender,

                blocked.username
                    AS blocked_username,

                blocked.full_names
                    AS blocked_full_names,

                blocked.email
                    AS blocked_email,

                blocked.gender
                    AS blocked_gender,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            blocker.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY p.id DESC

                    LIMIT 1

                ) AS blocker_avatar,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            blocked.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY p.id DESC

                    LIMIT 1

                ) AS blocked_avatar

            FROM blocked_users bu

            INNER JOIN users blocker
                ON blocker.id =
                    bu.user_id

            INNER JOIN users blocked
                ON blocked.id =
                    bu.blocked_user_id

            WHERE
                bu.id = :block_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':block_id' =>
                $blockId
        ]
    );


    $block =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    blockedGetResponse(
        false,
        'Unable to load the block record.',
        [],
        500
    );

}


if (
    !$block
) {

    blockedGetResponse(
        false,
        'Block record not found.',
        [],
        404
    );

}


blockedGetResponse(
    true,
    'Block record loaded successfully.',
    [
        'block' =>
            $block
    ]
);