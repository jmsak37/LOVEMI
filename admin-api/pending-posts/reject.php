<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - REJECT POST
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


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function pendingPostRejectResponse(
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
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    pendingPostRejectResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    pendingPostRejectResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN
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

    pendingPostRejectResponse(
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
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

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
                    'posts.manage'

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

        pendingPostRejectResponse(
            false,
            'You do not have permission to reject posts.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingPostRejectResponse(
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
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$postId =
    (int)(
        $input['post_id']
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
    $postId <= 0
) {

    pendingPostRejectResponse(
        false,
        'A valid post ID is required.',
        [],
        422
    );

}


if (
    $reason === ''
) {

    pendingPostRejectResponse(
        false,
        'A rejection reason is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $reason
    )
    >
    1000
) {

    pendingPostRejectResponse(
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
     * Lock post.
     */

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                content,

                approval_status,

                visibility,

                is_featured,

                deleted_at

            FROM posts

            WHERE
                id =
                    :post_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $stmt->fetch();


    if (
        !$post
    ) {

        throw new RuntimeException(
            'The requested post was not found.'
        );

    }


    if (
        !empty(
            $post['deleted_at']
        )
    ) {

        throw new RuntimeException(
            'This post has already been deleted.'
        );

    }


    if (
        strtolower(
            (string)
            $post['approval_status']
        )
        !==
        'pending'
    ) {

        throw new RuntimeException(
            'This post is no longer pending review.'
        );

    }


    /*
     * Save old values.
     */

    $oldValues =
        [

            'approval_status' =>
                $post['approval_status'],

            'visibility' =>
                $post['visibility'],

            'is_featured' =>
                (int)
                $post['is_featured']

        ];


    /*
     * Reject.
     *
     * The post remains in the database for audit/history,
     * but it is no longer part of the pending/approved flow.
     */

    $update =
        $pdo->prepare(
            "
            UPDATE posts

            SET

                approval_status =
                    'rejected',

                visibility =
                    'private'

            WHERE

                id =
                    :post_id

                AND LOWER(
                    approval_status
                ) =
                    'pending'

                AND deleted_at IS NULL

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    if (
        $update->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The post could not be rejected.'
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
                    'admin_reject_post',
                    'post',
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
                    $postId,

                ':old_values' =>
                    json_encode(
                        $oldValues,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [

                            'approval_status' =>
                                'rejected',

                            'visibility' =>
                                'private',

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
            '[LOVEMI REJECT POST AUDIT] '
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


    pendingPostRejectResponse(
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

pendingPostRejectResponse(
    true,
    'The post has been rejected successfully.',
    [

        'post_id' =>
            $postId,

        'approval_status' =>
            'rejected',

        'rejected' =>
            true

    ]
);