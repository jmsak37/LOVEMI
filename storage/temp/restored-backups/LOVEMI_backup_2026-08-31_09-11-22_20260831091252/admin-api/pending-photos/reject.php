<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - REJECT PHOTO
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


function pendingPhotoRejectResponse(
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

    pendingPhotoRejectResponse(
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
    !empty(
        $_SERVER['HTTPS']
    )
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

    pendingPhotoRejectResponse(
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

    pendingPhotoRejectResponse(
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
                u.id

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
                    'photos.manage'

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

        pendingPhotoRejectResponse(
            false,
            'You do not have permission to reject photos.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingPhotoRejectResponse(
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


$photoId =
    (int)(
        $input['photo_id']
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
    $photoId <= 0
) {

    pendingPhotoRejectResponse(
        false,
        'A valid photo ID is required.',
        [],
        422
    );

}


if (
    $reason === ''
) {

    pendingPhotoRejectResponse(
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

    pendingPhotoRejectResponse(
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


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                file_name,

                approval_status,

                is_featured,

                is_primary

            FROM photos

            WHERE
                id =
                    :photo_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    $photo =
        $stmt->fetch();


    if (
        !$photo
    ) {

        throw new RuntimeException(
            'The requested media was not found.'
        );

    }


    if (
        strtolower(
            (string)
            $photo['approval_status']
        )
        !==
        'pending'
    ) {

        throw new RuntimeException(
            'This media is no longer pending review.'
        );

    }


    $oldValues =
        [

            'approval_status' =>
                $photo['approval_status'],

            'is_featured' =>
                (int)
                $photo['is_featured']

        ];


    $update =
        $pdo->prepare(
            "
            UPDATE photos

            SET

                approval_status =
                    'rejected',

                is_featured =
                    0

            WHERE

                id =
                    :photo_id

                AND LOWER(
                    approval_status
                ) =
                    'pending'

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    if (
        $update->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The media could not be rejected.'
        );

    }


    /*
     * If rejected media was marked primary,
     * remove its primary state.
     */

    try {

        $primaryUpdate =
            $pdo->prepare(
                "
                UPDATE photos

                SET
                    is_primary =
                        0

                WHERE
                    id =
                        :photo_id

                LIMIT 1
                "
            );


        $primaryUpdate->execute(
            [
                ':photo_id' =>
                    $photoId
            ]
        );

    } catch (
        Throwable $primaryError
    ) {

        error_log(
            '[LOVEMI REJECT PHOTO PRIMARY] '
            .
            $primaryError->getMessage()
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
                    'admin_reject_photo',
                    'photo',
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
                    $photoId,

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

                            'is_featured' =>
                                false,

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
            '[LOVEMI PHOTO REJECT AUDIT] '
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


    pendingPhotoRejectResponse(
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

pendingPhotoRejectResponse(
    true,
    'The media has been rejected successfully.',
    [

        'photo_id' =>
            $photoId,

        'approval_status' =>
            'rejected',

        'rejected' =>
            true

    ]
);