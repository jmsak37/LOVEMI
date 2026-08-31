<?php

declare(strict_types=1);


/* ============================================================
   LOVEMI - REJECT PHOTO
============================================================ */

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


ini_set(
    'display_errors',
    '0'
);


/* ============================================================
   SESSION
============================================================ */

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


/* ============================================================
   RESPONSE
============================================================ */

function rejectPhotoResponse(
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

    rejectPhotoResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* ============================================================
   INPUT
============================================================ */

$data =
    json_decode(
        file_get_contents(
            'php://input'
        )
        ?:
        '{}',
        true
    );


if (
    !is_array(
        $data
    )
) {

    $data =
        $_POST;

}


$photoId =
    (int)(
        $data['photo_id']
        ??
        0
    );


if (
    $photoId <= 0
) {

    rejectPhotoResponse(
        false,
        'A valid photo ID is required.',
        [],
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

    rejectPhotoResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   SESSION
============================================================ */

$adminId =
    (int)(
        $_SESSION[
            'lovemi_user_id'
        ]
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION[
            'lovemi_database_session_id'
        ]
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION[
            'lovemi_session_token'
        ]
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

    rejectPhotoResponse(
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


/* ============================================================
   AUTH + PERMISSION
============================================================ */

try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.role_id

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

                u.id = :user_id

                AND s.id = :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND p.slug =
                    'photos.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [
            ':user_id' =>
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

    rejectPhotoResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    rejectPhotoResponse(
        false,
        'You do not have permission to reject photos.',
        [],
        403
    );

}


/* ============================================================
   LOAD PHOTO
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                file_name,

                approval_status,

                is_featured

            FROM photos

            WHERE
                id =
                    :photo_id

            LIMIT 1
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

} catch (
    Throwable $e
) {

    rejectPhotoResponse(
        false,
        'Unable to load the photo.',
        [],
        500
    );

}


if (
    !$photo
) {

    rejectPhotoResponse(
        false,
        'Photo not found.',
        [],
        404
    );

}


/* ============================================================
   REJECT
============================================================ */

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE photos

            SET

                approval_status =
                    'rejected',

                approved_at =
                    CURRENT_TIMESTAMP,

                approved_by =
                    :admin_id,

                is_featured =
                    0

            WHERE

                id =
                    :photo_id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':admin_id' =>
                $adminId,

            ':photo_id' =>
                $photoId
        ]
    );


    if (
        $update->rowCount()
        <
        1
    ) {

        throw new RuntimeException(
            'Photo rejection failed.'
        );

    }


    /* ========================================================
       AUDIT
    ======================================================== */

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
                'photo_rejected',
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
                    [
                        'approval_status' =>
                            $photo[
                                'approval_status'
                            ],

                        'is_featured' =>
                            (int)
                            $photo[
                                'is_featured'
                            ]
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':new_values' =>
                json_encode(
                    [
                        'approval_status' =>
                            'rejected',

                        'is_featured' =>
                            0,

                        'approved_by' =>
                            $adminId
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':ip' =>
                $_SERVER[
                    'REMOTE_ADDR'
                ]
                ??
                null,

            ':agent' =>
                $_SERVER[
                    'HTTP_USER_AGENT'
                ]
                ??
                null
        ]
    );


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
        '[LOVEMI REJECT PHOTO] '
        .
        $e->getMessage()
    );


    rejectPhotoResponse(
        false,
        'Unable to reject photo.',
        [],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

rejectPhotoResponse(
    true,
    'Photo rejected successfully.',
    [
        'photo_id' =>
            $photoId,

        'approval_status' =>
            'rejected'

    ]
);