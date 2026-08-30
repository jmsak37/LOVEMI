<?php

declare(strict_types=1);


/* ============================================================
   LOVEMI - DELETE PHOTO
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

function deletePhotoResponse(
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

    deletePhotoResponse(
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

    deletePhotoResponse(
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

    deletePhotoResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ADMIN SESSION
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

    deletePhotoResponse(
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

    deletePhotoResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    deletePhotoResponse(
        false,
        'You do not have permission to delete photos.',
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

                file_path,

                thumbnail_path,

                approval_status,

                is_primary,

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

    deletePhotoResponse(
        false,
        'Unable to load the photo.',
        [],
        500
    );

}


if (
    !$photo
) {

    deletePhotoResponse(
        false,
        'Photo not found.',
        [],
        404
    );

}


/* ============================================================
   DELETE
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Remove references from post_photos first.
     */

    $unlink =
        $pdo->prepare(
            "
            DELETE FROM post_photos

            WHERE
                photo_id =
                    :photo_id
            "
        );


    $unlink->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    /*
     * Delete database photo record.
     */

    $delete =
        $pdo->prepare(
            "
            DELETE FROM photos

            WHERE
                id =
                    :photo_id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'Photo deletion failed.'
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
                'photo_deleted',
                'photo',
                :entity_id,
                :old_values,
                NULL,
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
                        'user_id' =>
                            (int)
                            $photo[
                                'user_id'
                            ],

                        'file_name' =>
                            $photo[
                                'file_name'
                            ],

                        'file_path' =>
                            $photo[
                                'file_path'
                            ],

                        'approval_status' =>
                            $photo[
                                'approval_status'
                            ],

                        'is_primary' =>
                            (int)
                            $photo[
                                'is_primary'
                            ],

                        'is_featured' =>
                            (int)
                            $photo[
                                'is_featured'
                            ]
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
        '[LOVEMI DELETE PHOTO] '
        .
        $e->getMessage()
    );


    deletePhotoResponse(
        false,
        'Unable to delete photo.',
        [],
        500
    );

}


/* ============================================================
   REMOVE PHYSICAL FILES
============================================================ */

/*
 * Database deletion has already succeeded.
 *
 * File deletion is attempted separately so a filesystem
 * problem does not undo the database transaction.
 */

$deletedFiles = [];

$failedFiles = [];


$rootPath =
    dirname(
        __DIR__,
        2
    );


foreach (
    [
        $photo[
            'file_path'
        ],
        $photo[
            'thumbnail_path'
        ]
    ]
    as $relativePath
) {

    if (
        !$relativePath
    ) {

        continue;

    }


    $relativePath =
        str_replace(
            '\\',
            '/',
            trim(
                (string)
                $relativePath
            )
        );


    $relativePath =
        ltrim(
            $relativePath,
            '/'
        );


    /*
     * Do not allow path traversal.
     */

    if (
        str_contains(
            $relativePath,
            '../'
        )
        ||
        str_contains(
            $relativePath,
            '..\\'
        )
    ) {

        $failedFiles[] =
            $relativePath;

        continue;

    }


    $physicalPath =
        $rootPath
        .
        DIRECTORY_SEPARATOR
        .
        str_replace(
            '/',
            DIRECTORY_SEPARATOR,
            $relativePath
        );


    if (
        is_file(
            $physicalPath
        )
    ) {

        if (
            @unlink(
                $physicalPath
            )
        ) {

            $deletedFiles[] =
                $relativePath;

        } else {

            $failedFiles[] =
                $relativePath;

        }

    }

}


/* ============================================================
   RESPONSE
============================================================ */

deletePhotoResponse(
    true,
    $failedFiles
        ?
        'Photo record deleted. One or more physical files could not be removed automatically.'
        :
        'Photo deleted successfully.',
    [
        'photo_id' =>
            $photoId,

        'files_deleted' =>
            $deletedFiles,

        'files_failed' =>
            $failedFiles

    ]
);