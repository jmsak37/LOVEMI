<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function deleteProfilePhotoResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
    &&
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'DELETE'
) {

    deleteProfilePhotoResponse(
        false,
        'Only POST or DELETE requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
============================================================ */

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

    deleteProfilePhotoResponse(
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


$photoId =
    (int)
    (
        $input['photo_id']
        ??
        $_GET['photo_id']
        ??
        0
    );


if (
    $photoId <= 0
) {

    deleteProfilePhotoResponse(
        false,
        'Photo ID is required.',
        [
            'code' =>
                'PHOTO_ID_REQUIRED'
        ],
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

    error_log(
        '[LOVEMI DELETE PROFILE PHOTO DB] '
        .
        $e->getMessage()
    );


    deleteProfilePhotoResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
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
                photo_type,
                is_primary,
                approval_status

            FROM photos

            WHERE id =
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

    error_log(
        '[LOVEMI DELETE PROFILE PHOTO LOOKUP] '
        .
        $e->getMessage()
    );


    deleteProfilePhotoResponse(
        false,
        'Unable to load the selected photo.',
        [
            'code' =>
                'PHOTO_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$photo
) {

    deleteProfilePhotoResponse(
        false,
        'Photo not found.',
        [
            'code' =>
                'PHOTO_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   OWNER CHECK
============================================================ */

if (
    (int)
    $photo['user_id']
    !==
    $userId
) {

    deleteProfilePhotoResponse(
        false,
        'You can only delete your own photo.',
        [
            'code' =>
                'NOT_PHOTO_OWNER'
        ],
        403
    );
}


/* ============================================================
   PHOTO TYPE CHECK
============================================================ */

if (
    $photo['photo_type']
    !==
    'profile'
) {

    deleteProfilePhotoResponse(
        false,
        'This endpoint is only for profile photos.',
        [
            'code' =>
                'NOT_PROFILE_PHOTO'
        ],
        422
    );
}


/* ============================================================
   DELETE DATABASE RECORD
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * If this is the current primary profile photo, choose the
     * next approved profile photo before deleting it.
     */

    if (
        (int)
        $photo['is_primary']
        ===
        1
    ) {

        $replacementStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM photos

                WHERE user_id =
                      :user_id

                  AND photo_type =
                      'profile'

                  AND approval_status =
                      'approved'

                  AND id <>
                      :photo_id

                ORDER BY

                    is_primary DESC,
                    is_featured DESC,
                    uploaded_at DESC,
                    id DESC

                LIMIT 1
                "
            );


        $replacementStmt->execute(
            [

                ':user_id' =>
                    $userId,

                ':photo_id' =>
                    $photoId

            ]
        );


        $replacementId =
            $replacementStmt->fetchColumn();


        /*
         * Clear all primary flags, then set the replacement.
         */

        if (
            $replacementId
        ) {

            $clearPrimary =
                $pdo->prepare(
                    "
                    UPDATE photos

                    SET
                        is_primary = 0

                    WHERE user_id =
                          :user_id

                      AND photo_type =
                          'profile'
                    "
                );


            $clearPrimary->execute(
                [
                    ':user_id' =>
                        $userId
                ]
            );


            $setReplacement =
                $pdo->prepare(
                    "
                    UPDATE photos

                    SET
                        is_primary = 1

                    WHERE id =
                        :photo_id

                      AND user_id =
                          :user_id

                    LIMIT 1
                    "
                );


            $setReplacement->execute(
                [

                    ':photo_id' =>
                        (int)
                        $replacementId,

                    ':user_id' =>
                        $userId

                ]
            );

        }

    }


    /*
     * Delete photo record.
     *
     * post_photos references photos with ON DELETE CASCADE.
     */

    $deleteStmt =
        $pdo->prepare(
            "
            DELETE FROM photos

            WHERE id =
                :photo_id

              AND user_id =
                  :user_id

            LIMIT 1
            "
        );


    $deleteStmt->execute(
        [

            ':photo_id' =>
                $photoId,

            ':user_id' =>
                $userId

        ]
    );


    if (
        $deleteStmt->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'Photo deletion affected no database record.'
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
        '[LOVEMI DELETE PROFILE PHOTO DB] '
        .
        $e->getMessage()
    );


    deleteProfilePhotoResponse(
        false,
        'Unable to delete the profile photo.',
        [
            'code' =>
                'PHOTO_DELETE_FAILED'
        ],
        500
    );
}


/* ============================================================
   DELETE PHYSICAL FILES
============================================================ */

$rootDirectory =
    dirname(
        __DIR__,
        2
    );


$filePaths = [

    $photo['file_path'],

    $photo['thumbnail_path']

];


foreach (
    $filePaths
    as $relativePath
) {

    if (
        empty(
            $relativePath
        )
    ) {

        continue;

    }


    /*
     * Only allow paths inside LOVEMI/uploads.
     */

    $normalized =
        str_replace(
            [
                '/',
                '\\'
            ],
            DIRECTORY_SEPARATOR,
            (string)
            $relativePath
        );


    $fullPath =
        $rootDirectory .
        DIRECTORY_SEPARATOR .
        ltrim(
            $normalized,
            DIRECTORY_SEPARATOR
        );


    if (
        is_file(
            $fullPath
        )
    ) {

        @unlink(
            $fullPath
        );

    }

}


/* ============================================================
   RESPONSE
============================================================ */

deleteProfilePhotoResponse(
    true,
    'Profile photo deleted successfully.',
    [

        'photo_id' =>
            $photoId,

        'deleted' =>
            true

    ]
);