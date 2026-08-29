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

function uploadPhotoResponse(
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
) {

    uploadPhotoResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    uploadPhotoResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}


/* ============================================================
   POST ID
============================================================ */

$postId =
    (int) (
        $_POST['post_id']
        ??
        0
    );


if ($postId <= 0) {

    uploadPhotoResponse(
        false,
        'Post ID is required.',
        [
            'code' => 'POST_ID_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   FILE
============================================================ */

if (
    !isset($_FILES['file'])
) {

    uploadPhotoResponse(
        false,
        'Please select an image or video.',
        [
            'code' => 'FILE_REQUIRED'
        ],
        422
    );
}


$file =
    $_FILES['file'];


/* ============================================================
   UPLOAD ERROR
============================================================ */

if (
    !isset($file['error'])
    ||
    $file['error'] !== UPLOAD_ERR_OK
) {

    $uploadMessages = [

        UPLOAD_ERR_INI_SIZE =>
            'The uploaded file is larger than the server limit.',

        UPLOAD_ERR_FORM_SIZE =>
            'The uploaded file is too large.',

        UPLOAD_ERR_PARTIAL =>
            'The upload was interrupted.',

        UPLOAD_ERR_NO_FILE =>
            'No file was uploaded.',

        UPLOAD_ERR_NO_TMP_DIR =>
            'The server temporary directory is missing.',

        UPLOAD_ERR_CANT_WRITE =>
            'The server could not save the uploaded file.',

        UPLOAD_ERR_EXTENSION =>
            'The upload was blocked by a server extension.'

    ];


    uploadPhotoResponse(
        false,
        $uploadMessages[
            $file['error']
        ]
        ??
        'The file upload failed.',
        [
            'code' =>
                'UPLOAD_ERROR',

            'upload_error' =>
                (int)
                $file['error']
        ],
        422
    );
}


/* ============================================================
   FILE SIZE
============================================================ */

/*
 * Application limit:
 * images: 10 MB
 * videos: 50 MB
 *
 * These limits are checked again below after MIME detection.
 */

$fileSize =
    isset($file['size'])
        ? (int) $file['size']
        : 0;


if ($fileSize <= 0) {

    uploadPhotoResponse(
        false,
        'The uploaded file is empty.',
        [
            'code' => 'EMPTY_FILE'
        ],
        422
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPLOAD PHOTO DB] ' .
        $e->getMessage()
    );

    uploadPhotoResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   VERIFY USER
============================================================ */

try {

    $userStmt = $pdo->prepare(
        "
        SELECT

            id,
            email_verified,
            is_active,
            is_suspended,
            is_deleted

        FROM users

        WHERE id = :user_id

        LIMIT 1
        "
    );

    $userStmt->execute([
        ':user_id' => $userId
    ]);

    $user = $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPLOAD PHOTO USER] ' .
        $e->getMessage()
    );

    uploadPhotoResponse(
        false,
        'Unable to verify your account.',
        [
            'code' => 'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (!$user) {

    uploadPhotoResponse(
        false,
        'Account not found.',
        [
            'code' => 'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int) $user['is_deleted'] === 1
) {

    uploadPhotoResponse(
        false,
        'Your account has been deleted.',
        [
            'code' => 'ACCOUNT_DELETED'
        ],
        403
    );
}


if (
    (int) $user['is_suspended'] === 1
) {

    uploadPhotoResponse(
        false,
        'Your account is suspended.',
        [
            'code' => 'ACCOUNT_SUSPENDED'
        ],
        403
    );
}


if (
    (int) $user['is_active'] !== 1
) {

    uploadPhotoResponse(
        false,
        'Your account is inactive.',
        [
            'code' => 'ACCOUNT_INACTIVE'
        ],
        403
    );
}


if (
    (int) $user['email_verified'] !== 1
) {

    uploadPhotoResponse(
        false,
        'Please verify your email before uploading media.',
        [
            'code' => 'EMAIL_VERIFICATION_REQUIRED',
            'redirect' => 'verify-account.html'
        ],
        403
    );
}


/* ============================================================
   PREMIUM CHECK
============================================================ */

try {

    $premiumStmt = $pdo->prepare(
        "
        SELECT

            s.id,
            s.start_at,
            s.end_at,
            sv.name,
            sv.slug

        FROM subscriptions s

        INNER JOIN services sv
            ON sv.id = s.service_id

        WHERE s.user_id = :user_id

          AND s.status = 'active'

          AND s.end_at > CURRENT_TIMESTAMP

          AND sv.slug = 'lovemi-premium'

          AND sv.is_premium = 1

          AND sv.is_active = 1

        ORDER BY
            s.end_at DESC,
            s.id DESC

        LIMIT 1
        "
    );


    $premiumStmt->execute([
        ':user_id' => $userId
    ]);


    $premium =
        $premiumStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPLOAD PHOTO PREMIUM] ' .
        $e->getMessage()
    );

    uploadPhotoResponse(
        false,
        'Unable to verify Premium access.',
        [
            'code' => 'PREMIUM_CHECK_FAILED'
        ],
        500
    );
}


if (!$premium) {

    uploadPhotoResponse(
        false,
        'An active LOVEMI Premium subscription is required to upload media.',
        [
            'code' => 'PREMIUM_REQUIRED',
            'redirect' => 'premium.html'
        ],
        403
    );
}


/* ============================================================
   VERIFY POST OWNERSHIP
============================================================ */

try {

    $postStmt = $pdo->prepare(
        "
        SELECT

            id,
            user_id,
            approval_status,
            deleted_at

        FROM posts

        WHERE id = :post_id

        LIMIT 1
        "
    );

    $postStmt->execute([
        ':post_id' => $postId
    ]);

    $post = $postStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPLOAD PHOTO POST] ' .
        $e->getMessage()
    );

    uploadPhotoResponse(
        false,
        'Unable to load the post.',
        [
            'code' => 'POST_LOOKUP_FAILED'
        ],
        500
    );
}


if (!$post) {

    uploadPhotoResponse(
        false,
        'Post not found.',
        [
            'code' => 'POST_NOT_FOUND'
        ],
        404
    );
}


if (
    (int) $post['user_id'] !==
    $userId
) {

    uploadPhotoResponse(
        false,
        'You can only upload media to your own post.',
        [
            'code' => 'NOT_POST_OWNER'
        ],
        403
    );
}


if (
    $post['deleted_at'] !== null
) {

    uploadPhotoResponse(
        false,
        'This post has been deleted.',
        [
            'code' => 'POST_DELETED'
        ],
        409
    );
}


/* ============================================================
   MIME DETECTION
============================================================ */

$tmpName =
    (string)
    $file['tmp_name'];


if (
    !is_uploaded_file(
        $tmpName
    )
) {

    uploadPhotoResponse(
        false,
        'Invalid uploaded file.',
        [
            'code' => 'INVALID_UPLOAD'
        ],
        422
    );
}


$finfo =
    new finfo(
        FILEINFO_MIME_TYPE
    );


$mimeType =
    $finfo->file(
        $tmpName
    );


if (
    !is_string(
        $mimeType
    )
) {

    uploadPhotoResponse(
        false,
        'Unable to determine the uploaded file type.',
        [
            'code' => 'MIME_DETECTION_FAILED'
        ],
        422
    );
}


/* ============================================================
   ALLOWED TYPES
============================================================ */

$allowedImages = [

    'image/jpeg' =>
        'jpg',

    'image/png' =>
        'png',

    'image/webp' =>
        'webp',

    'image/gif' =>
        'gif'

];


$allowedVideos = [

    'video/mp4' =>
        'mp4',

    'video/webm' =>
        'webm',

    'video/ogg' =>
        'ogv',

    'video/quicktime' =>
        'mov'

];


$isImage =
    array_key_exists(
        $mimeType,
        $allowedImages
    );


$isVideo =
    array_key_exists(
        $mimeType,
        $allowedVideos
    );


if (
    !$isImage
    &&
    !$isVideo
) {

    uploadPhotoResponse(
        false,
        'Unsupported file type. Please upload JPG, PNG, WEBP, GIF, MP4, WEBM, OGG or MOV.',
        [
            'code' =>
                'UNSUPPORTED_FILE_TYPE',

            'mime_type' =>
                $mimeType

        ],
        422
    );
}


/* ============================================================
   SIZE LIMIT
============================================================ */

$maxBytes =
    $isImage
        ?
        10 * 1024 * 1024
        :
        50 * 1024 * 1024;


if (
    $fileSize >
    $maxBytes
) {

    uploadPhotoResponse(
        false,
        $isImage
            ?
            'Images must not exceed 10 MB.'
            :
            'Videos must not exceed 50 MB.',
        [
            'code' =>
                'FILE_TOO_LARGE'
        ],
        422
    );
}


/* ============================================================
   ORIGINAL CLIENT NAME
============================================================ */

$originalName =
    basename(
        (string)
        (
            $file['name']
            ??
            'media'
        )
    );


$extension =
    $isImage
        ?
        $allowedImages[$mimeType]
        :
        $allowedVideos[$mimeType];


/* ============================================================
   RANDOM STORAGE NAME
============================================================ */

try {

    $random =
        bin2hex(
            random_bytes(
                16
            )
        );

} catch (Throwable $e) {

    uploadPhotoResponse(
        false,
        'Unable to generate a secure file name.',
        [
            'code' =>
                'FILENAME_GENERATION_FAILED'
        ],
        500
    );
}


$storedName =
    'post_'
    .
    $userId
    .
    '_'
    .
    time()
    .
    '_'
    .
    $random
    .
    '.'
    .
    $extension;


/* ============================================================
   DIRECTORIES
============================================================ */

$rootDirectory =
    dirname(
        __DIR__,
        2
    );


$originalDirectory =
    $rootDirectory .
    DIRECTORY_SEPARATOR .
    'uploads' .
    DIRECTORY_SEPARATOR .
    'posts' .
    DIRECTORY_SEPARATOR .
    'original';


$thumbnailDirectory =
    $rootDirectory .
    DIRECTORY_SEPARATOR .
    'uploads' .
    DIRECTORY_SEPARATOR .
    'posts' .
    DIRECTORY_SEPARATOR .
    'thumbnails';


if (
    !is_dir(
        $originalDirectory
    )
) {

    if (
        !mkdir(
            $originalDirectory,
            0755,
            true
        )
        &&
        !is_dir(
            $originalDirectory
        )
    ) {

        uploadPhotoResponse(
            false,
            'The original upload directory could not be created.',
            [
                'code' =>
                    'UPLOAD_DIRECTORY_FAILED'
            ],
            500
        );
    }

}


if (
    !is_dir(
        $thumbnailDirectory
    )
) {

    if (
        !mkdir(
            $thumbnailDirectory,
            0755,
            true
        )
        &&
        !is_dir(
            $thumbnailDirectory
        )
    ) {

        uploadPhotoResponse(
            false,
            'The thumbnail directory could not be created.',
            [
                'code' =>
                    'THUMBNAIL_DIRECTORY_FAILED'
            ],
            500
        );
    }

}


/* ============================================================
   MOVE ORIGINAL
============================================================ */

$originalAbsolutePath =
    $originalDirectory .
    DIRECTORY_SEPARATOR .
    $storedName;


if (
    !move_uploaded_file(
        $tmpName,
        $originalAbsolutePath
    )
) {

    uploadPhotoResponse(
        false,
        'The uploaded file could not be saved.',
        [
            'code' =>
                'FILE_SAVE_FAILED'
        ],
        500
    );
}


/* ============================================================
   RELATIVE PATHS
============================================================ */

$relativeOriginalPath =
    'uploads/posts/original/' .
    $storedName;


$thumbnailPath =
    null;


/* ============================================================
   IMAGE DIMENSIONS
============================================================ */

$width =
    null;

$height =
    null;


if ($isImage) {

    $imageInfo =
        @getimagesize(
            $originalAbsolutePath
        );


    if (
        is_array(
            $imageInfo
        )
    ) {

        $width =
            isset(
                $imageInfo[0]
            )
                ?
                (int)
                $imageInfo[0]
                :
                null;

        $height =
            isset(
                $imageInfo[1]
            )
                ?
                (int)
                $imageInfo[1]
                :
                null;

    }


    /*
     * Generate a modest thumbnail where GD is available.
     * The original remains untouched.
     */

    if (
        function_exists(
            'imagecreatefromjpeg'
        )
        ||
        function_exists(
            'imagecreatefrompng'
        )
        ||
        function_exists(
            'imagecreatefromwebp'
        )
        ||
        function_exists(
            'imagecreatefromgif'
        )
    ) {

        try {

            $sourceImage =
                null;


            switch (
                $mimeType
            ) {

                case 'image/jpeg':

                    if (
                        function_exists(
                            'imagecreatefromjpeg'
                        )
                    ) {

                        $sourceImage =
                            @imagecreatefromjpeg(
                                $originalAbsolutePath
                            );

                    }

                    break;


                case 'image/png':

                    if (
                        function_exists(
                            'imagecreatefrompng'
                        )
                    ) {

                        $sourceImage =
                            @imagecreatefrompng(
                                $originalAbsolutePath
                            );

                    }

                    break;


                case 'image/webp':

                    if (
                        function_exists(
                            'imagecreatefromwebp'
                        )
                    ) {

                        $sourceImage =
                            @imagecreatefromwebp(
                                $originalAbsolutePath
                            );

                    }

                    break;


                case 'image/gif':

                    if (
                        function_exists(
                            'imagecreatefromgif'
                        )
                    ) {

                        $sourceImage =
                            @imagecreatefromgif(
                                $originalAbsolutePath
                            );

                    }

                    break;

            }


            if (
                $sourceImage
                &&
                $width
                &&
                $height
            ) {

                $maxDimension =
                    800;


                $scale =
                    min(
                        1,
                        $maxDimension /
                        max(
                            $width,
                            $height
                        )
                    );


                $thumbWidth =
                    max(
                        1,
                        (int)
                        round(
                            $width *
                            $scale
                        )
                    );


                $thumbHeight =
                    max(
                        1,
                        (int)
                        round(
                            $height *
                            $scale
                        )
                    );


                $thumb =
                    imagecreatetruecolor(
                        $thumbWidth,
                        $thumbHeight
                    );


                if (
                    $mimeType ===
                    'image/png'
                    ||
                    $mimeType ===
                    'image/webp'
                    ||
                    $mimeType ===
                    'image/gif'
                ) {

                    imagealphablending(
                        $thumb,
                        false
                    );

                    imagesavealpha(
                        $thumb,
                        true
                    );

                }


                imagecopyresampled(
                    $thumb,
                    $sourceImage,
                    0,
                    0,
                    0,
                    0,
                    $thumbWidth,
                    $thumbHeight,
                    $width,
                    $height
                );


                $thumbnailName =
                    'thumb_' .
                    $storedName;


                $thumbnailAbsolutePath =
                    $thumbnailDirectory .
                    DIRECTORY_SEPARATOR .
                    $thumbnailName;


                $created =
                    false;


                switch (
                    $mimeType
                ) {

                    case 'image/jpeg':

                        if (
                            function_exists(
                                'imagejpeg'
                            )
                        ) {

                            $created =
                                @imagejpeg(
                                    $thumb,
                                    $thumbnailAbsolutePath,
                                    82
                                );

                        }

                        break;


                    case 'image/png':

                        if (
                            function_exists(
                                'imagepng'
                            )
                        ) {

                            $created =
                                @imagepng(
                                    $thumb,
                                    $thumbnailAbsolutePath,
                                    6
                                );

                        }

                        break;


                    case 'image/webp':

                        if (
                            function_exists(
                                'imagewebp'
                            )
                        ) {

                            $created =
                                @imagewebp(
                                    $thumb,
                                    $thumbnailAbsolutePath,
                                    82
                                );

                        }

                        break;


                    case 'image/gif':

                        if (
                            function_exists(
                                'imagegif'
                            )
                        ) {

                            $created =
                                @imagegif(
                                    $thumb,
                                    $thumbnailAbsolutePath
                                );

                        }

                        break;

                }


                imagedestroy(
                    $sourceImage
                );


                imagedestroy(
                    $thumb
                );


                if (
                    $created
                    &&
                    is_file(
                        $thumbnailAbsolutePath
                    )
                ) {

                    $thumbnailPath =
                        'uploads/posts/thumbnails/' .
                        $thumbnailName;

                }

            }

        } catch (
            Throwable $e
        ) {

            /*
             * Thumbnail generation failure does not invalidate
             * the original upload.
             */

            error_log(
                '[LOVEMI THUMBNAIL] ' .
                $e->getMessage()
            );

        }

    }

}


/* ============================================================
   INSERT DATABASE RECORD
============================================================ */

$photoId =
    0;


try {

    $pdo->beginTransaction();


    /*
     * Store uploaded media as pending.
     */

    $photoStmt =
        $pdo->prepare(
            "
            INSERT INTO photos
            (
                user_id,
                file_name,
                file_path,
                thumbnail_path,
                mime_type,
                file_size,
                width,
                height,
                photo_type,
                approval_status,
                is_primary,
                is_featured
            )
            VALUES
            (
                :user_id,
                :file_name,
                :file_path,
                :thumbnail_path,
                :mime_type,
                :file_size,
                :width,
                :height,
                'post',
                'pending',
                0,
                0
            )
            "
        );


    $photoStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':file_name' =>
                $originalName,

            ':file_path' =>
                $relativeOriginalPath,

            ':thumbnail_path' =>
                $thumbnailPath,

            ':mime_type' =>
                $mimeType,

            ':file_size' =>
                $fileSize,

            ':width' =>
                $width,

            ':height' =>
                $height

        ]
    );


    $photoId =
        (int)
        $pdo->lastInsertId();


    /*
     * Attach the media to the post.
     */

    $orderStmt =
        $pdo->prepare(
            "
            SELECT
                COALESCE(
                    MAX(display_order),
                    0
                ) + 1

            FROM post_photos

            WHERE post_id =
                  :post_id
            "
        );


    $orderStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $displayOrder =
        (int)
        $orderStmt->fetchColumn();


    if (
        $displayOrder <
        1
    ) {

        $displayOrder =
            1;

    }


    $linkStmt =
        $pdo->prepare(
            "
            INSERT INTO post_photos
            (
                post_id,
                photo_id,
                display_order
            )
            VALUES
            (
                :post_id,
                :photo_id,
                :display_order
            )
            "
        );


    $linkStmt->execute(
        [

            ':post_id' =>
                $postId,

            ':photo_id' =>
                $photoId,

            ':display_order' =>
                $displayOrder

        ]
    );


    /*
     * If an already-approved post receives a new media item,
     * force the post back into moderation.
     */

    if (
        $post['approval_status'] ===
        'approved'
    ) {

        $resetApproval =
            $pdo->prepare(
                "
                UPDATE posts

                SET

                    approval_status =
                        'pending',

                    approved_at =
                        NULL,

                    approved_by =
                        NULL

                WHERE id =
                    :post_id

                AND user_id =
                    :user_id

                LIMIT 1
                "
            );


        $resetApproval->execute(
            [

                ':post_id' =>
                    $postId,

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


    /*
     * Remove the stored original when the database transaction
     * fails, so files do not become orphaned.
     */

    if (
        is_file(
            $originalAbsolutePath
        )
    ) {

        @unlink(
            $originalAbsolutePath
        );

    }


    if (
        $thumbnailPath
    ) {

        $thumbnailAbsolutePath =
            $thumbnailDirectory .
            DIRECTORY_SEPARATOR .
            basename(
                $thumbnailPath
            );


        if (
            is_file(
                $thumbnailAbsolutePath
            )
        ) {

            @unlink(
                $thumbnailAbsolutePath
            );

        }

    }


    error_log(
        '[LOVEMI UPLOAD PHOTO DB INSERT] '
        .
        $e->getMessage()
    );


    uploadPhotoResponse(
        false,
        'Unable to save the uploaded media.',
        [
            'code' =>
                'MEDIA_DATABASE_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

uploadPhotoResponse(
    true,
    'Media uploaded successfully and is awaiting admin approval.',
    [

        'photo' => [

            'id' =>
                $photoId,

            'post_id' =>
                $postId,

            'file_name' =>
                $originalName,

            'file_path' =>
                $relativeOriginalPath,

            'thumbnail_path' =>
                $thumbnailPath,

            'mime_type' =>
                $mimeType,

            'file_size' =>
                $fileSize,

            'width' =>
                $width,

            'height' =>
                $height,

            'photo_type' =>
                'post',

            'approval_status' =>
                'pending'

        ]

    ],
    201
);