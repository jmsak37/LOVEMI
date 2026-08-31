<?php

declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI
 * Profile Photo Upload API
 * ============================================================
 *
 * Upload location:
 *
 * uploads/
 * └── profiles/
 *     ├── original/
 *     ├── thumbnails/
 *     └── approved/
 *
 * The database stores the relative paths.
 *
 * New uploads are always:
 *
 * photo_type       = profile
 * approval_status  = pending
 *
 * unless system_settings explicitly enables automatic
 * photo approval.
 *
 * ============================================================
 */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/*
 * Load database connection.
 */
require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function respond(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
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
    ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST'
) {

    respond(
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
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        $_SESSION['user_id']
        ??
        $_SESSION['userID']
        ??
        0
    );


if ($userId <= 0) {

    respond(
        false,
        'Please log in before uploading a profile photo.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}


/* ============================================================
   FILE CHECK
============================================================ */

if (
    !isset($_FILES['profile_photo'])
) {

    respond(
        false,
        'No profile photo was selected.',
        [
            'code' => 'FILE_MISSING'
        ],
        422
    );
}


$file = $_FILES['profile_photo'];


if (
    !isset($file['error']) ||
    $file['error'] !== UPLOAD_ERR_OK
) {

    $uploadError =
        (int)(
            $file['error']
            ??
            UPLOAD_ERR_NO_FILE
        );


    $messages = [

        UPLOAD_ERR_INI_SIZE =>
            'The uploaded photo is larger than the server allows.',

        UPLOAD_ERR_FORM_SIZE =>
            'The uploaded photo is too large.',

        UPLOAD_ERR_PARTIAL =>
            'The upload was incomplete.',

        UPLOAD_ERR_NO_FILE =>
            'No profile photo was selected.',

        UPLOAD_ERR_NO_TMP_DIR =>
            'The temporary upload directory is missing.',

        UPLOAD_ERR_CANT_WRITE =>
            'The server could not write the uploaded photo.',

        UPLOAD_ERR_EXTENSION =>
            'The server stopped the photo upload.'

    ];


    respond(
        false,
        $messages[$uploadError]
            ??
            'The profile photo upload failed.',
        [
            'code' => 'UPLOAD_ERROR'
        ],
        422
    );
}


/* ============================================================
   FILE SIZE
============================================================ */

$maxSize =
    8 * 1024 * 1024;


if (
    (int)$file['size'] <= 0
) {

    respond(
        false,
        'The selected file is empty.',
        [
            'code' => 'EMPTY_FILE'
        ],
        422
    );
}


if (
    (int)$file['size'] > $maxSize
) {

    respond(
        false,
        'The profile photo must be 8 MB or smaller.',
        [
            'code' => 'FILE_TOO_LARGE'
        ],
        422
    );
}


/* ============================================================
   MIME TYPE
============================================================ */

$allowedMimeTypes = [

    'image/jpeg' => 'jpg',

    'image/png' => 'png',

    'image/webp' => 'webp'

];


$finfo =
    new finfo(
        FILEINFO_MIME_TYPE
    );


$mimeType =
    $finfo->file(
        $file['tmp_name']
    );


if (
    !isset(
        $allowedMimeTypes[$mimeType]
    )
) {

    respond(
        false,
        'Only JPG, PNG and WebP profile photos are allowed.',
        [
            'code' => 'INVALID_IMAGE_TYPE'
        ],
        422
    );
}


$extension =
    $allowedMimeTypes[$mimeType];


/* ============================================================
   VERIFY IMAGE
============================================================ */

$imageInfo =
    @getimagesize(
        $file['tmp_name']
    );


if (
    $imageInfo === false
) {

    respond(
        false,
        'The selected file is not a valid image.',
        [
            'code' => 'INVALID_IMAGE'
        ],
        422
    );
}


$width =
    (int)(
        $imageInfo[0]
        ??
        0
    );


$height =
    (int)(
        $imageInfo[1]
        ??
        0
    );


if (
    $width <= 0 ||
    $height <= 0
) {

    respond(
        false,
        'The image dimensions are invalid.',
        [
            'code' => 'INVALID_DIMENSIONS'
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPLOAD PHOTO DB] '
        .
        $e->getMessage()
    );

    respond(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   ENSURE TABLE
============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS photos
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            user_id BIGINT UNSIGNED NOT NULL,

            file_name VARCHAR(255) NOT NULL,

            file_path VARCHAR(500) NOT NULL,

            thumbnail_path VARCHAR(500) NULL,

            mime_type VARCHAR(100) NULL,

            file_size BIGINT UNSIGNED NULL,

            width INT UNSIGNED NULL,

            height INT UNSIGNED NULL,

            photo_type VARCHAR(30) NOT NULL DEFAULT 'profile',

            approval_status VARCHAR(30) NOT NULL DEFAULT 'pending',

            is_primary TINYINT(1) NOT NULL DEFAULT 0,

            is_featured TINYINT(1) NOT NULL DEFAULT 0,

            uploaded_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            approved_at DATETIME NULL,

            approved_by BIGINT UNSIGNED NULL,

            PRIMARY KEY (id),

            KEY idx_photos_user_id (user_id),

            KEY idx_photos_approval (approval_status),

            KEY idx_photos_type (photo_type),

            KEY idx_photos_primary (is_primary)

        )

        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );


    /*
     * Add missing columns when the table already exists
     * but is incomplete.
     */

    $columns = [

        'thumbnail_path' =>
            'VARCHAR(500) NULL',

        'mime_type' =>
            'VARCHAR(100) NULL',

        'file_size' =>
            'BIGINT UNSIGNED NULL',

        'width' =>
            'INT UNSIGNED NULL',

        'height' =>
            'INT UNSIGNED NULL',

        'photo_type' =>
            "VARCHAR(30) NOT NULL DEFAULT 'profile'",

        'approval_status' =>
            "VARCHAR(30) NOT NULL DEFAULT 'pending'",

        'is_primary' =>
            'TINYINT(1) NOT NULL DEFAULT 0',

        'is_featured' =>
            'TINYINT(1) NOT NULL DEFAULT 0',

        'uploaded_at' =>
            'DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP',

        'approved_at' =>
            'DATETIME NULL',

        'approved_by' =>
            'BIGINT UNSIGNED NULL'

    ];


    foreach (
        $columns
        as $column =>
        $definition
    ) {

        $check =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM INFORMATION_SCHEMA.COLUMNS

                WHERE TABLE_SCHEMA = DATABASE()

                  AND TABLE_NAME = 'photos'

                  AND COLUMN_NAME = ?
                "
            );


        $check->execute(
            [
                $column
            ]
        );


        $exists =
            (int)$check->fetchColumn()
            > 0;


        if (
            !$exists
        ) {

            $pdo->exec(
                "
                ALTER TABLE photos
                ADD COLUMN `{$column}` {$definition}
                "
            );

        }

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PHOTO SCHEMA] '
        .
        $e->getMessage()
    );

    respond(
        false,
        'The photo database structure could not be prepared.',
        [
            'code' => 'PHOTO_SCHEMA_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER CHECK
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                gender,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = ?

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PHOTO USER] '
        .
        $e->getMessage()
    );

    respond(
        false,
        'Your account could not be checked.',
        [
            'code' => 'USER_CHECK_ERROR'
        ],
        500
    );
}


if (
    !$user
) {

    respond(
        false,
        'Your account could not be found.',
        [
            'code' => 'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    !(bool)$user['is_active']
    ||
    (bool)$user['is_suspended']
    ||
    (bool)$user['is_deleted']
) {

    respond(
        false,
        'Your account is currently unavailable.',
        [
            'code' => 'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   PREMIUM CHECK
============================================================ */

$hasPremium = false;


try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM subscriptions

            WHERE user_id = ?

              AND status = 'active'

              AND start_at <= CURRENT_TIMESTAMP

              AND end_at > CURRENT_TIMESTAMP

            LIMIT 1
            "
        );


    $premiumStmt->execute(
        [
            $userId
        ]
    );


    $hasPremium =
        (bool)$premiumStmt->fetch();

} catch (Throwable $e) {

    /*
     * Fail closed.
     */

    $hasPremium =
        false;

}


/*
 * Only premium users can upload profile photos according
 * to the LOVEMI business rule.
 */

if (
    !$hasPremium
) {

    respond(
        false,
        'An active Premium subscription is required to upload profile photos.',
        [
            'code' => 'PREMIUM_REQUIRED',
            'redirect' => 'premium.html'
        ],
        403
    );
}


/* ============================================================
   STORAGE PATHS
============================================================ */

$projectRoot =
    realpath(
        __DIR__ . '/../..'
    );


if (
    $projectRoot === false
) {

    respond(
        false,
        'The LOVEMI project directory could not be located.',
        [
            'code' => 'PROJECT_PATH_ERROR'
        ],
        500
    );
}


/*
 * Create all profile photo folders automatically.
 */

$directories = [

    $projectRoot .
        DIRECTORY_SEPARATOR .
        'uploads' .
        DIRECTORY_SEPARATOR .
        'profiles' .
        DIRECTORY_SEPARATOR .
        'original',

    $projectRoot .
        DIRECTORY_SEPARATOR .
        'uploads' .
        DIRECTORY_SEPARATOR .
        'profiles' .
        DIRECTORY_SEPARATOR .
        'thumbnails',

    $projectRoot .
        DIRECTORY_SEPARATOR .
        'uploads' .
        DIRECTORY_SEPARATOR .
        'profiles' .
        DIRECTORY_SEPARATOR .
        'approved'

];


foreach (
    $directories
    as $directory
) {

    if (
        !is_dir(
            $directory
        )
    ) {

        if (
            !mkdir(
                $directory,
                0775,
                true
            )
            &&
            !is_dir(
                $directory
            )
        ) {

            respond(
                false,
                'The profile photo storage folders could not be created.',
                [
                    'code' =>
                        'STORAGE_DIRECTORY_ERROR'
                ],
                500
            );
        }
    }


    if (
        !is_writable(
            $directory
        )
    ) {

        respond(
            false,
            'The profile photo storage folder is not writable.',
            [
                'code' =>
                    'STORAGE_PERMISSION_ERROR'
            ],
            500
        );
    }

}


/* ============================================================
   SAFE FILE NAME
============================================================ */

$random =
    bin2hex(
        random_bytes(16)
    );


$fileName =
    'profile_'
    .
    $userId
    .
    '_'
    .
    date('YmdHis')
    .
    '_'
    .
    $random
    .
    '.'
    .
    $extension;


$originalRelative =
    'uploads/profiles/original/'
    .
    $fileName;


$thumbnailFileName =
    'thumb_'
    .
    $fileName;


$thumbnailRelative =
    'uploads/profiles/thumbnails/'
    .
    $thumbnailFileName;


$originalAbsolute =
    $projectRoot
    .
    DIRECTORY_SEPARATOR
    .
    str_replace(
        '/',
        DIRECTORY_SEPARATOR,
        $originalRelative
    );


$thumbnailAbsolute =
    $projectRoot
    .
    DIRECTORY_SEPARATOR
    .
    str_replace(
        '/',
        DIRECTORY_SEPARATOR,
        $thumbnailRelative
    );


/* ============================================================
   MOVE ORIGINAL
============================================================ */

if (
    !move_uploaded_file(
        $file['tmp_name'],
        $originalAbsolute
    )
) {

    respond(
        false,
        'The profile photo could not be saved to the server.',
        [
            'code' =>
                'FILE_MOVE_FAILED'
        ],
        500
    );
}


/* ============================================================
   CREATE THUMBNAIL
============================================================ */

$thumbnailCreated =
    false;


try {

    $sourceImage = null;


    if (
        $mimeType ===
        'image/jpeg'
    ) {

        $sourceImage =
            @imagecreatefromjpeg(
                $originalAbsolute
            );

    } elseif (
        $mimeType ===
        'image/png'
    ) {

        $sourceImage =
            @imagecreatefrompng(
                $originalAbsolute
            );

    } elseif (
        $mimeType ===
        'image/webp'
    ) {

        if (
            function_exists(
                'imagecreatefromwebp'
            )
        ) {

            $sourceImage =
                @imagecreatefromwebp(
                    $originalAbsolute
                );

        }

    }


    if (
        $sourceImage
    ) {

        $targetSize =
            500;


        $ratio =
            min(
                $targetSize / $width,
                $targetSize / $height
            );


        $newWidth =
            max(
                1,
                (int)round(
                    $width * $ratio
                )
            );


        $newHeight =
            max(
                1,
                (int)round(
                    $height * $ratio
                )
            );


        $thumb =
            imagecreatetruecolor(
                $newWidth,
                $newHeight
            );


        /*
         * PNG/WebP transparency.
         */

        if (
            $mimeType !==
            'image/jpeg'
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
            $newWidth,
            $newHeight,
            $width,
            $height
        );


        if (
            $mimeType ===
            'image/jpeg'
        ) {

            $thumbnailCreated =
                @imagejpeg(
                    $thumb,
                    $thumbnailAbsolute,
                    88
                );

        } elseif (
            $mimeType ===
            'image/png'
        ) {

            $thumbnailCreated =
                @imagepng(
                    $thumb,
                    $thumbnailAbsolute,
                    6
                );

        } elseif (
            $mimeType ===
            'image/webp'
            &&
            function_exists(
                'imagewebp'
            )
        ) {

            $thumbnailCreated =
                @imagewebp(
                    $thumb,
                    $thumbnailAbsolute,
                    88
                );

        }


        imagedestroy(
            $thumb
        );


        imagedestroy(
            $sourceImage
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI THUMBNAIL] '
        .
        $e->getMessage()
    );

}


/*
 * If thumbnail generation failed, use the original path
 * as thumbnail fallback.
 */

if (
    !$thumbnailCreated
) {

    $thumbnailRelative =
        $originalRelative;

}


/* ============================================================
   SYSTEM SETTING: AUTO APPROVAL
============================================================ */

$approvalStatus =
    'pending';


$approvedAt =
    null;


try {

    $settingStmt =
        $pdo->prepare(
            "
            SELECT setting_value

            FROM system_settings

            WHERE setting_key =
                'automatic_photo_approval'

            LIMIT 1
            "
        );


    $settingStmt->execute();


    $settingValue =
        $settingStmt->fetchColumn();


    if (
        in_array(
            strtolower(
                trim(
                    (string)$settingValue
                )
            ),
            [
                '1',
                'true',
                'yes'
            ],
            true
        )
    ) {

        $approvalStatus =
            'approved';


        $approvedAt =
            date(
                'Y-m-d H:i:s'
            );

    }

} catch (Throwable $e) {

    /*
     * Default remains pending.
     */

}


/* ============================================================
   DATABASE TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Existing primary profile photos are no longer primary.
     */

    $clearPrimary =
        $pdo->prepare(
            "
            UPDATE photos

            SET is_primary = 0

            WHERE user_id = ?

              AND photo_type = 'profile'
            "
        );


    $clearPrimary->execute(
        [
            $userId
        ]
    );


    /*
     * Insert new photo.
     */

    $insert =
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
                is_featured,
                uploaded_at,
                approved_at,
                approved_by
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
                'profile',
                :approval_status,
                1,
                0,
                CURRENT_TIMESTAMP,
                :approved_at,
                NULL
            )
            "
        );


    $insert->execute(
        [

            ':user_id' =>
                $userId,

            ':file_name' =>
                $fileName,

            ':file_path' =>
                $originalRelative,

            ':thumbnail_path' =>
                $thumbnailRelative,

            ':mime_type' =>
                $mimeType,

            ':file_size' =>
                (int)$file['size'],

            ':width' =>
                $width,

            ':height' =>
                $height,

            ':approval_status' =>
                $approvalStatus,

            ':approved_at' =>
                $approvedAt

        ]
    );


    $photoId =
        (int)$pdo->lastInsertId();


    /*
     * Audit log when available.
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
                    new_values,
                    ip_address,
                    user_agent
                )

                VALUES
                (
                    ?,
                    'profile_photo_upload',
                    'photo',
                    ?,
                    ?,
                    ?,
                    ?
                )
                "
            );


        $auditData =
            json_encode(
                [
                    'photo_type' =>
                        'profile',

                    'approval_status' =>
                        $approvalStatus,

                    'mime_type' =>
                        $mimeType,

                    'file_size' =>
                        (int)$file['size']
                ],
                JSON_UNESCAPED_UNICODE
            );


        $audit->execute(
            [
                $userId,

                $photoId,

                $auditData,

                $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                $_SERVER['HTTP_USER_AGENT']
                    ??
                    null
            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI PHOTO AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    /*
     * Remove files from disk if DB registration fails.
     */

    @unlink(
        $originalAbsolute
    );


    if (
        $thumbnailCreated
    ) {

        @unlink(
            $thumbnailAbsolute
        );

    }


    error_log(
        '[LOVEMI PHOTO DB INSERT] '
        .
        $e->getMessage()
    );


    respond(
        false,
        'The profile photo could not be registered in the database.',
        [
            'code' =>
                'PHOTO_DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

respond(
    true,
    $approvalStatus === 'approved'
        ? 'Your profile photo was uploaded successfully.'
        : 'Your profile photo was uploaded and sent for administrator approval.',
    [

        'photo' => [

            'id' =>
                $photoId,

            'file_name' =>
                $fileName,

            'file_path' =>
                $originalRelative,

            'thumbnail_path' =>
                $thumbnailRelative,

            'mime_type' =>
                $mimeType,

            'approval_status' =>
                $approvalStatus,

            'is_primary' =>
                true

        ],

        'photo_url' =>
            $thumbnailRelative,

        'profile_photo' =>
            $thumbnailRelative

    ]
);