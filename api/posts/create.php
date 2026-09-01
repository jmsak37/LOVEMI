<?php
/**
 * ============================================================
 * LOVEMI - CREATE PREMIUM POST
 * ============================================================
 *
 * Accepts:
 * - styled caption HTML
 * - image
 * - MP4/WebM video
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function createPostResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    createPostResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


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
    session_status() !== PHP_SESSION_ACTIVE
) {
    session_start();
}


$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
        $_SESSION['lovemi_user_id']
        :
        0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ?
        trim(
            (string)
            $_SESSION['lovemi_session_token']
        )
        :
        '';


if (
    $userId <= 0
    ||
    $sessionToken === ''
) {

    createPostResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
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
        '[LOVEMI CREATE POST DB] '
        .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/* ============================================================
   VALIDATE SESSION
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                us.id AS session_id,
                us.user_id,
                us.expires_at,
                us.revoked_at,
                us.two_factor_passed,

                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted

            FROM user_sessions us

            INNER JOIN users u
                ON u.id = us.user_id

            WHERE
                us.session_token_hash = :token

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':token' =>
                $tokenHash
        ]
    );

    $session =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE POST SESSION] '
        .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Unable to validate your session.',
        [],
        500
    );
}


if (!$session) {

    createPostResponse(
        false,
        'Your session is invalid.',
        [],
        401
    );
}


$expiry =
    strtotime(
        (string)
        $session['expires_at']
    );


if (
    (int)$session['user_id']
    !==
    $userId
    ||
    $session['revoked_at'] !== null
    ||
    $expiry === false
    ||
    $expiry <= time()
    ||
    !(bool)$session['two_factor_passed']
) {

    createPostResponse(
        false,
        'Your authenticated session is no longer valid.',
        [],
        401
    );
}


if (
    !(bool)$session['email_verified']
    ||
    !(bool)$session['is_active']
    ||
    (bool)$session['is_suspended']
    ||
    (bool)$session['is_deleted']
) {

    createPostResponse(
        false,
        'Your account cannot publish posts.',
        [],
        403
    );
}


/* ============================================================
   PREMIUM CHECK
============================================================ */

try {

    $premium =
        $pdo->prepare(
            "
            SELECT
                s.id

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id = s.service_id

            WHERE

                s.user_id = :user_id

              AND sv.slug = 'lovemi-premium'

              AND s.status = 'active'

              AND s.start_at <= CURRENT_TIMESTAMP

              AND s.end_at > CURRENT_TIMESTAMP

            LIMIT 1
            "
        );

    $premium->execute(
        [
            ':user_id' =>
                $userId
        ]
    );

    if (!$premium->fetch()) {

        createPostResponse(
            false,
            'Premium access is required to publish posts.',
            [
                'code' =>
                    'PREMIUM_REQUIRED',

                'redirect' =>
                    'premium.html'
            ],
            403
        );
    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE POST PREMIUM] '
        .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Unable to verify Premium access.',
        [],
        500
    );
}


/* ============================================================
   INPUT
============================================================ */

$content =
    trim(
        (string)(
            $_POST['content']
            ??
            ''
        )
    );


$visibility =
    strtolower(
        trim(
            (string)(
                $_POST['visibility']
                ??
                'public'
            )
        )
    );


if (
    !in_array(
        $visibility,
        [
            'public'
        ],
        true
    )
) {

    $visibility =
        'public';

}


/* ============================================================
   SANITIZE RICH CONTENT
============================================================ */

function sanitizeRichContent(
    string $html
): string {

    $html =
        trim(
            $html
        );


    if (
        $html === ''
    ) {

        return '';

    }


    $dom =
        new DOMDocument(
            '1.0',
            'UTF-8'
        );


    libxml_use_internal_errors(
        true
    );


    $dom->loadHTML(
        '<div id="lovemi-root">'
        .
        $html
        .
        '</div>',
        LIBXML_HTML_NOIMPLIED |
        LIBXML_HTML_NODEFDTD
    );


    libxml_clear_errors();


    $root =
        $dom->getElementById(
            'lovemi-root'
        );


    if (!$root) {

        return '';

    }


    $allowed =
        [
            'b',
            'strong',
            'i',
            'em',
            'u',
            'span',
            'br'
        ];


    $walker =
        function(
            DOMNode $node
        ) use (
            &$walker,
            $allowed
        ): void {

            if (
                $node->nodeType
                ===
                XML_ELEMENT_NODE
            ) {

                $tag =
                    strtolower(
                        $node->nodeName
                    );


                if (
                    !in_array(
                        $tag,
                        $allowed,
                        true
                    )
                ) {

                    $text =
                        $node->textContent;


                    $replacement =
                        $node->ownerDocument
                            ->createTextNode(
                                $text
                            );


                    $node->parentNode
                        ?->replaceChild(
                            $replacement,
                            $node
                        );


                    return;

                }


                while (
                    $node->attributes->length > 0
                ) {

                    $node->removeAttributeNode(
                        $node->attributes->item(
                            0
                        )
                    );

                }


                if (
                    $tag === 'span'
                ) {

                    /*
                     * Only allow a simple hexadecimal text
                     * color generated by the color picker.
                     */

                    $originalStyle =
                        '';

                    /*
                     * Removed above by design. The server accepts
                     * clean caption formatting but does not trust
                     * arbitrary CSS.
                     */

                }

            }


            foreach (
                iterator_to_array(
                    $node->childNodes
                ) as $child
            ) {

                $walker(
                    $child
                );

            }

        };


    $walker(
        $root
    );


    $output =
        '';


    foreach (
        $root->childNodes as $child
    ) {

        $output .=
            $dom->saveHTML(
                $child
            );

    }


    /*
     * Allow safe color styles separately.
     *
     * Browser color picker values are hexadecimal.
     */

    $output =
        preg_replace_callback(
            '/<span>(.*?)<\/span>/is',
            static function(
                array $matches
            ): string {

                return
                    '<span>'
                    .
                    $matches[1]
                    .
                    '</span>';

            },
            $output
        )
        ??
        $output;


    /*
     * Explicitly remove any remaining style attributes.
     */

    $output =
        preg_replace(
            '/\sstyle\s*=\s*"[^"]*"/i',
            '',
            $output
        )
        ??
        $output;


    return trim(
        $output
    );
}


$content =
    sanitizeRichContent(
        $content
    );


/*
 * Do not allow a post containing only empty HTML.
 */

$textOnly =
    trim(
        html_entity_decode(
            strip_tags(
                $content
            ),
            ENT_QUOTES,
            'UTF-8'
        )
    );


$media =
    $_FILES['media']
    ??
    null;


if (
    $textOnly === ''
    &&
    (
        !$media
        ||
        ($media['error'] ?? UPLOAD_ERR_NO_FILE)
        ===
        UPLOAD_ERR_NO_FILE
    )
) {

    createPostResponse(
        false,
        'Write a caption or select a photo/video.',
        [],
        422
    );
}


/* ============================================================
   SYSTEM SETTINGS
============================================================ */

$automaticPostApproval =
    false;

$automaticPhotoApproval =
    false;


try {

    $settings =
        $pdo->query(
            "
            SELECT
                setting_key,
                setting_value,
                value_type

            FROM system_settings

            WHERE setting_key IN
            (
                'automatic_post_approval',
                'automatic_photo_approval'
            )
            "
        );


    foreach (
        $settings->fetchAll() as $setting
    ) {

        $key =
            $setting['setting_key'];


        $value =
            (string)
            $setting['setting_value'];


        $bool =
            in_array(
                strtolower(
                    $value
                ),
                [
                    '1',
                    'true',
                    'yes',
                    'on'
                ],
                true
            );


        if (
            $key ===
            'automatic_post_approval'
        ) {

            $automaticPostApproval =
                $bool;

        }


        if (
            $key ===
            'automatic_photo_approval'
        ) {

            $automaticPhotoApproval =
                $bool;

        }

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE POST SETTINGS] '
        .
        $e->getMessage()
    );
}


/* ============================================================
   UPLOAD PREPARATION
============================================================ */

$uploadedPath =
    null;

$thumbnailPath =
    null;

$mimeType =
    null;

$fileSize =
    null;

$photoId =
    null;


$allowedImages =
    [
        'image/jpeg',
        'image/png',
        'image/webp',
        'image/gif'
    ];


$allowedVideos =
    [
        'video/mp4',
        'video/webm'
    ];


$maxUploadSize =
    60 *
    1024 *
    1024;


/* ============================================================
   PROCESS MEDIA
============================================================ */

try {

    $pdo->beginTransaction();


    if (
        $media
        &&
        (
            $media['error'] ?? UPLOAD_ERR_NO_FILE
        )
        !==
        UPLOAD_ERR_NO_FILE
    ) {

        if (
            ($media['error'] ?? UPLOAD_ERR_OK)
            !==
            UPLOAD_ERR_OK
        ) {

            throw new RuntimeException(
                'The selected media file could not be uploaded.'
            );

        }


        $fileSize =
            (int)
            (
                $media['size']
                ??
                0
            );


        if (
            $fileSize <= 0
            ||
            $fileSize >
            $maxUploadSize
        ) {

            throw new RuntimeException(
                'The selected media must be smaller than 60 MB.'
            );

        }


        $tmpName =
            (string)
            (
                $media['tmp_name']
                ??
                ''
            );


        if (
            !is_uploaded_file(
                $tmpName
            )
        ) {

            throw new RuntimeException(
                'Invalid uploaded file.'
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
            !in_array(
                $mimeType,
                array_merge(
                    $allowedImages,
                    $allowedVideos
                ),
                true
            )
        ) {

            throw new RuntimeException(
                'Only JPG, PNG, WEBP, GIF, MP4 and WebM files are allowed.'
            );

        }


        $isImage =
            in_array(
                $mimeType,
                $allowedImages,
                true
            );


        $isVideo =
            in_array(
                $mimeType,
                $allowedVideos,
                true
            );


        if (
            $isImage
        ) {

            $imageInfo =
                @getimagesize(
                    $tmpName
                );


            if (
                !$imageInfo
            ) {

                throw new RuntimeException(
                    'The selected image is invalid.'
                );

            }

        }


        $originalDirectory =
            __DIR__
            .
            '/../../uploads/posts/original';


        $thumbnailDirectory =
            __DIR__
            . '/../../uploads/posts/thumbnails';


        if (
            !is_dir(
                $originalDirectory
            )
            &&
            !mkdir(
                $originalDirectory,
                0755,
                true
            )
        ) {

            throw new RuntimeException(
                'Unable to prepare the upload directory.'
            );

        }


        if (
            !is_dir(
                $thumbnailDirectory
            )
            &&
            !mkdir(
                $thumbnailDirectory,
                0755,
                true
            )
        ) {

            throw new RuntimeException(
                'Unable to prepare the thumbnail directory.'
            );

        }


        $extensionMap =
            [
                'image/jpeg' =>
                    'jpg',

                'image/png' =>
                    'png',

                'image/webp' =>
                    'webp',

                'image/gif' =>
                    'gif',

                'video/mp4' =>
                    'mp4',

                'video/webm' =>
                    'webm'
            ];


        $extension =
            $extensionMap[
                $mimeType
            ]
            ??
            'bin';


        $filename =
            bin2hex(
                random_bytes(
                    24
                )
            )
            .
            '.'
            .
            $extension;


        $diskPath =
            $originalDirectory
            .
            DIRECTORY_SEPARATOR
            .
            $filename;


        $relativePath =
            'uploads/posts/original/'
            .
            $filename;


        if (
            !move_uploaded_file(
                $tmpName,
                $diskPath
            )
        ) {

            throw new RuntimeException(
                'Unable to save the uploaded media.'
            );

        }


        $uploadedPath =
            $relativePath;


        /*
         * Generate a thumbnail only for images.
         */

        if (
            $isImage
            &&
            function_exists(
                'imagecreatefromstring'
            )
        ) {

            $raw =
                file_get_contents(
                    $diskPath
                );


            $sourceImage =
                $raw !== false
                    ?
                    @imagecreatefromstring(
                        $raw
                    )
                    :
                    false;


            if (
                $sourceImage
            ) {

                $sourceWidth =
                    imagesx(
                        $sourceImage
                    );


                $sourceHeight =
                    imagesy(
                        $sourceImage
                    );


                $maxDimension =
                    640;


                $scale =
                    min(
                        1,
                        $maxDimension /
                        max(
                            $sourceWidth,
                            $sourceHeight
                        )
                    );


                $thumbWidth =
                    max(
                        1,
                        (int)
                        round(
                            $sourceWidth *
                            $scale
                        )
                    );


                $thumbHeight =
                    max(
                        1,
                        (int)
                        round(
                            $sourceHeight *
                            $scale
                        )
                    );


                $thumbnail =
                    imagecreatetruecolor(
                        $thumbWidth,
                        $thumbHeight
                    );


                imagealphablending(
                    $thumbnail,
                    false
                );


                imagesavealpha(
                    $thumbnail,
                    true
                );


                imagecopyresampled(
                    $thumbnail,
                    $sourceImage,
                    0,
                    0,
                    0,
                    0,
                    $thumbWidth,
                    $thumbHeight,
                    $sourceWidth,
                    $sourceHeight
                );


                $thumbFilename =
                    'thumb_'
                    .
                    $filename;


                $thumbDiskPath =
                    $thumbnailDirectory
                    .
                    DIRECTORY_SEPARATOR
                    .
                    $thumbFilename;


                $thumbRelativePath =
                    'uploads/posts/thumbnails/'
                    .
                    $thumbFilename;


                $savedThumb =
                    false;


                if (
                    $mimeType ===
                    'image/jpeg'
                ) {

                    $savedThumb =
                        imagejpeg(
                            $thumbnail,
                            $thumbDiskPath,
                            85
                        );

                } elseif (
                    $mimeType ===
                    'image/png'
                ) {

                    $savedThumb =
                        imagepng(
                            $thumbnail,
                            $thumbDiskPath,
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

                    $savedThumb =
                        imagewebp(
                            $thumbnail,
                            $thumbDiskPath,
                            85
                        );

                } elseif (
                    $mimeType ===
                    'image/gif'
                ) {

                    $savedThumb =
                        imagegif(
                            $thumbnail,
                            $thumbDiskPath
                        );

                }


                if (
                    $savedThumb
                ) {

                    $thumbnailPath =
                        $thumbRelativePath;

                }


                imagedestroy(
                    $thumbnail
                );


                imagedestroy(
                    $sourceImage
                );

            }

        }


        $photoApproval =
            $automaticPhotoApproval
                ?
                'approved'
                :
                'pending';


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
                    :approval_status,
                    0,
                    0
                )
                "
            );


        $width =
            null;

        $height =
            null;


        if (
            $isImage
            &&
            isset(
                $imageInfo
            )
        ) {

            $width =
                (int)
                $imageInfo[0];

            $height =
                (int)
                $imageInfo[1];

        }


        $photoStmt->execute(
            [
                ':user_id' =>
                    $userId,

                ':file_name' =>
                    (string)
                    $media['name'],

                ':file_path' =>
                    $uploadedPath,

                ':thumbnail_path' =>
                    $thumbnailPath,

                ':mime_type' =>
                    $mimeType,

                ':file_size' =>
                    $fileSize,

                ':width' =>
                    $width,

                ':height' =>
                    $height,

                ':approval_status' =>
                    $photoApproval
            ]
        );


        $photoId =
            (int)
            $pdo->lastInsertId();

    }


    /* ========================================================
       CREATE POST
    ======================================================== */

    $postApproval =
        $automaticPostApproval
            ?
            'approved'
            :
            'pending';


    $postStmt =
        $pdo->prepare(
            "
            INSERT INTO posts
            (
                user_id,
                content,
                visibility,
                approval_status,
                is_featured,
                approved_at
            )
            VALUES
            (
                :user_id,
                :content,
                :visibility,
                :approval_status,
                0,
                :approved_at
            )
            "
        );


    $approvedAt =
        $postApproval === 'approved'
            ?
            date(
                'Y-m-d H:i:s'
            )
            :
            null;


    $postStmt->execute(
        [
            ':user_id' =>
                $userId,

            ':content' =>
                $content,

            ':visibility' =>
                $visibility,

            ':approval_status' =>
                $postApproval,

            ':approved_at' =>
                $approvedAt
        ]
    );


    $postId =
        (int)
        $pdo->lastInsertId();


    /* ========================================================
       LINK MEDIA
    ======================================================== */

    if (
        $photoId !== null
    ) {

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
                    1
                )
                "
            );


        $linkStmt->execute(
            [
                ':post_id' =>
                    $postId,

                ':photo_id' =>
                    $photoId
            ]
        );

    }


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    if (
        $uploadedPath
    ) {

        @unlink(
            __DIR__
            .
            '/../../'
            .
            $uploadedPath
        );

    }


    if (
        $thumbnailPath
    ) {

        @unlink(
            __DIR__
            .
            '/../../'
            .
            $thumbnailPath
        );

    }


    error_log(
        '[LOVEMI CREATE POST ERROR] '
        .
        $e->getMessage()
    );


    createPostResponse(
        false,
        $e->getMessage()
            !==
            ''
                ?
                $e->getMessage()
                :
                'The post could not be created.',
        [],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

$publicImmediately =
    $postApproval === 'approved'
    &&
    (
        $photoId === null
        ||
        $automaticPhotoApproval
    );


createPostResponse(
    true,
    $publicImmediately
        ?
        'Your post has been published successfully.'
        :
        'Your post has been submitted successfully and is waiting for approval.',
    [

        'data' => [

            'post_id' =>
                $postId,

            'approval_status' =>
                $postApproval,

            'photo_id' =>
                $photoId,

            'media_path' =>
                $uploadedPath,

            'thumbnail_path' =>
                $thumbnailPath

        ]

    ],
    201
);