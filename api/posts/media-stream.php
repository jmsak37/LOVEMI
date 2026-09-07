<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

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

    session_start();

}


header(
    'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);

header(
    'X-Content-Type-Options: nosniff'
);

header(
    'Cross-Origin-Resource-Policy: same-origin'
);


/* ============================================================
   AUTHENTICATION
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    http_response_code(
        401
    );

    exit;

}


/* ============================================================
   INPUT
============================================================ */

$postId =
    isset(
        $_GET['post_id']
    )
        ?
        (int)
        $_GET['post_id']
        :
        0;


$requestedUrl =
    trim(
        (string)(
            $_GET['media_url']
            ??
            ''
        )
    );


$requestedMediaId =
    isset(
        $_GET['media_id']
    )
        ?
        (int)
        $_GET['media_id']
        :
        0;


if (
    $postId <= 0
    ||
    (
        $requestedUrl === ''
        &&
        $requestedMediaId <= 0
    )
) {

    http_response_code(
        404
    );

    exit;

}


/* ============================================================
   ONLY ALLOW MEDIA RESOURCE REQUESTS
============================================================ */

$fetchDest =
    strtolower(
        trim(
            (string)(
                $_SERVER[
                    'HTTP_SEC_FETCH_DEST'
                ]
                ??
                ''
            )
        )
    );


if (
    $fetchDest !== ''
    &&
    !in_array(
        $fetchDest,
        [
            'image',
            'video'
        ],
        true
    )
) {

    http_response_code(
        403
    );

    exit;

}


/* ============================================================
   NEVER ALLOW DOWNLOAD MODE
============================================================ */

$downloadRequested =
    isset(
        $_GET['download']
    )
    &&
    in_array(
        strtolower(
            trim(
                (string)
                $_GET['download']
            )
        ),
        [
            '1',
            'true',
            'yes',
            'download'
        ],
        true
    );


if (
    $downloadRequested
) {

    http_response_code(
        403
    );

    exit;

}


/* ============================================================
   NORMALIZE MEDIA PATH
============================================================ */

function normalizeLovemiMediaPath(
    string $value
): string {

    $value =
        trim(
            $value
        );


    if (
        $value === ''
    ) {

        return '';

    }


    if (
        str_starts_with(
            $value,
            '/'
        )
    ) {

        $value =
            'http://localhost'
            .
            $value;

    }


    $parts =
        parse_url(
            $value
        );


    if (
        is_array(
            $parts
        )
        &&
        isset(
            $parts['path']
        )
    ) {

        $value =
            (string)
            $parts['path'];

    }


    $value =
        rawurldecode(
            $value
        );


    $value =
        str_replace(
            '\\',
            '/',
            $value
        );


    $value =
        preg_replace(
            '/\/{2,}/',
            '/',
            $value
        )
        ?:
        $value;


    $value =
        ltrim(
            $value,
            '/'
        );


    foreach (
        [
            'LOVEMI/',
            'lovemi/'
        ]
        as $prefix
    ) {

        if (
            str_starts_with(
                $value,
                $prefix
            )
        ) {

            $value =
                substr(
                    $value,
                    strlen(
                        $prefix
                    )
                );

            break;

        }

    }


    return ltrim(
        $value,
        '/'
    );

}


/* ============================================================
   SAFE PHYSICAL FILE
============================================================ */

function safeMediaFilePath(
    ?string $filePath
): array {

    $root =
        realpath(
            dirname(
                __DIR__,
                2
            )
        );


    if (
        !$root
        ||
        !$filePath
    ) {

        return [
            null,
            null
        ];

    }


    $relative =
        ltrim(
            str_replace(
                [
                    '\\',
                    "\0"
                ],
                [
                    '/',
                    ''
                ],
                (string)
                $filePath
            ),
            '/'
        );


    $candidate =
        $root
        .
        DIRECTORY_SEPARATOR
        .
        str_replace(
            '/',
            DIRECTORY_SEPARATOR,
            $relative
        );


    $resolved =
        realpath(
            $candidate
        );


    if (
        !$resolved
        ||
        !is_file(
            $resolved
        )
        ||
        !str_starts_with(
            $resolved,
            $root
            .
            DIRECTORY_SEPARATOR
        )
    ) {

        return [
            null,
            null
        ];

    }


    return [
        $resolved,
        $root
    ];

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();


    /* ========================================================
       POST
    ======================================================== */

    $postStmt =
        $pdo->prepare(
            '
            SELECT
                p.id,
                p.user_id,
                p.visibility,
                p.approval_status AS post_approval,
                p.deleted_at
            FROM posts p
            WHERE p.id = :post_id
            LIMIT 1
            '
        );


    $postStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $postStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$post
        ||
        $post['deleted_at'] !== null
    ) {

        http_response_code(
            404
        );

        exit;

    }


    $ownerId =
        (int)
        $post['user_id'];


    $isOwner =
        $ownerId ===
        $currentUserId;


    /*
     * Other members may only access approved public posts.
     */

    if (
        !$isOwner
        &&
        (
            (string)
            $post['post_approval']
            !==
            'approved'
            ||
            (string)
            $post['visibility']
            !==
            'public'
        )
    ) {

        http_response_code(
            403
        );

        exit;

    }


    /* ========================================================
       POST MEDIA
    ======================================================== */

    $mediaStmt =
        $pdo->prepare(
            '
            SELECT
                ph.id AS media_id,
                ph.file_name,
                ph.file_path,
                ph.mime_type,
                ph.approval_status,
                pp.display_order
            FROM post_photos pp
            INNER JOIN photos ph
                ON ph.id = pp.photo_id
            WHERE pp.post_id = :post_id
            ORDER BY
                pp.display_order ASC,
                pp.id ASC
            '
        );


    $mediaStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $mediaRows =
        $mediaStmt->fetchAll(
            PDO::FETCH_ASSOC
        );


    $selected =
        null;


    $normalizedRequested =
        normalizeLovemiMediaPath(
            $requestedUrl
        );


    foreach (
        $mediaRows
        as $media
    ) {

        if (
            (string)
            $media['approval_status']
            !==
            'approved'
            &&
            !$isOwner
        ) {

            continue;

        }


        if (
            $requestedMediaId > 0
            &&
            (int)
            $media['media_id']
            ===
            $requestedMediaId
        ) {

            $selected =
                $media;

            break;

        }


        if (
            $normalizedRequested !== ''
        ) {

            $normalizedStored =
                normalizeLovemiMediaPath(
                    (string)
                    $media['file_path']
                );


            if (
                $normalizedStored !== ''
                &&
                hash_equals(
                    $normalizedStored,
                    $normalizedRequested
                )
            ) {

                $selected =
                    $media;

                break;

            }

        }

    }


    if (
        !$selected
    ) {

        http_response_code(
            404
        );

        exit;

    }


    /* ========================================================
       ONLY IMAGE / VIDEO
    ======================================================== */

    $mime =
        strtolower(
            trim(
                (string)(
                    $selected['mime_type']
                    ??
                    ''
                )
            )
        );


    if (
        !str_starts_with(
            $mime,
            'image/'
        )
        &&
        !str_starts_with(
            $mime,
            'video/'
        )
    ) {

        http_response_code(
            403
        );

        exit;

    }


    /* ========================================================
       PHYSICAL FILE
    ======================================================== */

    [
        $path,
        $root
    ] =
        safeMediaFilePath(
            (string)
            $selected['file_path']
        );


    if (
        !$path
        ||
        !$root
    ) {

        http_response_code(
            404
        );

        exit;

    }


    $size =
        filesize(
            $path
        );


    if (
        $size === false
        ||
        $size <= 0
    ) {

        http_response_code(
            404
        );

        exit;

    }


    /* ========================================================
       FILE NAME
    ======================================================== */

    $fileName =
        preg_replace(
            '/[^A-Za-z0-9._-]+/',
            '-',
            (string)(
                $selected['file_name']
                ??
                'lovemi-media'
            )
        )
        ?:
        'lovemi-media';


    /* ========================================================
       RANGE
    ======================================================== */

    $start =
        0;


    $end =
        $size - 1;


    $partial =
        false;


    $rangeHeader =
        trim(
            (string)(
                $_SERVER[
                    'HTTP_RANGE'
                ]
                ??
                ''
            )
        );


    if (
        $rangeHeader !== ''
    ) {

        if (
            !preg_match(
                '/bytes=(\d*)-(\d*)/i',
                $rangeHeader,
                $match
            )
        ) {

            header(
                'Content-Range: bytes */'
                .
                $size
            );

            http_response_code(
                416
            );

            exit;

        }


        if (
            $match[1] !== ''
        ) {

            $start =
                (int)
                $match[1];

        }


        if (
            $match[2] !== ''
        ) {

            $end =
                (int)
                $match[2];

        }


        if (
            $match[1] === ''
            &&
            $match[2] !== ''
        ) {

            $suffix =
                (int)
                $match[2];


            if (
                $suffix <= 0
            ) {

                header(
                    'Content-Range: bytes */'
                    .
                    $size
                );

                http_response_code(
                    416
                );

                exit;

            }


            $start =
                max(
                    0,
                    $size - $suffix
                );


            $end =
                $size - 1;

        }


        if (
            $start < 0
            ||
            $start > $end
            ||
            $start >= $size
        ) {

            header(
                'Content-Range: bytes */'
                .
                $size
            );

            http_response_code(
                416
            );

            exit;

        }


        $end =
            min(
                $end,
                $size - 1
            );


        $partial =
            true;

    }


    $length =
        $end
        -
        $start
        +
        1;


    /* ========================================================
       RESPONSE HEADERS
    ======================================================== */

    header(
        'Content-Type: '
        .
        (
            $mime
            ?:
            'application/octet-stream'
        )
    );


    header(
        'Content-Length: '
        .
        $length
    );


    if (
        str_starts_with(
            $mime,
            'video/'
        )
    ) {

        header(
            'Accept-Ranges: bytes'
        );

    }


    /*
     * Always inline.
     * Never return Content-Disposition: attachment.
     */

    header(
        'Content-Disposition: inline; filename="'
        .
        $fileName
        .
        '"'
    );


    header(
        'Content-Security-Policy: default-src \'none\'; media-src \'self\'; img-src \'self\' data:; style-src \'unsafe-inline\''
    );


    if (
        $partial
    ) {

        http_response_code(
            206
        );


        header(
            'Content-Range: bytes '
            .
            $start
            .
            '-'
            .
            $end
            .
            '/'
            .
            $size
        );

    }


    /* ========================================================
       STREAM
    ======================================================== */

    $fp =
        fopen(
            $path,
            'rb'
        );


    if (
        !$fp
    ) {

        http_response_code(
            404
        );

        exit;

    }


    fseek(
        $fp,
        $start
    );


    $remaining =
        $length;


    while (
        $remaining > 0
        &&
        !feof(
            $fp
        )
    ) {

        $chunk =
            fread(
                $fp,
                min(
                    1024 * 1024,
                    $remaining
                )
            );


        if (
            $chunk === false
            ||
            $chunk === ''
        ) {

            break;

        }


        echo $chunk;


        $remaining -=
            strlen(
                $chunk
            );


        if (
            function_exists(
                'ob_flush'
            )
        ) {

            @ob_flush();

        }


        flush();

    }


    fclose(
        $fp
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI MEDIA STREAM] '
        .
        $e->getMessage()
        .
        ' | FILE='
        .
        $e->getFile()
        .
        ' | LINE='
        .
        $e->getLine()
    );


    http_response_code(
        404
    );

    exit;

}