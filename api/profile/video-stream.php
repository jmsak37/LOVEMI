<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

$viewerId = profileRequireAuth();
$pdo = profileDb();

$code = trim((string)($_GET['code'] ?? ''));
$mediaId = (int)($_GET['media'] ?? 0);

if ($code === '' || $mediaId <= 0) {
    http_response_code(404);
    exit;
}

/*
 * Only allow the browser to request this endpoint as a video/media
 * resource. A normal page navigation must not receive the video file.
 *
 * Browsers that support Fetch Metadata send:
 *   Sec-Fetch-Dest: video
 *
 * If the header is present and is not "video", reject the request.
 * This does not alter normal HTML5 video streaming.
 */
$fetchDest = strtolower(
    trim((string)($_SERVER['HTTP_SEC_FETCH_DEST'] ?? ''))
);

if ($fetchDest !== '' && $fetchDest !== 'video') {
    http_response_code(403);
    exit;
}

/*
 * Do not allow normal browser navigation to open the stream directly.
 * A normal video element request uses Range for efficient streaming.
 */
$rangeHeader = trim((string)($_SERVER['HTTP_RANGE'] ?? ''));

if ($rangeHeader === '') {
    http_response_code(403);
    exit;
}

try {

    $request = resolveProfileRequest(
        $pdo,
        $viewerId
    );

    if (
        empty($request['code'])
        || !hash_equals(
            (string)$request['code'],
            $code
        )
    ) {
        http_response_code(403);
        exit;
    }

    $targetId =
        (int)(
            $request['user_id']
            ?? 0
        );

    $isOwner =
        (bool)(
            $request['is_owner']
            ?? false
        );

    if ($targetId <= 0) {
        http_response_code(403);
        exit;
    }

    /*
     * Find the video through the post relationship.
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            ph.id,
            ph.file_path,
            ph.mime_type,
            ph.approval_status,
            ph.user_id,
            p.id AS post_id,
            p.visibility,
            p.approval_status AS post_approval,
            p.deleted_at
        FROM photos ph
        INNER JOIN post_photos pp
            ON pp.photo_id = ph.id
        INNER JOIN posts p
            ON p.id = pp.post_id
        WHERE ph.id = :media
          AND ph.user_id = :user_id
          AND LOWER(
                ph.mime_type
              ) LIKE 'video/%'
          AND p.user_id = :post_user_id
        LIMIT 1
        "
    );

    $stmt->execute(
        [
            ':media' =>
                $mediaId,

            ':user_id' =>
                $targetId,

            ':post_user_id' =>
                $targetId
        ]
    );

    $row =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

    if (
        !$row
        || (string)(
            $row['approval_status']
            ?? ''
        ) !== 'approved'
        || $row['deleted_at'] !== null
    ) {
        http_response_code(404);
        exit;
    }

    /*
     * Other members may only stream approved public posts.
     */
    if (
        !$isOwner
        &&
        (
            (string)(
                $row['post_approval']
                ?? ''
            ) !== 'approved'
            ||
            (string)(
                $row['visibility']
                ?? ''
            ) !== 'public'
        )
    ) {
        http_response_code(403);
        exit;
    }

    /*
     * Resolve the physical file safely.
     */
    $root =
        realpath(
            dirname(
                __DIR__,
                2
            )
        );

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
                (string)(
                    $row['file_path']
                    ?? ''
                )
            ),
            '/'
        );

    $candidate =
        $root
        . DIRECTORY_SEPARATOR
        . str_replace(
            '/',
            DIRECTORY_SEPARATOR,
            $relative
        );

    $path =
        realpath(
            $candidate
        );

    if (
        !$root
        || !$path
        || !str_starts_with(
            $path,
            $root
        )
        || !is_file($path)
    ) {
        http_response_code(404);
        exit;
    }

    $size =
        filesize(
            $path
        );

    if (
        $size === false
        || $size <= 0
    ) {
        http_response_code(404);
        exit;
    }

    $mime =
        (string)(
            $row['mime_type']
            ?? 'video/mp4'
        );

    $start =
        0;

    $end =
        $size - 1;

    $partial =
        false;

    /*
     * Range requests are required by HTML5 video playback
     * for seeking and efficient streaming.
     */
    if (
        preg_match(
            '/bytes=(\d*)-(\d*)/i',
            $rangeHeader,
            $match
        )
    ) {

        if (
            $match[1] !== ''
        ) {
            $start =
                (int)$match[1];
        }

        if (
            $match[2] !== ''
        ) {
            $end =
                (int)$match[2];
        }

        if (
            $match[1] === ''
            && $match[2] !== ''
        ) {
            $suffix =
                (int)$match[2];

            $start =
                max(
                    0,
                    $size - $suffix
                );

            $end =
                $size - 1;
        }

        if (
            $start > $end
            || $start >= $size
        ) {
            header(
                'Content-Range: bytes */'
                . $size
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

        http_response_code(
            206
        );
    }

    $length =
        $end
        - $start
        + 1;

    header(
        'Content-Type: '
        . (
            $mime
            ?: 'video/mp4'
        )
    );

    header(
        'Content-Length: '
        . $length
    );

    header(
        'Accept-Ranges: bytes'
    );

    /*
     * Inline playback rather than forcing a download.
     */
    header(
        'Content-Disposition: inline; filename="lovemi-video-'
        . $mediaId
        . '.mp4"'
    );

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

    if ($partial) {
        header(
            'Content-Range: bytes '
            . $start
            . '-'
            . $end
            . '/'
            . $size
        );
    }

    $fp =
        fopen(
            $path,
            'rb'
        );

    if (!$fp) {
        http_response_code(404);
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
        && !feof($fp)
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
            || $chunk === ''
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIDEO STREAM] '
        . $e->getMessage()
        . ' | FILE='
        . $e->getFile()
        . ' | LINE='
        . $e->getLine()
    );

    http_response_code(
        404
    );
}