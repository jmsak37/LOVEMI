<?php
/**
 * ============================================================
 * LOVEMI - DOWNLOAD INDEX PROTECTOR
 * ============================================================
 *
 * Streams approved LOVEMI images/videos through a controlled
 * endpoint instead of exposing the physical upload path.
 *
 * Important:
 * Browser JavaScript and HTTP headers cannot guarantee that a
 * person cannot save media or take a screenshot. This endpoint
 * reduces direct-link exposure and disables normal inline-page
 * download affordances where the browser allows it.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/api/profile/_helper.php';

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('X-Download-Options: noopen');
header('Referrer-Policy: same-origin');
header('Content-Disposition: inline');
header('Permissions-Policy: camera=(), microphone=(), geolocation=()');

function protectorFail(int $status = 404): never
{
    http_response_code($status);
    header('Content-Type: text/plain; charset=utf-8');
    exit;
}

if (strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET')) !== 'GET') {
    protectorFail(405);
}

/*
 * The homepage is public, so media must be viewable by guests when
 * the underlying post/profile is approved and public. When a LOVEMI
 * session exists, the owner is also allowed to view their own media.
 *
 * Do not call profileRequireAuth() here because that would make the
 * public index unable to display its approved media cards.
 */
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$currentUserId = (int)(
    $_SESSION['user_id']
    ?? $_SESSION['lovemi_user_id']
    ?? $_SESSION['auth_user_id']
    ?? $_SESSION['authenticated_user_id']
    ?? 0
);

$photoId = (int)($_GET['photo_id'] ?? 0);
$variant = strtolower(trim((string)($_GET['variant'] ?? 'original')));

if ($photoId <= 0) {
    protectorFail(404);
}

if (!in_array($variant, ['original', 'thumbnail'], true)) {
    $variant = 'original';
}

try {
    $pdo = profileDb();

    $stmt = $pdo->prepare(
        '
        SELECT
            ph.id,
            ph.user_id,
            ph.file_path,
            ph.thumbnail_path,
            ph.mime_type,
            ph.photo_type,
            ph.approval_status,
            ph.is_primary,
                p.id AS post_id,
            p.user_id AS post_user_id,
            p.visibility AS post_visibility,
            p.approval_status AS post_approval_status,
            p.deleted_at AS post_deleted_at,
            pr.profile_visibility
        FROM photos ph
        LEFT JOIN post_photos pp
            ON pp.photo_id = ph.id
        LEFT JOIN posts p
            ON p.id = pp.post_id
        LEFT JOIN profiles pr
            ON pr.user_id = ph.user_id
        WHERE ph.id = :photo_id
        LIMIT 1
        '
    );

    $stmt->execute([
        ':photo_id' => $photoId,
    ]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        protectorFail(404);
    }

    $ownerId = (int)$row['user_id'];
    $isOwner = $ownerId === $currentUserId;

    if (!$isOwner) {
        if (strtolower((string)($row['approval_status'] ?? '')) !== 'approved') {
            protectorFail(403);
        }

        /* Post media requires an approved public post. */
        if ((int)($row['post_id'] ?? 0) > 0) {
            if (!empty($row['post_deleted_at'])) {
                protectorFail(404);
            }

            if (strtolower((string)($row['post_approval_status'] ?? '')) !== 'approved') {
                protectorFail(403);
            }

            if (strtolower((string)($row['post_visibility'] ?? 'public')) !== 'public') {
                protectorFail(403);
            }
        } else {
            /* Profile photo must belong to a public profile. */
            if (
                isset($row['profile_visibility'])
                && strtolower((string)$row['profile_visibility']) !== 'public'
            ) {
                protectorFail(403);
            }
        }
    }

    $mimeType = strtolower(trim((string)($row['mime_type'] ?? '')));

    if (
        !str_starts_with($mimeType, 'image/')
        && !str_starts_with($mimeType, 'video/')
    ) {
        protectorFail(415);
    }

    $relativePath = $variant === 'thumbnail'
        ? trim((string)($row['thumbnail_path'] ?? ''))
        : trim((string)($row['file_path'] ?? ''));

    if ($relativePath === '' && $variant === 'thumbnail') {
        $relativePath = trim((string)($row['file_path'] ?? ''));
    }

    if ($relativePath === '') {
        protectorFail(404);
    }

    /* --------------------------------------------------------
       Normalize old rows containing physical Windows paths.
    -------------------------------------------------------- */
    $relativePath = str_replace('\\', '/', $relativePath);

    if (preg_match('~^.*?/LOVEMI/(uploads/.*)$~i', $relativePath, $match)) {
        $relativePath = $match[1];
    } elseif (preg_match('~^.*?/LOVEMI/(assets/.*)$~i', $relativePath, $match)) {
        $relativePath = $match[1];
    }

    $relativePath = ltrim($relativePath, '/');

    /* Only media stored below these web application folders is served. */
    if (
        !str_starts_with(strtolower($relativePath), 'uploads/')
        && !str_starts_with(strtolower($relativePath), 'assets/')
    ) {
        protectorFail(403);
    }

    $root = realpath(__DIR__);
    $candidate = realpath(__DIR__ . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath));

    if ($root === false || $candidate === false || !is_file($candidate)) {
        protectorFail(404);
    }

    $uploadsRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'uploads');
    $assetsRoot = realpath(__DIR__ . DIRECTORY_SEPARATOR . 'assets');

    $allowed = false;

    foreach ([$uploadsRoot, $assetsRoot] as $allowedRoot) {
        if ($allowedRoot === false) {
            continue;
        }

        $prefix = rtrim($allowedRoot, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;

        if (str_starts_with($candidate, $prefix)) {
            $allowed = true;
            break;
        }
    }

    if (!$allowed) {
        protectorFail(403);
    }

    $size = filesize($candidate);

    if ($size === false || $size < 1) {
        protectorFail(404);
    }

    $downloadName = preg_replace(
        '/[^A-Za-z0-9._-]/',
        '_',
        (string)($row['id'] ?? 'media')
        . '-lovemi-media'
        . (str_starts_with($mimeType, 'video/') ? '.mp4' : '.img')
    );

    header('Content-Type: ' . $mimeType);
    header('Content-Length: ' . (string)$size);
    header('Content-Disposition: inline; filename="' . $downloadName . '"');
    header('Accept-Ranges: bytes');

    /* --------------------------------------------------------
       Support byte ranges for normal browser video playback.
       This is playback support, not a guarantee against saving.
    -------------------------------------------------------- */
    $start = 0;
    $end = $size - 1;
    $status = 200;

    $rangeHeader = trim((string)($_SERVER['HTTP_RANGE'] ?? ''));

    if ($rangeHeader !== '' && preg_match('/bytes=(\d*)-(\d*)/i', $rangeHeader, $rangeMatch)) {
        $requestedStart = $rangeMatch[1] !== '' ? (int)$rangeMatch[1] : 0;
        $requestedEnd = $rangeMatch[2] !== '' ? (int)$rangeMatch[2] : $end;

        if ($rangeMatch[1] === '' && $rangeMatch[2] !== '') {
            $suffixLength = (int)$rangeMatch[2];
            if ($suffixLength > 0) {
                $requestedStart = max(0, $size - $suffixLength);
            }
            $requestedEnd = $end;
        }

        $start = max(0, $requestedStart);
        $end = min($end, max($start, $requestedEnd));

        if ($start > $end || $start >= $size) {
            header('Content-Range: bytes */' . (string)$size);
            protectorFail(416);
        }

        $status = 206;
        $length = $end - $start + 1;

        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        header('Content-Length: ' . (string)$length);
    }

    while (ob_get_level() > 0) {
        ob_end_clean();
    }

    $handle = fopen($candidate, 'rb');

    if ($handle === false) {
        protectorFail(404);
    }

    if ($start > 0) {
        fseek($handle, $start);
    }

    $remaining = $end - $start + 1;
    $chunkSize = 1024 * 1024;

    while (!feof($handle) && $remaining > 0) {
        $readLength = min($chunkSize, $remaining);
        $buffer = fread($handle, $readLength);

        if ($buffer === false || $buffer === '') {
            break;
        }

        echo $buffer;
        flush();

        $remaining -= strlen($buffer);
    }

    fclose($handle);
    exit;

} catch (Throwable $e) {
    error_log('[LOVEMI DOWNLOAD INDEX PROTECTOR] ' . $e->getMessage());
    protectorFail(500);
}
