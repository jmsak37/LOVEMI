<?php
declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI - PROFILE / MEDIA DOWNLOAD + SCREENSHOT PROTECTOR
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\profile\profile-download-protector.php
 *
 * PURPOSE
 *   1. Store per-media owner permissions:
 *        - allow_download
 *        - allow_screenshot
 *   2. Read the owner permission for a photo/video.
 *   3. Fail closed when permission cannot be determined.
 *   4. Provide a protected media stream endpoint.
 *   5. Block obvious download attempts when the owner disabled
 *      downloading.
 *
 * IMPORTANT
 *   A normal web browser cannot be made mathematically incapable of:
 *      - taking a screenshot,
 *      - using screen-recording software,
 *      - saving bytes received by the browser,
 *      - inspecting network requests.
 *
 *   Therefore this file provides server-side permission enforcement
 *   for requests made through this endpoint plus browser deterrence.
 *   To use the server-side protection, profile/video/image URLs must
 *   be routed through this endpoint instead of exposing /uploads/*
 *   directly.
 *
 * ACTIONS
 *   POST save
 *      photo_id, allow_download (0|1), allow_screenshot (0|1)
 *      Owner only.
 *
 *   GET check
 *      ?action=check&photo_id=123
 *
 *   GET media
 *      ?action=media&photo_id=123
 *      ?action=media&photo_id=123&download=1
 *
 *   GET policy
 *      ?action=policy&photo_id=123
 *
 * FAIL-CLOSED RULE
 *   If a media policy is missing:
 *      - images: download BLOCKED
 *      - videos: download follows the existing
 *        user_content_security.default_allow_video_download
 *      - screenshots: BLOCKED
 *
 * OWNERS
 *   The media owner may always view/serve their own media.
 *   Download/screenshot settings still determine what viewers are
 *   allowed to do.
 * ============================================================
 */

require_once __DIR__ . '/../../config/database.php';

header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: same-origin');
header('X-Frame-Options: SAMEORIGIN');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function protectorJson(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {
    http_response_code($status);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

function protectorBool(mixed $value, bool $default = false): bool
{
    if ($value === null || $value === '') {
        return $default;
    }

    if (is_bool($value)) {
        return $value;
    }

    if (is_int($value) || is_float($value)) {
        return (int) $value === 1;
    }

    $v = strtolower(trim((string) $value));

    if (in_array($v, ['1', 'true', 'yes', 'on', 'allow', 'allowed'], true)) {
        return true;
    }

    if (in_array($v, ['0', 'false', 'no', 'off', 'deny', 'denied', 'blocked'], true)) {
        return false;
    }

    return $default;
}

function protectorMethod(): string
{
    return strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
}

function protectorCurrentUserId(): int
{
    return (int) ($_SESSION['lovemi_user_id'] ?? 0);
}

function protectorResolveAbsolutePath(string $relativePath): ?string
{
    $relativePath = str_replace('\\', '/', trim($relativePath));

    // Never allow a client supplied absolute filesystem path.
    if ($relativePath === '' || $relativePath[0] === '/' || preg_match('/^[A-Za-z]:\//', $relativePath)) {
        return null;
    }

    // Normalize leading ./ only.
    $relativePath = ltrim($relativePath, '/');
    while (str_starts_with($relativePath, './')) {
        $relativePath = substr($relativePath, 2);
    }

    // Explicitly keep media inside the LOVEMI uploads tree.
    if (!str_starts_with($relativePath, 'uploads/')) {
        return null;
    }

    $projectRoot = realpath(__DIR__ . '/../../');
    if ($projectRoot === false) {
        return null;
    }

    $uploadsRoot = realpath($projectRoot . DIRECTORY_SEPARATOR . 'uploads');
    if ($uploadsRoot === false) {
        return null;
    }

    $candidate = realpath($projectRoot . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath));

    if ($candidate === false || !is_file($candidate)) {
        return null;
    }

    $candidateNorm = str_replace('\\', '/', $candidate);
    $uploadsNorm = rtrim(str_replace('\\', '/', $uploadsRoot), '/') . '/';

    if (!str_starts_with($candidateNorm, $uploadsNorm)) {
        return null;
    }

    return $candidate;
}

function protectorIsVideo(string $mimeType, string $path): bool
{
    $mimeType = strtolower(trim($mimeType));
    if (str_starts_with($mimeType, 'video/')) {
        return true;
    }

    return (bool) preg_match(
        '/\.(mp4|webm|ogg|ogv|mov|m4v|avi|mkv)$/i',
        parse_url($path, PHP_URL_PATH) ?: $path
    );
}

try {
    $pdo = db();
} catch (Throwable $e) {
    error_log('[LOVEMI PROFILE PROTECTOR DB] ' . $e->getMessage());
    protectorJson(
        false,
        'Unable to connect to the LOVEMI database.',
        ['code' => 'DATABASE_ERROR'],
        500
    );
}

$currentUserId = protectorCurrentUserId();

if ($currentUserId <= 0) {
    protectorJson(
        false,
        'Please log in first.',
        ['code' => 'AUTHENTICATION_REQUIRED'],
        401
    );
}

/*
 * Verify current user is active.
 */
try {
    $userStmt = $pdo->prepare(
        'SELECT id, is_active, is_suspended, is_deleted
         FROM users
         WHERE id = :id
         LIMIT 1'
    );
    $userStmt->execute([':id' => $currentUserId]);
    $viewer = $userStmt->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('[LOVEMI PROFILE PROTECTOR USER] ' . $e->getMessage());
    protectorJson(
        false,
        'Unable to verify your account.',
        ['code' => 'USER_LOOKUP_FAILED'],
        500
    );
}

if (!$viewer) {
    protectorJson(
        false,
        'Your account could not be found.',
        ['code' => 'USER_NOT_FOUND'],
        404
    );
}

if (
    (int) ($viewer['is_deleted'] ?? 0) === 1 ||
    (int) ($viewer['is_suspended'] ?? 0) === 1 ||
    (int) ($viewer['is_active'] ?? 0) !== 1
) {
    protectorJson(
        false,
        'Your account is currently unavailable.',
        ['code' => 'ACCOUNT_UNAVAILABLE'],
        403
    );
}

/*
 * Create the per-media policy table if it does not already exist.
 * This avoids requiring a separate manual SQL installation step.
 */
try {
    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS profile_media_security (
            photo_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            allow_download TINYINT(1) NOT NULL DEFAULT 0,
            allow_screenshot TINYINT(1) NOT NULL DEFAULT 0,
            updated_by BIGINT UNSIGNED DEFAULT NULL,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_profile_media_security_updated_by (updated_by)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        "
    );
} catch (Throwable $e) {
    error_log('[LOVEMI PROFILE PROTECTOR TABLE] ' . $e->getMessage());
    protectorJson(
        false,
        'The media protection storage could not be initialized.',
        ['code' => 'PROTECTION_STORAGE_FAILED'],
        500
    );
}

$method = protectorMethod();

/*
 * ------------------------------------------------------------
 * POST save
 * ------------------------------------------------------------
 * Owner only.
 */
if ($method === 'POST') {
    $raw = file_get_contents('php://input');
    $input = json_decode((string) $raw, true);

    if (!is_array($input)) {
        $input = $_POST;
    }

    $action = strtolower(trim((string) ($input['action'] ?? '')));

    if ($action !== 'save') {
        protectorJson(
            false,
            'Invalid protection action.',
            ['code' => 'INVALID_ACTION'],
            422
        );
    }

    $photoId = (int) ($input['photo_id'] ?? 0);

    if ($photoId <= 0) {
        protectorJson(
            false,
            'A valid photo or media ID is required.',
            ['code' => 'INVALID_MEDIA_ID'],
            422
        );
    }

    $allowDownload = protectorBool($input['allow_download'] ?? 0, false) ? 1 : 0;
    $allowScreenshot = protectorBool($input['allow_screenshot'] ?? 0, false) ? 1 : 0;

    try {
        $mediaStmt = $pdo->prepare(
            'SELECT id, user_id, mime_type, file_path, approval_status
             FROM photos
             WHERE id = :id
             LIMIT 1'
        );
        $mediaStmt->execute([':id' => $photoId]);
        $media = $mediaStmt->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        error_log('[LOVEMI PROFILE PROTECTOR SAVE LOOKUP] ' . $e->getMessage());
        protectorJson(
            false,
            'Unable to load the selected media.',
            ['code' => 'MEDIA_LOOKUP_FAILED'],
            500
        );
    }

    if (!$media) {
        protectorJson(
            false,
            'The selected media was not found.',
            ['code' => 'MEDIA_NOT_FOUND'],
            404
        );
    }

    if ((int) $media['user_id'] !== $currentUserId) {
        protectorJson(
            false,
            'You can only change protection for your own media.',
            ['code' => 'NOT_MEDIA_OWNER'],
            403
        );
    }

    if (strtolower((string) ($media['approval_status'] ?? '')) !== 'approved') {
        protectorJson(
            false,
            'Only approved media can have viewer protection settings.',
            ['code' => 'MEDIA_NOT_APPROVED'],
            403
        );
    }

    try {
        $saveStmt = $pdo->prepare(
            "
            INSERT INTO profile_media_security
                (photo_id, allow_download, allow_screenshot, updated_by)
            VALUES
                (:photo_id, :allow_download, :allow_screenshot, :updated_by)
            ON DUPLICATE KEY UPDATE
                allow_download = VALUES(allow_download),
                allow_screenshot = VALUES(allow_screenshot),
                updated_by = VALUES(updated_by)
            "
        );

        $saveStmt->execute(
            [
                ':photo_id' => $photoId,
                ':allow_download' => $allowDownload,
                ':allow_screenshot' => $allowScreenshot,
                ':updated_by' => $currentUserId
            ]
        );
    } catch (Throwable $e) {
        error_log('[LOVEMI PROFILE PROTECTOR SAVE] ' . $e->getMessage());
        protectorJson(
            false,
            'Unable to save media protection settings.',
            ['code' => 'POLICY_SAVE_FAILED'],
            500
        );
    }

    protectorJson(
        true,
        'Media protection settings saved successfully.',
        [
            'photo_id' => $photoId,
            'allow_download' => $allowDownload,
            'allow_screenshot' => $allowScreenshot
        ]
    );
}

/*
 * Everything below is GET-only.
 */
if ($method !== 'GET') {
    protectorJson(
        false,
        'Only GET and POST requests are allowed.',
        ['code' => 'METHOD_NOT_ALLOWED'],
        405
    );
}

$action = strtolower(trim((string) ($_GET['action'] ?? 'check')));
$photoId = (int) ($_GET['photo_id'] ?? 0);

if ($photoId <= 0) {
    protectorJson(
        false,
        'A valid photo or media ID is required.',
        ['code' => 'INVALID_MEDIA_ID'],
        422
    );
}

/*
 * Load media + owner.
 */
try {
    $mediaStmt = $pdo->prepare(
        "
        SELECT
            p.id,
            p.user_id,
            p.file_name,
            p.file_path,
            p.thumbnail_path,
            p.mime_type,
            p.file_size,
            p.approval_status,
            p.photo_type
        FROM photos p
        WHERE p.id = :id
        LIMIT 1
        "
    );
    $mediaStmt->execute([':id' => $photoId]);
    $media = $mediaStmt->fetch(PDO::FETCH_ASSOC);
} catch (Throwable $e) {
    error_log('[LOVEMI PROFILE PROTECTOR MEDIA LOOKUP] ' . $e->getMessage());
    protectorJson(
        false,
        'Unable to load the media.',
        ['code' => 'MEDIA_LOOKUP_FAILED'],
        500
    );
}

if (!$media) {
    protectorJson(
        false,
        'The requested media was not found.',
        ['code' => 'MEDIA_NOT_FOUND'],
        404
    );
}

if (strtolower((string) ($media['approval_status'] ?? '')) !== 'approved') {
    protectorJson(
        false,
        'This media is not available.',
        ['code' => 'MEDIA_NOT_APPROVED'],
        403
    );
}

$ownerId = (int) $media['user_id'];
$isOwner = $ownerId === $currentUserId;
$isVideo = protectorIsVideo(
    (string) ($media['mime_type'] ?? ''),
    (string) ($media['file_path'] ?? '')
);

/*
 * Existing LOVEMI default video download preference.
 */
$defaultVideoDownload = false;

try {
    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS user_content_security (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            default_allow_repost TINYINT(1) NOT NULL DEFAULT 1,
            default_allow_video_download TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        "
    );

    $securityStmt = $pdo->prepare(
        'SELECT default_allow_video_download
         FROM user_content_security
         WHERE user_id = :user_id
         LIMIT 1'
    );
    $securityStmt->execute([':user_id' => $ownerId]);

    $security = $securityStmt->fetch(PDO::FETCH_ASSOC);

    if (!$security) {
        $insertSecurity = $pdo->prepare(
            'INSERT INTO user_content_security (user_id)
             VALUES (:user_id)
             ON DUPLICATE KEY UPDATE user_id = user_id'
        );
        $insertSecurity->execute([':user_id' => $ownerId]);

        // Existing LOVEMI default is 1 for video downloads.
        $defaultVideoDownload = true;
    } else {
        $defaultVideoDownload = (int) ($security['default_allow_video_download'] ?? 0) === 1;
    }
} catch (Throwable $e) {
    /*
     * Fail closed when the existing security preference cannot be read.
     */
    error_log('[LOVEMI PROFILE PROTECTOR VIDEO DEFAULT] ' . $e->getMessage());
    $defaultVideoDownload = false;
}

/*
 * Resolve per-media policy.
 */
$policyFound = false;
$allowDownload = false;
$allowScreenshot = false;

try {
    $policyStmt = $pdo->prepare(
        'SELECT allow_download, allow_screenshot
         FROM profile_media_security
         WHERE photo_id = :photo_id
         LIMIT 1'
    );
    $policyStmt->execute([':photo_id' => $photoId]);
    $policy = $policyStmt->fetch(PDO::FETCH_ASSOC);

    if ($policy) {
        $policyFound = true;
        $allowDownload = (int) ($policy['allow_download'] ?? 0) === 1;
        $allowScreenshot = (int) ($policy['allow_screenshot'] ?? 0) === 1;
    }
} catch (Throwable $e) {
    error_log('[LOVEMI PROFILE PROTECTOR POLICY LOOKUP] ' . $e->getMessage());
}

/*
 * Fail-closed defaults:
 *   - image download: blocked unless owner explicitly allows it
 *   - video download: use existing owner default, unless a per-media
 *     policy exists
 *   - screenshot: blocked unless explicitly allowed
 */
if (!$policyFound) {
    $allowDownload = $isVideo ? $defaultVideoDownload : false;
    $allowScreenshot = false;
}

/*
 * The owner is allowed to view their own media. The policy still
 * controls viewer permissions.
 */
$requestedDownload = protectorBool($_GET['download'] ?? 0, false);

$payload = [
    'photo_id' => $photoId,
    'owner_id' => $ownerId,
    'is_owner' => $isOwner,
    'media_type' => $isVideo ? 'video' : 'image',
    'allow_download' => $allowDownload,
    'allow_screenshot' => $allowScreenshot,
    'protected' => (!$allowDownload || !$allowScreenshot),
    'policy_found' => $policyFound
];

/*
 * ------------------------------------------------------------
 * CHECK / POLICY
 * ------------------------------------------------------------
 */
if ($action === 'check' || $action === 'policy') {
    protectorJson(
        true,
        'Media protection policy loaded.',
        ['policy' => $payload]
    );
}

/*
 * ------------------------------------------------------------
 * MEDIA STREAM
 * ------------------------------------------------------------
 *
 * This is the important server-side part.
 *
 * A normal viewer is allowed to view the media.
 * An explicit ?download=1 request is blocked unless the owner
 * has enabled downloading.
 */
if ($action === 'media') {
    if ($requestedDownload && !$allowDownload && !$isOwner) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(403);

        echo json_encode(
            [
                'success' => false,
                'message' => 'The owner has disabled downloading for this media.',
                'code' => 'DOWNLOAD_BLOCKED'
            ],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        exit;
    }

    $absolutePath = protectorResolveAbsolutePath(
        (string) ($media['file_path'] ?? '')
    );

    if ($absolutePath === null) {
        header('Content-Type: application/json; charset=utf-8');
        http_response_code(404);

        echo json_encode(
            [
                'success' => false,
                'message' => 'The media file could not be found.',
                'code' => 'MEDIA_FILE_NOT_FOUND'
            ],
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        exit;
    }

    $mime = trim((string) ($media['mime_type'] ?? ''));
    if ($mime === '' || !preg_match('/^[A-Za-z0-9.+-]+\/[A-Za-z0-9.+-]+$/', $mime)) {
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mime = (string) ($finfo->file($absolutePath) ?: 'application/octet-stream');
    }

    $size = filesize($absolutePath);
    if ($size === false) {
        protectorJson(
            false,
            'Unable to read the media.',
            ['code' => 'MEDIA_READ_FAILED'],
            500
        );
    }

    /*
     * Never advertise the file as an attachment.
     */
    header('Content-Type: ' . $mime);
    header('Content-Disposition: inline');
    header('Accept-Ranges: bytes');
    header('Content-Length: ' . (string) $size);
    header('X-Content-Type-Options: nosniff');
    header('Cross-Origin-Resource-Policy: same-origin');
    header('Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');

    /*
     * Range requests are required for practical HTML5 video playback.
     */
    $range = trim((string) ($_SERVER['HTTP_RANGE'] ?? ''));

    if ($range !== '' && preg_match('/bytes=(\d*)-(\d*)/i', $range, $matches)) {
        $start = ($matches[1] !== '') ? (int) $matches[1] : 0;
        $end = ($matches[2] !== '') ? (int) $matches[2] : ($size - 1);

        if ($start < 0 || $start >= $size || $end < $start) {
            header('Content-Range: bytes */' . $size);
            http_response_code(416);
            exit;
        }

        $end = min($end, $size - 1);
        $length = $end - $start + 1;

        http_response_code(206);
        header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
        header('Content-Length: ' . $length);

        $fp = fopen($absolutePath, 'rb');
        if ($fp === false) {
            http_response_code(500);
            exit;
        }

        if (fseek($fp, $start, SEEK_SET) !== 0) {
            fclose($fp);
            http_response_code(500);
            exit;
        }

        $remaining = $length;

        while ($remaining > 0 && !feof($fp)) {
            $chunk = fread($fp, min(1024 * 1024, $remaining));

            if ($chunk === false || $chunk === '') {
                break;
            }

            echo $chunk;
            flush();

            $remaining -= strlen($chunk);
        }

        fclose($fp);
        exit;
    }

    readfile($absolutePath);
    exit;
}

protectorJson(
    false,
    'Invalid media protection action.',
    ['code' => 'INVALID_ACTION'],
    422
);
