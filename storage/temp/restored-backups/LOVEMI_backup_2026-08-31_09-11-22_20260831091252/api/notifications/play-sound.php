<?php
/**
 * ============================================================
 * LOVEMI - NOTIFICATION SOUND API
 * ============================================================
 *
 * Usage:
 *
 *   api/notifications/play-sound.php?id=123
 *
 * Returns the audio file associated with the user's
 * notification.
 *
 * The database controls the sound path.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {
    http_response_code(401);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Please log in first.'
        ],
        JSON_UNESCAPED_UNICODE
    );

    exit;
}

$notificationId =
    isset($_GET['id'])
        ? (int) $_GET['id']
        : 0;

if ($notificationId <= 0) {
    http_response_code(422);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Notification ID is required.'
        ]
    );

    exit;
}

/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PLAY SOUND DB] ' .
        $e->getMessage()
    );

    http_response_code(500);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Database connection failed.'
        ]
    );

    exit;
}

/* ============================================================
   USER PREFERENCES + AUDIO
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                n.id AS notification_id,

                n.user_id,

                n.audio_id,

                na.name AS audio_name,

                na.file_name,

                na.file_path,

                na.mime_type,

                na.is_active AS audio_active,

                nt.slug AS notification_type,

                nt.sound_enabled AS type_sound_enabled,

                np.sound_enabled AS user_sound_enabled

            FROM notifications n

            LEFT JOIN notification_audio na
                ON na.id = n.audio_id

            LEFT JOIN notification_types nt
                ON nt.id = n.notification_type_id

            LEFT JOIN notification_preferences np
                ON np.user_id = n.user_id

            WHERE n.id = :notification_id

              AND n.user_id = :user_id

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':notification_id' => $notificationId,
            ':user_id' => $userId
        ]
    );

    $row =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PLAY SOUND QUERY] ' .
        $e->getMessage()
    );

    http_response_code(500);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Unable to load notification sound.'
        ]
    );

    exit;
}

if (!$row) {

    http_response_code(404);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Notification sound was not found.'
        ]
    );

    exit;
}

/* ============================================================
   SOUND PREFERENCE
============================================================ */

$userSoundEnabled =
    !isset($row['user_sound_enabled'])
    ||
    (bool) $row['user_sound_enabled'];

$typeSoundEnabled =
    !isset($row['type_sound_enabled'])
    ||
    (bool) $row['type_sound_enabled'];

$audioActive =
    !isset($row['audio_active'])
    ||
    (bool) $row['audio_active'];

if (
    !$userSoundEnabled
    ||
    !$typeSoundEnabled
    ||
    !$audioActive
) {

    http_response_code(403);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Notification sounds are disabled.'
        ]
    );

    exit;
}

$filePath =
    trim(
        (string)
        (
            $row['file_path']
            ??
            ''
        )
    );

if ($filePath === '') {

    http_response_code(404);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'No sound is assigned to this notification.'
        ]
    );

    exit;
}

/* ============================================================
   SECURITY - ONLY ALLOW PROJECT-RELATIVE ASSET AUDIO
============================================================ */

$filePath =
    str_replace(
        '\\',
        '/',
        $filePath
    );

$filePath =
    ltrim(
        $filePath,
        '/'
    );

/*
 * Your saved database uses paths like:
 *
 * assets/audio/notification1.mp3
 *
 * Only allow that directory.
 */

if (
    !str_starts_with(
        strtolower($filePath),
        'assets/audio/'
    )
) {

    error_log(
        '[LOVEMI INVALID NOTIFICATION AUDIO PATH] '
        .
        $filePath
    );

    http_response_code(403);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Invalid notification sound location.'
        ]
    );

    exit;
}

/* Prevent traversal */
if (
    str_contains($filePath, '..')
) {

    http_response_code(403);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Invalid sound path.'
        ]
    );

    exit;
}

/* ============================================================
   PHYSICAL FILE
============================================================ */

$projectRoot =
    realpath(
        __DIR__ .
        '/../../'
    );

if (
    $projectRoot === false
) {

    http_response_code(500);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Project directory could not be resolved.'
        ]
    );

    exit;
}

$fullPath =
    realpath(
        $projectRoot .
        DIRECTORY_SEPARATOR .
        str_replace(
            '/',
            DIRECTORY_SEPARATOR,
            $filePath
        )
    );

if (
    $fullPath === false
    ||
    !is_file($fullPath)
) {

    http_response_code(404);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Notification sound file does not exist.'
        ]
    );

    exit;
}

/*
 * Ensure resolved path is still inside project.
 */

$rootPrefix =
    rtrim(
        $projectRoot,
        DIRECTORY_SEPARATOR
    )
    .
    DIRECTORY_SEPARATOR;

if (
    !str_starts_with(
        $fullPath,
        $rootPrefix
    )
) {

    http_response_code(403);

    header('Content-Type: application/json; charset=utf-8');

    echo json_encode(
        [
            'success' => false,
            'message' => 'Invalid file location.'
        ]
    );

    exit;
}

/* ============================================================
   MIME TYPE
============================================================ */

$mimeType =
    trim(
        (string)
        (
            $row['mime_type']
            ??
            ''
        )
    );

if (
    $mimeType === ''
) {

    $mimeType =
        'audio/mpeg';

}

$allowedMimeTypes = [
    'audio/mpeg',
    'audio/mp3',
    'audio/wav',
    'audio/ogg'
];

if (
    !in_array(
        strtolower($mimeType),
        $allowedMimeTypes,
        true
    )
) {

    $mimeType =
        'audio/mpeg';

}

/* ============================================================
   STREAM AUDIO
============================================================ */

$fileSize =
    filesize(
        $fullPath
    );

if (
    $fileSize === false
) {

    http_response_code(500);

    exit;
}

$downloadName =
    basename(
        (string)
        (
            $row['file_name']
            ??
            basename($fullPath)
        )
    );

header(
    'Content-Type: '
    .
    $mimeType
);

header(
    'Content-Length: '
    .
    (string)
    $fileSize
);

header(
    'Content-Disposition: inline; filename="'
    .
    addcslashes(
        $downloadName,
        "\"\\"
    )
    .
    '"'
);

header(
    'Accept-Ranges: bytes'
);

header(
    'Cache-Control: private, no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'X-Content-Type-Options: nosniff'
);

readfile(
    $fullPath
);

exit;