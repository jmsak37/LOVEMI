<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/profile-code.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function profileJsonResponse(
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
                'message' => $message,
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

function jsonResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {
    profileJsonResponse(
        $success,
        $message,
        $data,
        $status
    );
}

function profileDb(): PDO
{
    $pdo = db();

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS post_comments (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL,
            parent_id BIGINT UNSIGNED DEFAULT NULL,
            body TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_post_comments_post (post_id),
            KEY idx_post_comments_user (user_id),
            KEY idx_post_comments_parent (parent_id)
        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS post_reactions (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL,
            reaction VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_post_reaction_user (post_id, user_id),
            KEY idx_post_reactions_post (post_id),
            KEY idx_post_reactions_user (user_id)
        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_follows (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            follower_id BIGINT UNSIGNED NOT NULL,
            following_id BIGINT UNSIGNED NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_user_follow (follower_id, following_id),
            KEY idx_user_follows_follower (follower_id),
            KEY idx_user_follows_following (following_id)
        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    ");

    return $pdo;
}

function requireAuthenticatedUser(): int
{
    $userId =
        isset($_SESSION['lovemi_user_id'])
            ?
            (int)$_SESSION['lovemi_user_id']
            :
            0;

    if ($userId <= 0) {
        profileJsonResponse(
            false,
            'Please log in first.',
            [
                'code' => 'AUTHENTICATION_REQUIRED',
            ],
            401
        );
    }

    return $userId;
}

function profileRequireAuth(): int
{
    return requireAuthenticatedUser();
}

function profileHasPremium(
    PDO $pdo,
    int $userId
): bool {
    if ($userId <= 0) {
        return false;
    }

    try {
        $stmt = $pdo->prepare("
            SELECT EXISTS
            (
                SELECT 1
                FROM subscriptions s
                INNER JOIN services sv
                    ON sv.id = s.service_id
                WHERE s.user_id = :user_id
                  AND sv.slug = 'lovemi-premium'
                  AND sv.is_active = 1
                  AND s.status = 'active'
                  AND (
                        s.start_at IS NULL
                        OR s.start_at <= CURRENT_TIMESTAMP
                  )
                  AND (
                        s.end_at IS NULL
                        OR s.end_at > CURRENT_TIMESTAMP
                  )
                LIMIT 1
            )
        ");

        $stmt->execute([
            ':user_id' => $userId,
        ]);

        return (bool)$stmt->fetchColumn();

    } catch (Throwable) {
        return false;
    }
}

function profileGetConnection(
    PDO $pdo,
    int $viewerId,
    int $targetId
): ?array {
    if (
        $viewerId <= 0
        ||
        $targetId <= 0
        ||
        $viewerId === $targetId
    ) {
        return null;
    }

    $stmt = $pdo->prepare("
        SELECT
            id,
            user_id,
            connected_user_id,
            initiated_by,
            status,
            connected_at,
            created_at,
            updated_at
        FROM connections
        WHERE
            (
                user_id = :viewer_a
                AND connected_user_id = :target_a
            )
            OR
            (
                user_id = :target_b
                AND connected_user_id = :viewer_b
            )
        ORDER BY id DESC
        LIMIT 1
    ");

    $stmt->execute([
        ':viewer_a' => $viewerId,
        ':target_a' => $targetId,
        ':target_b' => $targetId,
        ':viewer_b' => $viewerId,
    ]);

    $row = $stmt->fetch(
        PDO::FETCH_ASSOC
    );

    return $row ?: null;
}

function profileIsConnected(
    ?array $connection
): bool {
    if (!$connection) {
        return false;
    }

    return in_array(
        strtolower(
            (string)($connection['status'] ?? '')
        ),
        [
            'accepted',
            'connected',
            'active',
        ],
        true
    );
}

function hasActiveConnection(
    PDO $pdo,
    int $viewerId,
    int $targetId
): bool {
    return profileIsConnected(
        profileGetConnection(
            $pdo,
            $viewerId,
            $targetId
        )
    );
}

function createNotification(
    PDO $pdo,
    int $recipientId,
    int $senderId,
    string $typeSlug,
    string $title,
    string $message,
    ?string $referenceType = null,
    ?int $referenceId = null
): bool {
    if ($recipientId <= 0) {
        return false;
    }

    try {
        $typeStmt = $pdo->prepare("
            SELECT
                nt.id AS notification_type_id,
                (
                    SELECT na.id
                    FROM notification_audio na
                    WHERE na.notification_type_id = nt.id
                      AND na.is_active = 1
                    ORDER BY
                        na.sort_order ASC,
                        na.id ASC
                    LIMIT 1
                ) AS audio_id
            FROM notification_types nt
            WHERE nt.slug = :slug
            LIMIT 1
        ");

        $typeStmt->execute([
            ':slug' => $typeSlug,
        ]);

        $type =
            $typeStmt->fetch(
                PDO::FETCH_ASSOC
            )
            ?: [];

        $stmt = $pdo->prepare("
            INSERT INTO notifications
            (
                user_id,
                notification_type_id,
                sender_id,
                title,
                message,
                reference_type,
                reference_id,
                audio_id,
                is_read,
                created_at
            )
            VALUES
            (
                :user_id,
                :notification_type_id,
                :sender_id,
                :title,
                :message,
                :reference_type,
                :reference_id,
                :audio_id,
                0,
                CURRENT_TIMESTAMP
            )
        ");

        $stmt->execute([
            ':user_id' =>
                $recipientId,

            ':notification_type_id' =>
                isset($type['notification_type_id'])
                    ?
                    (int)$type['notification_type_id']
                    :
                    null,

            ':sender_id' =>
                $senderId > 0
                    ?
                    $senderId
                    :
                    null,

            ':title' =>
                $title,

            ':message' =>
                $message,

            ':reference_type' =>
                $referenceType,

            ':reference_id' =>
                $referenceId,

            ':audio_id' =>
                isset($type['audio_id'])
                    &&
                    $type['audio_id'] !== null
                    ?
                    (int)$type['audio_id']
                    :
                    null,
        ]);

        return true;

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI NOTIFICATION] '
            .
            $e->getMessage()
        );

        return false;
    }
}

function ensureProfileCode(
    PDO $pdo,
    int $userId
): ?string {
    if ($userId <= 0) {
        return null;
    }

    return profileGenerateCode(
        $pdo,
        $userId
    );
}

function resolveProfileRequest(
    PDO $pdo,
    int $currentUserId
): array {
    $code =
        trim(
            (string)(
                $_GET['code']
                ??
                ''
            )
        );

    if (
        $code === ''
    ) {
        return [
            'user_id' =>
                $currentUserId,

            'is_owner' =>
                true,

            'code' =>
                null,
        ];
    }

    $resolved =
        lovemiResolveProfileCode(
            $pdo,
            $code
        );

    if (
        !is_array(
            $resolved
        )
    ) {
        profileJsonResponse(
            false,
            'The profile code is invalid or has expired.',
            [
                'code' =>
                    'PROFILE_CODE_INVALID',
            ],
            404
        );
    }

    $targetId =
        (int)(
            $resolved['user_id']
            ??
            0
        );

    if (
        $targetId <= 0
    ) {
        profileJsonResponse(
            false,
            'The profile code is invalid.',
            [
                'code' =>
                    'INVALID_PROFILE_CODE',
            ],
            404
        );
    }

    if (
        $targetId ===
        $currentUserId
    ) {
        profileJsonResponse(
            false,
            'Use the Profile menu to open your own profile.',
            [
                'code' =>
                    'OWN_PROFILE_CODE',
            ],
            403
        );
    }

    return [
        'user_id' =>
            $targetId,

        'is_owner' =>
            false,

        'code' =>
            $code,
    ];
}