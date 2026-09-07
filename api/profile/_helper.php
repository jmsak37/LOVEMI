<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/profile-code.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

error_reporting(E_ALL);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function profileJsonResponse(
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

function profileEnsureSocialTables(
    PDO $pdo
): void {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS post_comments (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL,
            parent_id BIGINT UNSIGNED NULL,
            body TEXT NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_comment_post (post_id),
            KEY idx_comment_user (user_id),
            KEY idx_comment_parent (parent_id)
        ) ENGINE=InnoDB
          DEFAULT CHARSET=utf8mb4
          COLLATE=utf8mb4_unicode_ci
        "
    );

    $pdo->exec(
        "
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
        "
    );

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS profile_codes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            encrypted_payload TEXT NOT NULL,
            version SMALLINT UNSIGNED NOT NULL DEFAULT 1,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_profile_codes_user_id (user_id),
            UNIQUE KEY uq_profile_codes_hash (code_hash)
        ) ENGINE=InnoDB
          DEFAULT CHARSET=utf8mb4
          COLLATE=utf8mb4_unicode_ci
        "
    );

    $pdo->exec(
        "
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
        "
    );
}

function profileDb(): PDO
{
    $pdo = db();

    profileEnsureSocialTables($pdo);

    return $pdo;
}

function requireAuthenticatedUser(): int
{
    $userId =
        isset($_SESSION['lovemi_user_id'])
            ? (int)$_SESSION['lovemi_user_id']
            : 0;

    if ($userId <= 0) {
        profileJsonResponse(
            false,
            'Please log in first.',
            [
                'code' => 'AUTHENTICATION_REQUIRED',
                'redirect' => 'login.html'
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

    $stmt = $pdo->prepare(
        "
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
        "
    );

    $stmt->execute([
        ':user_id' => $userId
    ]);

    return (bool)$stmt->fetchColumn();
}

function profileGetConnection(
    PDO $pdo,
    int $viewerId,
    int $targetId
): ?array {

    if (
        $viewerId <= 0
        || $targetId <= 0
        || $viewerId === $targetId
    ) {
        return null;
    }

    $stmt = $pdo->prepare(
        "
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
        "
    );

    $stmt->execute(
        [
            ':viewer_a' => $viewerId,
            ':target_a' => $targetId,
            ':target_b' => $targetId,
            ':viewer_b' => $viewerId
        ]
    );

    $row =
        $stmt->fetch(PDO::FETCH_ASSOC);

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
            (string)(
                $connection['status']
                ?? ''
            )
        ),
        [
            'accepted',
            'connected',
            'active'
        ],
        true
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

        $typeStmt =
            $pdo->prepare(
                "
                SELECT
                    nt.id AS notification_type_id,
                    (
                        SELECT na.id
                        FROM notification_audio na
                        WHERE na.notification_type_id = nt.id
                          AND na.is_active = 1
                        ORDER BY na.sort_order ASC, na.id ASC
                        LIMIT 1
                    ) AS audio_id
                FROM notification_types nt
                WHERE nt.slug = :slug
                LIMIT 1
                "
            );

        $typeStmt->execute([
            ':slug' => $typeSlug
        ]);

        $type =
            $typeStmt->fetch(PDO::FETCH_ASSOC)
            ?: [];

        $stmt =
            $pdo->prepare(
                "
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
                "
            );

        $stmt->execute(
            [
                ':user_id' =>
                    $recipientId,

                ':notification_type_id' =>
                    isset($type['notification_type_id'])
                        ? (int)$type['notification_type_id']
                        : null,

                ':sender_id' =>
                    $senderId > 0
                        ? $senderId
                        : null,

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
                    && $type['audio_id'] !== null
                        ? (int)$type['audio_id']
                        : null
            ]
        );

        return true;

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI NOTIFICATION] ' .
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

    $stmt =
        $pdo->prepare(
            "
            SELECT
                code_hash,
                encrypted_payload,
                version
            FROM profile_codes
            WHERE user_id = :user_id
              AND version = :version
            ORDER BY id DESC
            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':user_id' =>
                $userId,

            ':version' =>
                LOVEMI_PROFILE_CODE_VERSION
        ]
    );

    $row =
        $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {

        $payload =
            lovemiDecryptProfilePayload(
                (string)$row['encrypted_payload']
            );

        if (
            is_array($payload)
            && (int)(
                $payload['user_id']
                ?? 0
            ) === $userId
            && (int)(
                $payload['version']
                ?? 0
            ) === LOVEMI_PROFILE_CODE_VERSION
        ) {

            $code =
                (string)(
                    $payload['code']
                    ?? ''
                );

            if (
                $code !== ''
                && hash_equals(
                    (string)$row['code_hash'],
                    hash('sha256', $code)
                )
            ) {
                return $code;
            }
        }
    }

    for ($attempt = 0; $attempt < 5; $attempt++) {

        $code =
            lovemiBase64UrlEncode(
                random_bytes(24)
            );

        $hash =
            hash(
                'sha256',
                $code
            );

        $check =
            $pdo->prepare(
                "
                SELECT id
                FROM profile_codes
                WHERE code_hash = :code_hash
                LIMIT 1
                "
            );

        $check->execute([
            ':code_hash' => $hash
        ]);

        if ($check->fetchColumn()) {
            continue;
        }

        $payload = [
            'user_id' =>
                $userId,

            'code' =>
                $code,

            'version' =>
                LOVEMI_PROFILE_CODE_VERSION,

            'created_at' =>
                time(),

            'nonce' =>
                bin2hex(
                    random_bytes(16)
                )
        ];

        $encrypted =
            lovemiEncryptProfilePayload(
                $payload
            );

        try {

            $insert =
                $pdo->prepare(
                    "
                    INSERT INTO profile_codes
                    (
                        user_id,
                        code_hash,
                        encrypted_payload,
                        version,
                        created_at,
                        updated_at
                    )
                    VALUES
                    (
                        :user_id,
                        :code_hash,
                        :encrypted_payload,
                        :version,
                        CURRENT_TIMESTAMP,
                        CURRENT_TIMESTAMP
                    )
                    "
                );

            $insert->execute(
                [
                    ':user_id' =>
                        $userId,

                    ':code_hash' =>
                        $hash,

                    ':encrypted_payload' =>
                        $encrypted,

                    ':version' =>
                        LOVEMI_PROFILE_CODE_VERSION
                ]
            );

            return $code;

        } catch (PDOException $e) {

            error_log(
                '[LOVEMI PROFILE CODE INSERT] ' .
                $e->getMessage()
            );

            /*
             * Another request may have created it.
             */
            $retry =
                $pdo->prepare(
                    "
                    SELECT
                        encrypted_payload,
                        code_hash
                    FROM profile_codes
                    WHERE user_id = :user_id
                      AND version = :version
                    ORDER BY id DESC
                    LIMIT 1
                    "
                );

            $retry->execute(
                [
                    ':user_id' =>
                        $userId,

                    ':version' =>
                        LOVEMI_PROFILE_CODE_VERSION
                ]
            );

            $existing =
                $retry->fetch(PDO::FETCH_ASSOC);

            if ($existing) {

                $payload =
                    lovemiDecryptProfilePayload(
                        (string)$existing['encrypted_payload']
                    );

                if (
                    is_array($payload)
                    && !empty($payload['code'])
                ) {

                    $existingCode =
                        (string)$payload['code'];

                    if (
                        hash_equals(
                            (string)$existing['code_hash'],
                            hash(
                                'sha256',
                                $existingCode
                            )
                        )
                    ) {
                        return $existingCode;
                    }
                }
            }
        }
    }

    return null;
}

function resolveProfileRequest(
    PDO $pdo,
    int $currentUserId
): array {

    $profileCode =
        trim(
            (string)(
                $_GET['code']
                ?? ''
            )
        );

    if ($profileCode === '') {

        return [
            'user_id' =>
                $currentUserId,

            'is_owner' =>
                true,

            'code' =>
                null
        ];
    }

    $resolved =
        lovemiResolveProfileCode(
            $pdo,
            $profileCode
        );

    if (!is_array($resolved)) {

        profileJsonResponse(
            false,
            'The profile code is invalid or has expired.',
            [
                'code' =>
                    'PROFILE_CODE_INVALID'
            ],
            404
        );
    }

    $targetUserId =
        (int)(
            $resolved['user_id']
            ?? 0
        );

    if ($targetUserId <= 0) {

        profileJsonResponse(
            false,
            'The profile code does not identify a valid member.',
            [
                'code' =>
                    'INVALID_PROFILE_ID'
            ],
            404
        );
    }

    $stmt =
        $pdo->prepare(
            "
            SELECT
                u.id,
                u.account_status,
                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted,
                p.profile_visibility
            FROM users u
            LEFT JOIN profiles p
                ON p.user_id = u.id
            WHERE u.id = :user_id
            LIMIT 1
            "
        );

    $stmt->execute([
        ':user_id' =>
            $targetUserId
    ]);

    $user =
        $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {

        profileJsonResponse(
            false,
            'The requested profile could not be found.',
            [
                'code' =>
                    'PROFILE_NOT_FOUND'
            ],
            404
        );
    }

    if (
        (int)$user['is_active'] !== 1
        || (int)$user['is_suspended'] === 1
        || (int)$user['is_deleted'] === 1
    ) {

        profileJsonResponse(
            false,
            'This profile is currently unavailable.',
            [
                'code' =>
                    'PROFILE_UNAVAILABLE'
            ],
            403
        );
    }

    if (
        strtolower(
            (string)$user['account_status']
        ) !== 'approved'
        || (int)$user['email_verified'] !== 1
    ) {

        profileJsonResponse(
            false,
            'This profile is not currently available.',
            [
                'code' =>
                    'PROFILE_NOT_AVAILABLE'
            ],
            403
        );
    }

    $visibility =
        strtolower(
            trim(
                (string)(
                    $user['profile_visibility']
                    ?? 'public'
                )
            )
        );

    if (
        $targetUserId !== $currentUserId
        && $visibility !== 'public'
    ) {

        profileJsonResponse(
            false,
            'This profile is not public.',
            [
                'code' =>
                    'PROFILE_NOT_PUBLIC'
            ],
            403
        );
    }

    return [
        'user_id' =>
            $targetUserId,

        'is_owner' =>
            $targetUserId === $currentUserId,

        'code' =>
            $profileCode
    ];
}