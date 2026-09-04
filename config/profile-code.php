<?php

declare(strict_types=1);

const LOVEMI_PROFILE_CODE_VERSION = 2;
const LOVEMI_PROFILE_CODE_CIPHER = 'aes-256-gcm';

function lovemiProfileCodeSecret(): string
{
    $secret = getenv('LOVEMI_PROFILE_SECRET');

    if (!is_string($secret) || $secret === '') {
        $secret = 'LOVEMI_PROFILE_SECRET_CHANGE_THIS_LOCAL_ONLY_2026';
    }

    return $secret;
}

function lovemiBase64UrlEncode(string $value): string
{
    return rtrim(
        strtr(
            base64_encode($value),
            '+/',
            '-_'
        ),
        '='
    );
}

function lovemiBase64UrlDecode(string $value): string|false
{
    $padding = strlen($value) % 4;

    if ($padding > 0) {
        $value .= str_repeat('=', 4 - $padding);
    }

    return base64_decode(
        strtr($value, '-_', '+/'),
        true
    );
}

function lovemiEncryptProfilePayload(array $payload): string
{
    $key = hash(
        'sha256',
        lovemiProfileCodeSecret(),
        true
    );

    $iv = random_bytes(12);
    $tag = '';

    $plaintext = json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    if ($plaintext === false) {
        throw new RuntimeException('Unable to encode profile payload.');
    }

    $ciphertext = openssl_encrypt(
        $plaintext,
        LOVEMI_PROFILE_CODE_CIPHER,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($ciphertext === false) {
        throw new RuntimeException('Unable to encrypt profile payload.');
    }

    return lovemiBase64UrlEncode(
        $iv .
        $tag .
        $ciphertext
    );
}

function lovemiDecryptProfilePayload(string $encrypted): array|false
{
    $binary = lovemiBase64UrlDecode($encrypted);

    if ($binary === false || strlen($binary) < 29) {
        return false;
    }

    $iv = substr($binary, 0, 12);
    $tag = substr($binary, 12, 16);
    $ciphertext = substr($binary, 28);

    $key = hash(
        'sha256',
        lovemiProfileCodeSecret(),
        true
    );

    $plaintext = openssl_decrypt(
        $ciphertext,
        LOVEMI_PROFILE_CODE_CIPHER,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plaintext === false) {
        return false;
    }

    $payload = json_decode(
        $plaintext,
        true
    );

    return is_array($payload)
        ? $payload
        : false;
}

function profileGenerateCode(
    PDO $pdo,
    int $userId
): string {
    if ($userId <= 0) {
        throw new InvalidArgumentException(
            'Invalid user ID.'
        );
    }

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS profile_codes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            encrypted_payload TEXT NOT NULL,
            version SMALLINT UNSIGNED NOT NULL DEFAULT 2,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_profile_code_user (user_id),
            UNIQUE KEY uq_profile_code_hash (code_hash)
        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    ");

    $lookup = $pdo->prepare("
        SELECT
            code_hash,
            encrypted_payload,
            version
        FROM profile_codes
        WHERE user_id = :user_id
          AND version = :version
        ORDER BY id DESC
        LIMIT 1
    ");

    $lookup->execute([
        ':user_id' => $userId,
        ':version' => LOVEMI_PROFILE_CODE_VERSION,
    ]);

    $existing = $lookup->fetch(PDO::FETCH_ASSOC);

    if ($existing) {
        $payload = lovemiDecryptProfilePayload(
            (string)$existing['encrypted_payload']
        );

        if (
            is_array($payload)
            && (int)($payload['user_id'] ?? 0) === $userId
            && (int)($payload['version'] ?? 0) === LOVEMI_PROFILE_CODE_VERSION
        ) {
            $code = (string)($payload['code'] ?? '');

            if (
                $code !== ''
                && hash_equals(
                    (string)$existing['code_hash'],
                    hash('sha256', $code)
                )
            ) {
                return $code;
            }
        }
    }

    for ($attempt = 0; $attempt < 10; $attempt++) {
        $code = lovemiBase64UrlEncode(
            random_bytes(32)
        );

        $payload = [
            'user_id' => $userId,
            'code' => $code,
            'version' => LOVEMI_PROFILE_CODE_VERSION,
            'created_at' => time(),
            'nonce' => bin2hex(random_bytes(16)),
        ];

        $encrypted = lovemiEncryptProfilePayload(
            $payload
        );

        $hash = hash(
            'sha256',
            $code
        );

        try {
            $insert = $pdo->prepare("
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
                ON DUPLICATE KEY UPDATE
                    code_hash = VALUES(code_hash),
                    encrypted_payload = VALUES(encrypted_payload),
                    version = VALUES(version),
                    updated_at = CURRENT_TIMESTAMP
            ");

            $insert->execute([
                ':user_id' => $userId,
                ':code_hash' => $hash,
                ':encrypted_payload' => $encrypted,
                ':version' => LOVEMI_PROFILE_CODE_VERSION,
            ]);

            return $code;

        } catch (Throwable $e) {
            if ($attempt === 9) {
                throw $e;
            }
        }
    }

    throw new RuntimeException(
        'Unable to generate profile code.'
    );
}

function lovemiResolveProfileCode(
    PDO $pdo,
    string $code
): array|false {
    $code = trim($code);

    if ($code === '') {
        return false;
    }

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS profile_codes (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            user_id BIGINT UNSIGNED NOT NULL,
            code_hash CHAR(64) NOT NULL,
            encrypted_payload TEXT NOT NULL,
            version SMALLINT UNSIGNED NOT NULL DEFAULT 2,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_profile_code_user (user_id),
            UNIQUE KEY uq_profile_code_hash (code_hash)
        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    ");

    $hash = hash(
        'sha256',
        $code
    );

    $stmt = $pdo->prepare("
        SELECT
            user_id,
            code_hash,
            encrypted_payload,
            version
        FROM profile_codes
        WHERE code_hash = :code_hash
          AND version = :version
        LIMIT 1
    ");

    $stmt->execute([
        ':code_hash' => $hash,
        ':version' => LOVEMI_PROFILE_CODE_VERSION,
    ]);

    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row) {
        return false;
    }

    $payload = lovemiDecryptProfilePayload(
        (string)$row['encrypted_payload']
    );

    if (!is_array($payload)) {
        return false;
    }

    if (
        (int)($payload['user_id'] ?? 0)
        !==
        (int)$row['user_id']
    ) {
        return false;
    }

    if (
        (string)($payload['code'] ?? '')
        !==
        $code
    ) {
        return false;
    }

    if (
        (int)($payload['version'] ?? 0)
        !==
        LOVEMI_PROFILE_CODE_VERSION
    ) {
        return false;
    }

    return [
        'user_id' => (int)$row['user_id'],
        'version' => (int)$row['version'],
    ];
}