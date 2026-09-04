<?php

declare(strict_types=1);

/**
 * LOVEMI profile-code configuration.
 *
 * The public code is an opaque random lookup key.
 * The database stores a SHA-256 hash of that code and an encrypted
 * payload containing the real database user id.
 */

const LOVEMI_PROFILE_CODE_VERSION = 2;
const LOVEMI_PROFILE_CODE_CIPHER = 'aes-256-gcm';

function lovemiProfileCodeSecret(): string
{
    $secret = getenv('LOVEMI_PROFILE_SECRET');

    if (!is_string($secret) || $secret === '') {
        // Keep this identical for generator/resolver on localhost.
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
    $value = strtr($value, '-_', '+/');

    $remainder = strlen($value) % 4;

    if ($remainder !== 0) {
        $value .= str_repeat('=', 4 - $remainder);
    }

    return base64_decode($value, true);
}

/**
 * Encrypt the payload stored in profile_codes.encrypted_payload.
 * AES-256-GCM gives confidentiality + authentication.
 */
function lovemiEncryptProfilePayload(array $payload): string
{
    $method = LOVEMI_PROFILE_CODE_CIPHER;
    $key = hash('sha256', lovemiProfileCodeSecret(), true);
    $ivLength = openssl_cipher_iv_length($method);

    if ($ivLength === false || $ivLength <= 0) {
        throw new RuntimeException('Profile-code encryption is unavailable.');
    }

    $plaintext = json_encode(
        $payload,
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );

    $iv = random_bytes($ivLength);
    $tag = '';

    $ciphertext = openssl_encrypt(
        $plaintext,
        $method,
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($ciphertext === false) {
        throw new RuntimeException('Unable to encrypt the profile-code payload.');
    }

    $envelope = json_encode(
        [
            'version' => LOVEMI_PROFILE_CODE_VERSION,
            'cipher' => $method,
            'iv' => lovemiBase64UrlEncode($iv),
            'tag' => lovemiBase64UrlEncode($tag),
            'ciphertext' => lovemiBase64UrlEncode($ciphertext),
        ],
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR
    );

    return lovemiBase64UrlEncode($envelope);
}

/**
 * Decrypt a current profile-code database payload.
 */
function lovemiDecryptProfilePayload(string $encryptedPayload): array|false
{
    try {
        $envelopeJson = lovemiBase64UrlDecode($encryptedPayload);

        if ($envelopeJson === false) {
            return false;
        }

        $envelope = json_decode($envelopeJson, true, 32, JSON_THROW_ON_ERROR);

        if (!is_array($envelope)) {
            return false;
        }

        $method = (string)($envelope['cipher'] ?? '');

        if ($method !== LOVEMI_PROFILE_CODE_CIPHER) {
            return false;
        }

        $iv = lovemiBase64UrlDecode((string)($envelope['iv'] ?? ''));
        $tag = lovemiBase64UrlDecode((string)($envelope['tag'] ?? ''));
        $ciphertext = lovemiBase64UrlDecode((string)($envelope['ciphertext'] ?? ''));

        if ($iv === false || $tag === false || $ciphertext === false) {
            return false;
        }

        $key = hash('sha256', lovemiProfileCodeSecret(), true);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );

        if ($plaintext === false) {
            return false;
        }

        $payload = json_decode($plaintext, true, 32, JSON_THROW_ON_ERROR);

        return is_array($payload) ? $payload : false;
    } catch (Throwable) {
        return false;
    }
}

/**
 * Backward compatibility for the previous self-contained token format:
 * Base64URL(IV + AES-256-CBC ciphertext + HMAC-SHA256).
 *
 * Valid legacy tokens are migrated into profile_codes automatically.
 */
function lovemiDecryptLegacyProfileToken(string $token): array|false
{
    try {
        $binary = lovemiBase64UrlDecode(rawurldecode($token));

        if ($binary === false || strlen($binary) < 16 + 32 + 1) {
            return false;
        }

        $method = 'AES-256-CBC';
        $ivLength = openssl_cipher_iv_length($method);

        if ($ivLength === false || strlen($binary) <= $ivLength + 32) {
            return false;
        }

        $iv = substr($binary, 0, $ivLength);
        $signature = substr($binary, -32);
        $ciphertext = substr($binary, $ivLength, -32);

        $expected = hash_hmac(
            'sha256',
            $iv . $ciphertext,
            lovemiProfileCodeSecret(),
            true
        );

        if (!hash_equals($expected, $signature)) {
            return false;
        }

        $key = hash('sha256', lovemiProfileCodeSecret(), true);

        $plaintext = openssl_decrypt(
            $ciphertext,
            $method,
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($plaintext === false) {
            return false;
        }

        $payload = json_decode($plaintext, true, 32, JSON_THROW_ON_ERROR);

        return is_array($payload) ? $payload : false;
    } catch (Throwable) {
        return false;
    }
}

/**
 * Resolve an opaque public code into its database user id.
 *
 * The URL never needs to contain the database id.
 */
function lovemiResolveProfileCode(PDO $pdo, string $profileCode): array|false
{
    $profileCode = trim($profileCode);

    if ($profileCode === '') {
        return false;
    }

    $codeHash = hash('sha256', $profileCode);

    $stmt = $pdo->prepare(
        '
        SELECT
            id,
            user_id,
            code_hash,
            encrypted_payload,
            version
        FROM profile_codes
        WHERE code_hash = :code_hash
        ORDER BY id DESC
        LIMIT 1
        '
    );

    $stmt->execute([':code_hash' => $codeHash]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        $payload = lovemiDecryptProfilePayload((string)$row['encrypted_payload']);

        if ($payload === false) {
            return false;
        }

        $userId = (int)($payload['user_id'] ?? 0);
        $payloadCode = (string)($payload['code'] ?? '');
        $version = (int)($payload['version'] ?? 0);

        if ($userId <= 0 || $payloadCode === '' || $version !== LOVEMI_PROFILE_CODE_VERSION) {
            return false;
        }

        if (!hash_equals($profileCode, $payloadCode)) {
            return false;
        }

        if ((int)$row['user_id'] !== $userId) {
            return false;
        }

        if (!hash_equals((string)$row['code_hash'], $codeHash)) {
            return false;
        }

        return [
            'user_id' => $userId,
            'version' => $version,
            'migrated' => false,
        ];
    }

    /* Legacy token migration. */
    $legacyPayload = lovemiDecryptLegacyProfileToken($profileCode);

    if ($legacyPayload === false) {
        return false;
    }

    $legacyUserId = (int)($legacyPayload['user_id'] ?? 0);

    if ($legacyUserId <= 0) {
        return false;
    }

    $newPayload = [
        'user_id' => $legacyUserId,
        'code' => $profileCode,
        'version' => LOVEMI_PROFILE_CODE_VERSION,
        'created_at' => time(),
        'nonce' => bin2hex(random_bytes(16)),
        'migrated_from_version' => (int)($legacyPayload['version'] ?? 1),
    ];

    $encrypted = lovemiEncryptProfilePayload($newPayload);

    $insert = $pdo->prepare(
        '
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
        '
    );

    $insert->execute(
        [
            ':user_id' => $legacyUserId,
            ':code_hash' => $codeHash,
            ':encrypted_payload' => $encrypted,
            ':version' => LOVEMI_PROFILE_CODE_VERSION,
        ]
    );

    return [
        'user_id' => $legacyUserId,
        'version' => LOVEMI_PROFILE_CODE_VERSION,
        'migrated' => true,
    ];
}
