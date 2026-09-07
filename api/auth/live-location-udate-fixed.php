<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function locationResponse(bool $success, string $message, array $data = [], int $status = 200): never
{
    http_response_code($status);
    echo json_encode(
        array_merge(
            ['success' => $success, 'message' => $message],
            $data
        ),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

$userId = (int)($_SESSION['lovemi_user_id'] ?? 0);

if ($userId <= 0) {
    locationResponse(
        false,
        'You must be signed in before location can be updated.',
        ['code' => 'AUTHENTICATION_REQUIRED'],
        401
    );
}

try {
    $pdo = db();
} catch (Throwable $e) {
    error_log('[LOVEMI LOCATION DB] ' . $e->getMessage());
    locationResponse(
        false,
        'Unable to connect to the LOVEMI database.',
        ['code' => 'DATABASE_ERROR'],
        500
    );
}

/*
 * These CREATE TABLE IF NOT EXISTS statements are deliberately defensive.
 * They prevent Settings/Discover from breaking when the live-location
 * migration has not yet been run.
 */
try {
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_location_preferences (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            live_location_enabled TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_live_locations (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            latitude DECIMAL(10,7) NOT NULL,
            longitude DECIMAL(10,7) NOT NULL,
            accuracy_meters DECIMAL(10,2) NULL,
            altitude_meters DECIMAL(10,2) NULL,
            heading DECIMAL(10,2) NULL,
            speed_mps DECIMAL(10,2) NULL,
            country_name VARCHAR(120) NULL,
            region_name VARCHAR(160) NULL,
            city_name VARCHAR(160) NULL,
            location_enabled TINYINT(1) NOT NULL DEFAULT 1,
            last_updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_live_enabled (location_enabled),
            INDEX idx_live_updated (last_updated_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");

    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_devices (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            user_id BIGINT UNSIGNED NOT NULL,
            device_id VARCHAR(191) NOT NULL,
            device_name VARCHAR(150) NULL,
            browser_name VARCHAR(100) NULL,
            operating_system VARCHAR(100) NULL,
            user_agent TEXT NULL,
            first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_ip_address VARCHAR(45) NULL,
            last_country VARCHAR(120) NULL,
            last_region VARCHAR(160) NULL,
            last_city VARCHAR(160) NULL,
            is_trusted TINYINT(1) NOT NULL DEFAULT 0,
            UNIQUE KEY uq_user_device (user_id, device_id),
            INDEX idx_user_devices_user (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
} catch (Throwable $e) {
    error_log('[LOVEMI LOCATION TABLE INIT] ' . $e->getMessage());
    locationResponse(
        false,
        'Unable to prepare live-location storage.',
        ['code' => 'LOCATION_STORAGE_FAILED'],
        500
    );
}

$method = strtoupper((string)($_SERVER['REQUEST_METHOD'] ?? 'GET'));

$raw = file_get_contents('php://input');
$input = json_decode((string)$raw, true);

if (!is_array($input)) {
    $input = $_POST;
}

$action = trim((string)(
    $input['action']
    ?? $_GET['action']
    ?? ''
));

/*
 * GET preference
 */
if ($method === 'GET' && $action === 'preference') {
    try {
        $ensure = $pdo->prepare("
            INSERT INTO user_location_preferences (user_id)
            VALUES (:user_id)
            ON DUPLICATE KEY UPDATE user_id = user_id
        ");
        $ensure->execute([':user_id' => $userId]);

        $stmt = $pdo->prepare("
            SELECT live_location_enabled
            FROM user_location_preferences
            WHERE user_id = :user_id
            LIMIT 1
        ");
        $stmt->execute([':user_id' => $userId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        locationResponse(
            true,
            'Live-location preference loaded.',
            [
                'live_location_enabled' =>
                    (int)($row['live_location_enabled'] ?? 1)
            ]
        );
    } catch (Throwable $e) {
        error_log('[LOVEMI LOCATION PREF GET] ' . $e->getMessage());
        locationResponse(
            false,
            'Unable to load your live-location preference.',
            ['code' => 'PREFERENCE_QUERY_FAILED'],
            500
        );
    }
}

/*
 * All writes are POST only.
 */
if ($method !== 'POST') {
    locationResponse(
        false,
        'Only GET and POST requests are allowed.',
        ['code' => 'METHOD_NOT_ALLOWED'],
        405
    );
}

/*
 * Enable / disable live location.
 *
 * IMPORTANT:
 * Disabling immediately deletes the active live location.
 * This means Discover cannot show another member's stored GPS
 * position after the user turns this control off.
 */
if ($action === 'preference') {
    if (!array_key_exists('enabled', $input)) {
        locationResponse(
            false,
            'The location preference is required.',
            ['code' => 'PREFERENCE_REQUIRED'],
            422
        );
    }

    $enabled = filter_var(
        $input['enabled'],
        FILTER_VALIDATE_BOOLEAN,
        FILTER_NULL_ON_FAILURE
    );

    if ($enabled === null) {
        locationResponse(
            false,
            'Invalid location preference.',
            ['code' => 'PREFERENCE_INVALID'],
            422
        );
    }

    try {
        $pdo->beginTransaction();

        $stmt = $pdo->prepare("
            INSERT INTO user_location_preferences
                (user_id, live_location_enabled)
            VALUES
                (:user_id, :enabled)
            ON DUPLICATE KEY UPDATE
                live_location_enabled = VALUES(live_location_enabled),
                updated_at = CURRENT_TIMESTAMP
        ");

        $stmt->execute([
            ':user_id' => $userId,
            ':enabled' => $enabled ? 1 : 0
        ]);

        if (!$enabled) {
            $delete = $pdo->prepare("
                DELETE FROM user_live_locations
                WHERE user_id = :user_id
                LIMIT 1
            ");
            $delete->execute([':user_id' => $userId]);
        }

        $pdo->commit();

        locationResponse(
            true,
            $enabled
                ? 'Live location has been enabled.'
                : 'Live location has been disabled and your saved live location has been removed.',
            [
                'live_location_enabled' => $enabled ? 1 : 0,
                'location_removed' => $enabled ? false : true
            ]
        );
    } catch (Throwable $e) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }

        error_log('[LOVEMI LOCATION PREFERENCE SAVE] ' . $e->getMessage());

        locationResponse(
            false,
            'Unable to save your live-location preference.',
            ['code' => 'PREFERENCE_UPDATE_FAILED'],
            500
        );
    }
}

/*
 * Save a real browser GPS location.
 *
 * The server accepts coordinates only from an authenticated session.
 * The client supplies reverse-geocoded city/region/country labels.
 */
if ($action === 'location') {
    try {
        $enabledStmt = $pdo->prepare("
            SELECT live_location_enabled
            FROM user_location_preferences
            WHERE user_id = :user_id
            LIMIT 1
        ");
        $enabledStmt->execute([':user_id' => $userId]);
        $pref = $enabledStmt->fetch(PDO::FETCH_ASSOC);

        if ((int)($pref['live_location_enabled'] ?? 1) !== 1) {
            locationResponse(
                false,
                'Live location is disabled in your LOVEMI settings.',
                ['code' => 'LOCATION_DISABLED'],
                403
            );
        }

        $latitude = filter_var(
            $input['latitude'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        $longitude = filter_var(
            $input['longitude'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        if (
            $latitude === false ||
            $latitude === null ||
            $longitude === false ||
            $longitude === null ||
            $latitude < -90 ||
            $latitude > 90 ||
            $longitude < -180 ||
            $longitude > 180
        ) {
            locationResponse(
                false,
                'A valid GPS latitude and longitude are required.',
                ['code' => 'LOCATION_INVALID'],
                422
            );
        }

        $accuracy = filter_var(
            $input['accuracy'] ?? $input['accuracy_meters'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        $altitude = filter_var(
            $input['altitude'] ?? $input['altitude_meters'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        $heading = filter_var(
            $input['heading'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        $speed = filter_var(
            $input['speed'] ?? $input['speed_mps'] ?? null,
            FILTER_VALIDATE_FLOAT
        );

        $country = trim((string)(
            $input['country_name']
            ?? $input['country']
            ?? ''
        ));

        $region = trim((string)(
            $input['region_name']
            ?? $input['region']
            ?? ''
        ));

        $city = trim((string)(
            $input['city_name']
            ?? $input['city']
            ?? ''
        ));

        $deviceId = trim((string)(
            $input['device_id']
            ?? $_SESSION['lovemi_device_id']
            ?? ''
        ));

        $deviceName = trim((string)(
            $input['device_name']
            ?? $_SESSION['lovemi_device_name']
            ?? ''
        ));

        $browser = trim((string)(
            $input['browser_name']
            ?? $_SESSION['lovemi_browser_name']
            ?? ''
        ));

        $operatingSystem = trim((string)(
            $input['operating_system']
            ?? $_SESSION['lovemi_operating_system']
            ?? ''
        ));

        $stmt = $pdo->prepare("
            INSERT INTO user_live_locations
            (
                user_id,
                latitude,
                longitude,
                accuracy_meters,
                altitude_meters,
                heading,
                speed_mps,
                country_name,
                region_name,
                city_name,
                location_enabled,
                last_updated_at
            )
            VALUES
            (
                :user_id,
                :latitude,
                :longitude,
                :accuracy,
                :altitude,
                :heading,
                :speed,
                :country,
                :region,
                :city,
                1,
                CURRENT_TIMESTAMP
            )
            ON DUPLICATE KEY UPDATE
                latitude = VALUES(latitude),
                longitude = VALUES(longitude),
                accuracy_meters = VALUES(accuracy_meters),
                altitude_meters = VALUES(altitude_meters),
                heading = VALUES(heading),
                speed_mps = VALUES(speed_mps),
                country_name = VALUES(country_name),
                region_name = VALUES(region_name),
                city_name = VALUES(city_name),
                location_enabled = 1,
                last_updated_at = CURRENT_TIMESTAMP
        ");

        $stmt->execute([
            ':user_id' => $userId,
            ':latitude' => $latitude,
            ':longitude' => $longitude,
            ':accuracy' => $accuracy !== false ? $accuracy : null,
            ':altitude' => $altitude !== false ? $altitude : null,
            ':heading' => $heading !== false ? $heading : null,
            ':speed' => $speed !== false ? $speed : null,
            ':country' => $country !== '' ? $country : null,
            ':region' => $region !== '' ? $region : null,
            ':city' => $city !== '' ? $city : null
        ]);

        if ($deviceId !== '') {
            $deviceStmt = $pdo->prepare("
                INSERT INTO user_devices
                (
                    user_id,
                    device_id,
                    device_name,
                    browser_name,
                    operating_system,
                    user_agent,
                    first_seen_at,
                    last_seen_at,
                    last_ip_address,
                    last_country,
                    last_region,
                    last_city
                )
                VALUES
                (
                    :user_id,
                    :device_id,
                    :device_name,
                    :browser,
                    :os,
                    :agent,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP,
                    :ip,
                    :country,
                    :region,
                    :city
                )
                ON DUPLICATE KEY UPDATE
                    device_name = VALUES(device_name),
                    browser_name = VALUES(browser_name),
                    operating_system = VALUES(operating_system),
                    user_agent = VALUES(user_agent),
                    last_seen_at = CURRENT_TIMESTAMP,
                    last_ip_address = VALUES(last_ip_address),
                    last_country = VALUES(last_country),
                    last_region = VALUES(last_region),
                    last_city = VALUES(last_city)
            ");

            $deviceStmt->execute([
                ':user_id' => $userId,
                ':device_id' => substr($deviceId, 0, 191),
                ':device_name' => $deviceName !== '' ? $deviceName : null,
                ':browser' => $browser !== '' ? $browser : null,
                ':os' => $operatingSystem !== '' ? $operatingSystem : null,
                ':agent' => $_SERVER['HTTP_USER_AGENT'] ?? null,
                ':ip' => $_SERVER['REMOTE_ADDR'] ?? null,
                ':country' => $country !== '' ? $country : null,
                ':region' => $region !== '' ? $region : null,
                ':city' => $city !== '' ? $city : null
            ]);
        }

        locationResponse(
            true,
            'Your live location has been updated.',
            [
                'location_updated' => true,
                'live_location_enabled' => 1,
                'latitude' => (float)$latitude,
                'longitude' => (float)$longitude,
                'accuracy' =>
                    $accuracy !== false && $accuracy !== null
                        ? (float)$accuracy
                        : null
            ]
        );
    } catch (Throwable $e) {
        error_log('[LOVEMI LOCATION UPDATE] ' . $e->getMessage());

        locationResponse(
            false,
            'Unable to update your live location.',
            ['code' => 'LOCATION_UPDATE_FAILED'],
            500
        );
    }
}

locationResponse(
    false,
    'Invalid location action.',
    ['code' => 'INVALID_ACTION'],
    422
);
