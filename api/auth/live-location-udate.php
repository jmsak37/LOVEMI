<?php

/**
 * ============================================================
 * LOVEMI - LIVE LOCATION UPDATE
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\auth\live-location-udate.php
 *
 * PURPOSE
 *
 * - Store the user's latest location after login.
 * - Respect the user's live-location preference.
 * - Recognize the browser/device using a client device ID.
 * - Detect a new device.
 * - Send an official LOVEMI security email when a new device
 *   signs in.
 *
 * ACTIONS
 *
 * POST action=location
 *
 * POST action=preference
 *
 * GET  action=preference
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   REQUIRED FILES
============================================================ */

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';


/* ============================================================
   HEADERS
============================================================ */

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   SESSION
============================================================ */

if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function locationResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   CURRENT USER
============================================================ */

$userId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION['lovemi_session_token']
            ??
            ''
        )
    );


if (
    $userId <= 0
    ||
    $sessionToken === ''
) {

    locationResponse(
        false,
        'You must be signed in before location can be updated.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
    );

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOCATION DB] '
        .
        $e->getMessage()
    );

    locationResponse(
        false,
        'Unable to connect to the LOVEMI database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   VERIFY CURRENT SESSION
============================================================ */

$sessionHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $sessionStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                device_id,
                two_factor_passed,
                expires_at,
                revoked_at

            FROM user_sessions

            WHERE user_id = :user_id

              AND session_token_hash = :token_hash

            LIMIT 1
            "
        );


    $sessionStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':token_hash' =>
                $sessionHash

        ]
    );


    $sessionRow =
        $sessionStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOCATION SESSION QUERY] '
        .
        $e->getMessage()
    );

    locationResponse(
        false,
        'Unable to verify the current login session.',
        [
            'code' =>
                'SESSION_QUERY_FAILED'
        ],
        500
    );

}


if (
    !$sessionRow
) {

    locationResponse(
        false,
        'Your login session could not be verified.',
        [
            'code' =>
                'SESSION_INVALID'
        ],
        401
    );

}


if (
    (int)$sessionRow['two_factor_passed'] !== 1
) {

    locationResponse(
        false,
        'Your login has not completed two-step verification.',
        [
            'code' =>
                'TWO_FACTOR_NOT_COMPLETED'
        ],
        403
    );

}


if (
    !empty(
        $sessionRow['revoked_at']
    )
) {

    locationResponse(
        false,
        'This login session is no longer active.',
        [
            'code' =>
                'SESSION_REVOKED'
        ],
        401
    );

}


if (
    !empty(
        $sessionRow['expires_at']
    )
    &&
    strtotime(
        (string)$sessionRow['expires_at']
    ) < time()
) {

    locationResponse(
        false,
        'Your login session has expired.',
        [
            'code' =>
                'SESSION_EXPIRED'
        ],
        401
    );

}


/* ============================================================
   KEEP SESSION ACTIVITY CURRENT
============================================================ */

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $activity->execute(
        [
            ':id' =>
                (int)$sessionRow['id']
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOCATION SESSION ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   CURRENT REQUEST METHOD
============================================================ */

$method =
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ?? ''
        )
    );


/* ============================================================
   GET PREFERENCE
============================================================ */

if (
    $method === 'GET'
) {

    $action =
        trim(
            (string)(
                $_GET['action']
                ??
                ''
            )
        );


    if (
        $action !== 'preference'
    ) {

        locationResponse(
            false,
            'Invalid location request.',
            [
                'code' =>
                    'INVALID_ACTION'
            ],
            400
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                SELECT
                    live_location_enabled

                FROM user_location_preferences

                WHERE user_id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $row =
            $stmt->fetch(
                PDO::FETCH_ASSOC
            );


        $enabled =
            $row
                ? (bool)$row['live_location_enabled']
                : true;


        locationResponse(
            true,
            'Live-location preference loaded.',
            [
                'live_location_enabled' =>
                    $enabled
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI LOCATION PREF GET] '
            .
            $e->getMessage()
        );


        locationResponse(
            false,
            'Unable to load your location preference.',
            [
                'code' =>
                    'PREFERENCE_QUERY_FAILED'
            ],
            500
        );

    }

}


/* ============================================================
   POST ONLY
============================================================ */

if (
    $method !== 'POST'
) {

    locationResponse(
        false,
        'Only GET and POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   READ BODY
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)$raw,
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


$action =
    trim(
        (string)(
            $input['action']
            ??
            ''
        )
    );


/* ============================================================
   PREFERENCE UPDATE
============================================================ */

if (
    $action === 'preference'
) {

    if (
        !array_key_exists(
            'enabled',
            $input
        )
    ) {

        locationResponse(
            false,
            'The location preference is required.',
            [
                'code' =>
                    'PREFERENCE_REQUIRED'
            ],
            422
        );

    }


    $enabled =
        filter_var(
            $input['enabled'],
            FILTER_VALIDATE_BOOLEAN,
            FILTER_NULL_ON_FAILURE
        );


    if (
        $enabled === null
    ) {

        locationResponse(
            false,
            'Invalid location preference.',
            [
                'code' =>
                    'PREFERENCE_INVALID'
            ],
            422
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                INSERT INTO user_location_preferences
                (
                    user_id,
                    live_location_enabled
                )
                VALUES
                (
                    :user_id,
                    :enabled
                )
                ON DUPLICATE KEY UPDATE

                    live_location_enabled =
                        VALUES(live_location_enabled),

                    updated_at =
                        CURRENT_TIMESTAMP
                "
            );


        $stmt->execute(
            [

                ':user_id' =>
                    $userId,

                ':enabled' =>
                    $enabled ? 1 : 0

            ]
        );


        /*
         * When location is disabled, remove the stored
         * live location from the user's active record.
         */

        if (
            !$enabled
        ) {

            $deleteLocation =
                $pdo->prepare(
                    "
                    DELETE FROM user_live_locations

                    WHERE user_id = :user_id

                    LIMIT 1
                    "
                );


            $deleteLocation->execute(
                [
                    ':user_id' =>
                        $userId
                ]
            );

        }


        locationResponse(
            true,
            $enabled
                ? 'Live location has been enabled.'
                : 'Live location has been disabled.',
            [
                'live_location_enabled' =>
                    $enabled
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI LOCATION PREF UPDATE] '
            .
            $e->getMessage()
        );


        locationResponse(
            false,
            'Unable to update your live-location preference.',
            [
                'code' =>
                    'PREFERENCE_UPDATE_FAILED'
            ],
            500
        );

    }

}


/* ============================================================
   LOCATION UPDATE
============================================================ */

if (
    $action !== 'location'
) {

    /*
     * Older clients may omit action.
     *
     * Treat the presence of latitude/longitude as a location
     * update for compatibility.
     */

    if (
        !isset(
            $input['latitude'],
            $input['longitude']
        )
    ) {

        locationResponse(
            false,
            'Invalid location request.',
            [
                'code' =>
                    'INVALID_ACTION'
            ],
            400
        );

    }

}


/* ============================================================
   CHECK LOCATION PREFERENCE
============================================================ */

try {

    $preferenceStmt =
        $pdo->prepare(
            "
            SELECT
                live_location_enabled

            FROM user_location_preferences

            WHERE user_id = :user_id

            LIMIT 1
            "
        );


    $preferenceStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $preference =
        $preferenceStmt->fetch(
            PDO::FETCH_ASSOC
        );


    /*
     * Default is enabled for existing accounts.
     */

    $locationEnabled =
        $preference
            ? (bool)$preference['live_location_enabled']
            : true;

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOCATION PREF CHECK] '
        .
        $e->getMessage()
    );


    locationResponse(
        false,
        'Unable to check your location setting.',
        [
            'code' =>
                'PREFERENCE_CHECK_FAILED'
        ],
        500
    );

}


if (
    !$locationEnabled
) {

    locationResponse(
        true,
        'Live location is disabled in your account settings.',
        [
            'location_updated' =>
                false,

            'live_location_enabled' =>
                false
        ]
    );

}


/* ============================================================
   LOCATION INPUT
============================================================ */

$latitude =
    filter_var(
        $input['latitude'] ?? null,
        FILTER_VALIDATE_FLOAT
    );


$longitude =
    filter_var(
        $input['longitude'] ?? null,
        FILTER_VALIDATE_FLOAT
    );


$accuracy =
    filter_var(
        $input['accuracy']
        ??
        $input['accuracy_meters']
        ??
        null,
        FILTER_VALIDATE_FLOAT
    );


$altitude =
    filter_var(
        $input['altitude']
        ??
        $input['altitude_meters']
        ??
        null,
        FILTER_VALIDATE_FLOAT
    );


$heading =
    filter_var(
        $input['heading'] ?? null,
        FILTER_VALIDATE_FLOAT
    );


$speed =
    filter_var(
        $input['speed']
        ??
        $input['speed_mps']
        ??
        null,
        FILTER_VALIDATE_FLOAT
    );


$countryName =
    trim(
        (string)(
            $input['country_name']
            ??
            ''
        )
    );


$regionName =
    trim(
        (string)(
            $input['region_name']
            ??
            ''
        )
    );


$cityName =
    trim(
        (string)(
            $input['city_name']
            ??
            ''
        )
    );


$deviceId =
    trim(
        (string)(
            $input['device_id']
            ??
            ''
        )
    );


$deviceName =
    trim(
        (string)(
            $input['device_name']
            ??
            ''
        )
    );


$browserName =
    trim(
        (string)(
            $input['browser_name']
            ??
            ''
        )
    );


$operatingSystem =
    trim(
        (string)(
            $input['operating_system']
            ??
            ''
        )
    );


/* ============================================================
   VALIDATE COORDINATES
============================================================ */

if (
    $latitude === false
    ||
    $longitude === false
) {

    locationResponse(
        false,
        'A valid latitude and longitude are required.',
        [
            'code' =>
                'LOCATION_REQUIRED'
        ],
        422
    );

}


if (
    $latitude < -90
    ||
    $latitude > 90
) {

    locationResponse(
        false,
        'Invalid latitude.',
        [
            'code' =>
                'LATITUDE_INVALID'
        ],
        422
    );

}


if (
    $longitude < -180
    ||
    $longitude > 180
) {

    locationResponse(
        false,
        'Invalid longitude.',
        [
            'code' =>
                'LONGITUDE_INVALID'
        ],
        422
    );

}


if (
    $accuracy !== false
    &&
    (
        $accuracy < 0
        ||
        $accuracy > 100000
    )
) {

    $accuracy =
        null;

}


if (
    $altitude !== false
    &&
    (
        $altitude < -2000
        ||
        $altitude > 100000
    )
) {

    $altitude =
        null;

}


if (
    $heading !== false
    &&
    (
        $heading < 0
        ||
        $heading > 360
    )
) {

    $heading =
        null;

}


if (
    $speed !== false
    &&
    (
        $speed < 0
        ||
        $speed > 1000
    )
) {

    $speed =
        null;

}


/* ============================================================
   NORMALIZE TEXT
============================================================ */

$countryName =
    mb_substr(
        $countryName,
        0,
        150
    );


$regionName =
    mb_substr(
        $regionName,
        0,
        150
    );


$cityName =
    mb_substr(
        $cityName,
        0,
        150
    );


$deviceId =
    mb_substr(
        $deviceId,
        0,
        128
    );


$deviceName =
    mb_substr(
        $deviceName,
        0,
        255
    );


$browserName =
    mb_substr(
        $browserName,
        0,
        100
    );


$operatingSystem =
    mb_substr(
        $operatingSystem,
        0,
        150
    );


/* ============================================================
   FALLBACK DEVICE ID
============================================================ */

if (
    $deviceId === ''
) {

    /*
     * The browser should normally create this value.
     *
     * Server fallback is deliberately generated per session.
     */

    $deviceId =
        'server-session-'
        .
        substr(
            hash(
                'sha256',
                $sessionHash
            ),
            0,
            32
        );

}


/* ============================================================
   CURRENT IP
============================================================ */

$ipAddress =
    trim(
        (string)(
            $_SERVER['REMOTE_ADDR']
            ??
            ''
        )
    );


if (
    strlen($ipAddress) > 45
) {

    $ipAddress =
        substr(
            $ipAddress,
            0,
            45
        );

}


/* ============================================================
   STORE LOCATION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Insert or update current live location.
     */

    $locationStmt =
        $pdo->prepare(
            "
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
                :country_name,
                :region_name,
                :city_name,
                1,
                CURRENT_TIMESTAMP
            )
            ON DUPLICATE KEY UPDATE

                latitude =
                    VALUES(latitude),

                longitude =
                    VALUES(longitude),

                accuracy_meters =
                    VALUES(accuracy_meters),

                altitude_meters =
                    VALUES(altitude_meters),

                heading =
                    VALUES(heading),

                speed_mps =
                    VALUES(speed_mps),

                country_name =
                    VALUES(country_name),

                region_name =
                    VALUES(region_name),

                city_name =
                    VALUES(city_name),

                location_enabled =
                    1,

                last_updated_at =
                    CURRENT_TIMESTAMP
            "
        );


    $locationStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':latitude' =>
                $latitude,

            ':longitude' =>
                $longitude,

            ':accuracy' =>
                $accuracy !== false
                    ? $accuracy
                    : null,

            ':altitude' =>
                $altitude !== false
                    ? $altitude
                    : null,

            ':heading' =>
                $heading !== false
                    ? $heading
                    : null,

            ':speed' =>
                $speed !== false
                    ? $speed
                    : null,

            ':country_name' =>
                $countryName !== ''
                    ? $countryName
                    : null,

            ':region_name' =>
                $regionName !== ''
                    ? $regionName
                    : null,

            ':city_name' =>
                $cityName !== ''
                    ? $cityName
                    : null

        ]
    );


    /*
     * Update current session with the client device ID.
     */

    $sessionDeviceStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                device_id = :device_id

            WHERE id = :id

            LIMIT 1
            "
        );


    $sessionDeviceStmt->execute(
        [

            ':device_id' =>
                $deviceId,

            ':id' =>
                (int)$sessionRow['id']

        ]
    );


    /*
     * Check whether this device has been seen before.
     */

    $deviceCheckStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                is_trusted

            FROM user_devices

            WHERE user_id = :user_id

              AND device_id = :device_id

            LIMIT 1
            "
        );


    $deviceCheckStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':device_id' =>
                $deviceId

        ]
    );


    $existingDevice =
        $deviceCheckStmt->fetch(
            PDO::FETCH_ASSOC
        );


    $isNewDevice =
        !$existingDevice;


    if (
        $existingDevice
    ) {

        $updateDevice =
            $pdo->prepare(
                "
                UPDATE user_devices

                SET

                    device_name =
                        NULLIF(
                            :device_name,
                            ''
                        ),

                    browser_name =
                        NULLIF(
                            :browser_name,
                            ''
                        ),

                    operating_system =
                        NULLIF(
                            :operating_system,
                            ''
                        ),

                    user_agent =
                        :user_agent,

                    last_seen_at =
                        CURRENT_TIMESTAMP,

                    last_ip_address =
                        :ip_address,

                    last_country =
                        NULLIF(
                            :country_name,
                            ''
                        ),

                    last_region =
                        NULLIF(
                            :region_name,
                            ''
                        ),

                    last_city =
                        NULLIF(
                            :city_name,
                            ''
                        )

                WHERE id = :id

                LIMIT 1
                "
            );


        $updateDevice->execute(
            [

                ':device_name' =>
                    $deviceName,

                ':browser_name' =>
                    $browserName,

                ':operating_system' =>
                    $operatingSystem,

                ':user_agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null,

                ':ip_address' =>
                    $ipAddress !== ''
                        ? $ipAddress
                        : null,

                ':country_name' =>
                    $countryName,

                ':region_name' =>
                    $regionName,

                ':city_name' =>
                    $cityName,

                ':id' =>
                    (int)$existingDevice['id']

            ]
        );

    } else {

        $insertDevice =
            $pdo->prepare(
                "
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
                    last_city,
                    is_trusted
                )
                VALUES
                (
                    :user_id,
                    :device_id,
                    NULLIF(:device_name, ''),
                    NULLIF(:browser_name, ''),
                    NULLIF(:operating_system, ''),
                    :user_agent,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP,
                    :ip_address,
                    NULLIF(:country_name, ''),
                    NULLIF(:region_name, ''),
                    NULLIF(:city_name, ''),
                    0
                )
                "
            );


        $insertDevice->execute(
            [

                ':user_id' =>
                    $userId,

                ':device_id' =>
                    $deviceId,

                ':device_name' =>
                    $deviceName,

                ':browser_name' =>
                    $browserName,

                ':operating_system' =>
                    $operatingSystem,

                ':user_agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null,

                ':ip_address' =>
                    $ipAddress !== ''
                        ? $ipAddress
                        : null,

                ':country_name' =>
                    $countryName,

                ':region_name' =>
                    $regionName,

                ':city_name' =>
                    $cityName

            ]
        );

    }


    $pdo->commit();


} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI LOCATION SAVE] '
        .
        $e->getMessage()
    );


    locationResponse(
        false,
        'Unable to save your location.',
        [
            'code' =>
                'LOCATION_SAVE_FAILED'
        ],
        500
    );

}


/* ============================================================
   NEW DEVICE SECURITY EMAIL
============================================================ */

if (
    $isNewDevice
) {

    try {

        $userStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    full_names,
                    email

                FROM users

                WHERE id = :id

                LIMIT 1
                "
            );


        $userStmt->execute(
            [
                ':id' =>
                    $userId
            ]
        );


        $user =
            $userStmt->fetch(
                PDO::FETCH_ASSOC
            );


        if (
            $user
        ) {

            $safeName =
                htmlspecialchars(
                    (string)$user['full_names'],
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeCity =
                htmlspecialchars(
                    $cityName !== ''
                        ? $cityName
                        : 'Location unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeRegion =
                htmlspecialchars(
                    $regionName !== ''
                        ? $regionName
                        : 'Location unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeCountry =
                htmlspecialchars(
                    $countryName !== ''
                        ? $countryName
                        : 'Location unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeIp =
                htmlspecialchars(
                    $ipAddress !== ''
                        ? $ipAddress
                        : 'Unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeDevice =
                htmlspecialchars(
                    $deviceName !== ''
                        ? $deviceName
                        : 'Unknown device',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeBrowser =
                htmlspecialchars(
                    $browserName !== ''
                        ? $browserName
                        : 'Browser information unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeOperatingSystem =
                htmlspecialchars(
                    $operatingSystem !== ''
                        ? $operatingSystem
                        : 'Operating system unavailable',
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $safeDeviceId =
                htmlspecialchars(
                    $deviceId,
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $loginDate =
                date(
                    'F j, Y \a\t g:i A'
                );


            $loginUrl =
                lovemiLocationAppUrl()
                .
                '/login.html';


            $safeLoginUrl =
                htmlspecialchars(
                    $loginUrl,
                    ENT_QUOTES |
                    ENT_HTML5,
                    'UTF-8'
                );


            $html = <<<HTML
<!DOCTYPE html>

<html lang="en">

<head>

<meta charset="UTF-8">

<meta
    name="viewport"
    content="width=device-width,initial-scale=1.0"
>

<title>LOVEMI - New Sign-In</title>

</head>

<body
style="
    margin:0;
    padding:0;
    background:#f7f7fb;
    font-family:Arial,Helvetica,sans-serif;
    color:#18181b;
"
>

<div
style="
    width:100%;
    padding:35px 15px;
"
>

<div
style="
    max-width:620px;
    margin:0 auto;
    background:#ffffff;
    border:1px solid #e8e8ef;
    border-radius:20px;
    overflow:hidden;
    box-shadow:0 12px 35px rgba(24,24,27,.08);
"
>

<div
style="
    padding:28px 30px;
    background:linear-gradient(135deg,#7c3aed,#ec4899);
    color:#ffffff;
"
>

<div
style="
    font-family:Georgia,serif;
    font-size:28px;
    font-weight:800;
"
>
LOVEMI
</div>

<div
style="
    margin-top:5px;
    font-size:12px;
    opacity:.95;
"
>
Discover • Connect • Meet
</div>

</div>

<div
style="
    padding:32px 30px;
"
>

<div
style="
    display:inline-block;
    padding:7px 12px;
    border-radius:999px;
    background:#fff7ed;
    color:#c2410c;
    font-size:11px;
    font-weight:700;
"
>
NEW SIGN-IN DETECTED
</div>

<h1
style="
    margin:15px 0 12px;
    font-size:25px;
"
>
A new device signed in to your LOVEMI account
</h1>

<p
style="
    font-size:14px;
    line-height:1.8;
    margin:0 0 15px;
"
>
Hello <strong>{$safeName}</strong>,
</p>

<p
style="
    font-size:14px;
    line-height:1.8;
    color:#3f3f46;
"
>
LOVEMI detected a successful sign-in from a device
that has not previously been associated with your account.
</p>

<div
style="
    margin:24px 0;
    padding:20px;
    background:#fafafa;
    border:1px solid #ececf2;
    border-radius:14px;
"
>

<table
width="100%"
cellpadding="0"
cellspacing="0"
border="0"
style="
    font-size:12px;
    line-height:1.7;
"
>

<tr>
<td style="padding:5px 0;color:#71717a;width:38%;">
Date
</td>
<td style="padding:5px 0;font-weight:600;">
{$loginDate}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
Device
</td>
<td style="padding:5px 0;font-weight:600;">
{$safeDevice}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
Browser
</td>
<td style="padding:5px 0;font-weight:600;">
{$safeBrowser}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
Operating system
</td>
<td style="padding:5px 0;font-weight:600;">
{$safeOperatingSystem}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
IP address
</td>
<td style="padding:5px 0;font-weight:600;">
{$safeIp}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
Location
</td>
<td style="padding:5px 0;font-weight:600;">
{$safeCity}, {$safeRegion}, {$safeCountry}
</td>
</tr>

<tr>
<td style="padding:5px 0;color:#71717a;">
Device ID
</td>
<td style="
    padding:5px 0;
    font-weight:600;
    word-break:break-all;
">
{$safeDeviceId}
</td>
</tr>

</table>

</div>

<div
style="
    margin:24px 0;
    padding:18px 20px;
    background:#f0fdf4;
    border:1px solid #bbf7d0;
    border-radius:14px;
"
>

<div
style="
    font-size:13px;
    font-weight:700;
    color:#166534;
"
>
✓ Sign-in completed successfully
</div>

<div
style="
    margin-top:7px;
    font-size:12px;
    line-height:1.7;
    color:#3f6212;
"
>
Your LOVEMI account was accessed successfully using
two-step verification.
</div>

</div>

<div
style="
    margin:24px 0;
    padding:18px 20px;
    background:#fff7ed;
    border:1px solid #fed7aa;
    border-radius:14px;
"
>

<div
style="
    font-size:13px;
    font-weight:700;
    color:#9a3412;
"
>
Wasn't you?
</div>

<div
style="
    margin-top:7px;
    font-size:12px;
    line-height:1.7;
    color:#7c2d12;
"
>
Secure your account immediately by signing in,
changing your password if necessary and reviewing
your trusted devices.
</div>

</div>

<div
style="
    text-align:center;
    margin:28px 0 20px;
"
>

<a
href="{$safeLoginUrl}"
style="
    display:inline-block;
    padding:13px 24px;
    border-radius:10px;
    background:linear-gradient(135deg,#7c3aed,#ec4899);
    color:#ffffff;
    text-decoration:none;
    font-size:13px;
    font-weight:700;
"
>
Open LOVEMI
</a>

</div>

<p
style="
    margin:24px 0 0;
    padding-top:18px;
    border-top:1px solid #eeeeF3;
    font-size:11px;
    line-height:1.7;
    color:#71717a;
"
>
LOVEMI will never ask you to send your password,
Google Authenticator code or account security codes
by email.
</p>

</div>

<div
style="
    padding:22px 30px;
    background:#fafafa;
    border-top:1px solid #eeeeF3;
    text-align:center;
"
>

<div
style="
    font-family:Georgia,serif;
    font-size:15px;
    font-weight:700;
"
>
LOVEMI
</div>

<div
style="
    margin-top:5px;
    font-size:11px;
    color:#a1a1aa;
"
>
Discover • Connect • Meet
</div>

<div
style="
    margin-top:10px;
    font-size:10px;
    color:#a1a1aa;
"
>
© {$loginDate} LOVEMI. All rights reserved.
</div>

</div>

</div>

</div>

</body>

</html>
HTML;


            $plainText =
                "LOVEMI - NEW SIGN-IN DETECTED\n\n"
                .
                "Hello {$user['full_names']},\n\n"
                .
                "A new device signed in to your LOVEMI account.\n\n"
                .
                "Date: {$loginDate}\n"
                .
                "Device: "
                .
                ($deviceName ?: 'Unknown device')
                .
                "\n"
                .
                "Browser: "
                .
                ($browserName ?: 'Unavailable')
                .
                "\n"
                .
                "Operating system: "
                .
                ($operatingSystem ?: 'Unavailable')
                .
                "\n"
                .
                "IP address: "
                .
                ($ipAddress ?: 'Unavailable')
                .
                "\n"
                .
                "Location: "
                .
                (
                    $cityName !== ''
                        ? $cityName . ', '
                        : ''
                )
                .
                (
                    $regionName !== ''
                        ? $regionName . ', '
                        : ''
                )
                .
                (
                    $countryName !== ''
                        ? $countryName
                        : 'Unavailable'
                )
                .
                "\n"
                .
                "Device ID: {$deviceId}\n\n"
                .
                "If this was not you, secure your account immediately.\n\n"
                .
                "LOVEMI\n"
                .
                "Discover • Connect • Meet";


            /*
             * Email failure must not make the successful login
             * fail.
             */

            sendLovemiEmail(
                (string)$user['email'],
                (string)$user['full_names'],
                'LOVEMI - New Sign-In Detected',
                $html,
                $plainText
            );

        }

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI NEW DEVICE EMAIL] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   RESPONSE
============================================================ */

locationResponse(
    true,
    'Your live location has been updated.',
    [
        'location_updated' =>
            true,

        'live_location_enabled' =>
            true,

        'latitude' =>
            (float)$latitude,

        'longitude' =>
            (float)$longitude,

        'accuracy' =>
            $accuracy !== false
                ? (float)$accuracy
                : null,

        'new_device' =>
            $isNewDevice
    ]
);


/* ============================================================
   EMAIL BASE URL
============================================================ */

function lovemiLocationAppUrl(): string
{
    $configured =
        trim(
            (string)(
                getenv('LOVEMI_APP_URL')
                ?: ''
            )
        );


    if (
        $configured !== ''
    ) {

        return rtrim(
            $configured,
            '/'
        );

    }


    $https =
        !empty($_SERVER['HTTPS'])
        &&
        strtolower(
            (string)$_SERVER['HTTPS']
        ) !== 'off';


    $scheme =
        $https
            ? 'https'
            : 'http';


    $host =
        trim(
            (string)(
                $_SERVER['HTTP_HOST']
                ?? 'localhost'
            )
        );


    return
        $scheme
        .
        '://'
        .
        $host
        .
        '/LOVEMI';
}
