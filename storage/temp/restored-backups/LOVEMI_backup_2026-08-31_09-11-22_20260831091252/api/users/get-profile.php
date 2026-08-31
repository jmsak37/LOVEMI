<?php
/**
 * ============================================================
 * LOVEMI - GET PROFILE API
 * ============================================================
 *
 * Uses the actual LOVEMI database structure:
 *
 * users
 * profiles
 * countries
 * photos
 * subscriptions
 * connections
 *
 * NO private data is returned unless the viewer is authorized.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function profileResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   AUTHENTICATED USER
============================================================ */

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int)$_SESSION['lovemi_user_id']
        : 0;


/* ============================================================
   REQUESTED USER
============================================================ */

$requestedUserId =
    isset($_GET['user'])
        ? (int)$_GET['user']
        : 0;


/*
 * When no user is provided, load the current user's profile.
 */

$profileUserId =
    $requestedUserId > 0
        ? $requestedUserId
        : $currentUserId;


if ($profileUserId <= 0) {

    profileResponse(
        false,
        'Please log in to view a profile.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET PROFILE DB] ' .
        $e->getMessage()
    );

    profileResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER + PROFILE + COUNTRY
============================================================ */

try {

    $stmt = $pdo->prepare(
        "
        SELECT

            u.id,
            u.username,
            u.full_names,
            u.gender,
            u.email,
            u.country_id,
            u.phone_number,
            u.date_of_birth,
            u.email_verified,
            u.phone_verified,
            u.identity_verified,
            u.age_verified,
            u.is_active,
            u.is_suspended,
            u.is_deleted,
            u.last_seen_at,
            u.created_at,

            c.name AS country_name,
            c.iso2 AS country_iso2,
            c.iso3 AS country_iso3,
            c.phone_code AS country_phone_code,

            p.id AS profile_id,
            p.display_name,
            p.bio,
            p.occupation,
            p.education,
            p.city,
            p.relationship_status,
            p.looking_for,
            p.interests,
            p.profile_visibility,
            p.show_online_status,
            p.allow_messages

        FROM users u

        LEFT JOIN countries c
            ON c.id = u.country_id

        LEFT JOIN profiles p
            ON p.user_id = u.id

        WHERE u.id = :user_id

        LIMIT 1
        "
    );

    $stmt->execute(
        [
            ':user_id' => $profileUserId
        ]
    );

    $user = $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET PROFILE QUERY] ' .
        $e->getMessage()
    );

    profileResponse(
        false,
        'The profile could not be loaded.',
        [
            'code' => 'PROFILE_QUERY_ERROR'
        ],
        500
    );
}


if (!$user) {

    profileResponse(
        false,
        'The requested profile could not be found.',
        [
            'code' => 'PROFILE_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   ACCOUNT CHECK
============================================================ */

if (
    (bool)$user['is_deleted'] ||
    !(bool)$user['is_active'] ||
    (bool)$user['is_suspended']
) {

    profileResponse(
        false,
        'This profile is not currently available.',
        [
            'code' => 'PROFILE_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   PROFILE VISIBILITY
============================================================ */

$isOwner =
    $currentUserId > 0 &&
    $currentUserId === $profileUserId;


$profileVisibility =
    strtolower(
        (string)(
            $user['profile_visibility']
            ?? 'public'
        )
    );


if (
    !$isOwner &&
    $profileVisibility === 'private'
) {

    profileResponse(
        false,
        'This profile is private.',
        [
            'code' => 'PROFILE_PRIVATE'
        ],
        403
    );
}


/* ============================================================
   APPROVED PRIMARY PHOTO
============================================================ */

try {

    $photoStmt = $pdo->prepare(
        "
        SELECT

            id,
            file_name,
            file_path,
            thumbnail_path,
            mime_type,
            width,
            height,
            photo_type,
            approval_status,
            is_primary,
            is_featured,
            uploaded_at,
            approved_at

        FROM photos

        WHERE user_id = :user_id

          AND approval_status = 'approved'

          AND photo_type = 'profile'

        ORDER BY

            is_primary DESC,
            is_featured DESC,
            approved_at DESC,
            id DESC

        LIMIT 1
        "
    );

    $photoStmt->execute(
        [
            ':user_id' => $profileUserId
        ]
    );

    $photo = $photoStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI GET PROFILE PHOTO] ' .
        $e->getMessage()
    );

    $photo = false;
}


/* ============================================================
   ONLINE STATUS
============================================================ */

$isOnline = false;


if (
    (bool)(
        $user['show_online_status']
        ??
        true
    )
) {

    $lastSeen =
        $user['last_seen_at'];

    if ($lastSeen) {

        try {

            $lastSeenTime =
                new DateTime(
                    (string)$lastSeen
                );

            $now =
                new DateTime();

            $difference =
                $now->getTimestamp()
                -
                $lastSeenTime->getTimestamp();

            $isOnline =
                $difference >= 0 &&
                $difference <= 600;

        } catch (Throwable $e) {

            $isOnline =
                false;
        }
    }
}


/* ============================================================
   CONNECTION STATUS
============================================================ */

$connectionStatus = null;

if (
    $currentUserId > 0 &&
    !$isOwner
) {

    try {

        $connectionStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    status,
                    user_id,
                    connected_user_id,
                    initiated_by,
                    connected_at

                FROM connections

                WHERE
                    (
                        user_id = :me1
                        AND
                        connected_user_id = :other1
                    )

                    OR

                    (
                        user_id = :other2
                        AND
                        connected_user_id = :me2
                    )

                ORDER BY id DESC

                LIMIT 1
                "
            );

        $connectionStmt->execute(
            [
                ':me1' =>
                    $currentUserId,

                ':other1' =>
                    $profileUserId,

                ':other2' =>
                    $profileUserId,

                ':me2' =>
                    $currentUserId
            ]
        );

        $connection =
            $connectionStmt->fetch();

        if ($connection) {

            $connectionStatus =
                (string)$connection['status'];

        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PROFILE CONNECTION] ' .
            $e->getMessage()
        );
    }
}


/* ============================================================
   PREMIUM ACCESS
============================================================ */

$viewerHasPremium = false;


if (
    $currentUserId > 0
) {

    try {

        $premiumStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM subscriptions

                WHERE user_id = :user_id

                  AND status = 'active'

                  AND start_at <= CURRENT_TIMESTAMP

                  AND end_at > CURRENT_TIMESTAMP

                LIMIT 1
                "
            );

        $premiumStmt->execute(
            [
                ':user_id' =>
                    $currentUserId
            ]
        );

        $viewerHasPremium =
            (bool)$premiumStmt->fetch();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PROFILE PREMIUM] '
            .
            $e->getMessage()
        );
    }
}


/* ============================================================
   PRIVATE CONTACT ACCESS
============================================================ */

/*
 * Phone number is returned only:
 *
 * 1. To the account owner
 * OR
 * 2. To a connected viewer who currently has Premium.
 */

$canViewPhone =
    $isOwner
    ||
    (
        $viewerHasPremium
        &&
        $connectionStatus !== null
        &&
        in_array(
            strtolower(
                $connectionStatus
            ),
            [
                'accepted',
                'connected'
            ],
            true
        )
    );


$phoneNumber =
    $canViewPhone
        ? (string)$user['phone_number']
        : null;


/* ============================================================
   RETURN PROFILE
============================================================ */

$profile = [

    'id' =>
        (int)$user['id'],

    'username' =>
        (string)$user['username'],

    'full_name' =>
        (string)$user['full_names'],

    'full_names' =>
        (string)$user['full_names'],

    'display_name' =>
        $user['display_name']
            ?: $user['full_names'],

    'gender' =>
        (string)$user['gender'],

    'email' =>
        $isOwner
            ? (string)$user['email']
            : null,

    'country_id' =>
        (int)$user['country_id'],

    'country_name' =>
        $user['country_name']
            ? (string)$user['country_name']
            : null,

    'country_iso2' =>
        $user['country_iso2']
            ? strtoupper(
                (string)$user['country_iso2']
            )
            : null,

    'country_iso3' =>
        $user['country_iso3']
            ? strtoupper(
                (string)$user['country_iso3']
            )
            : null,

    'country_phone_code' =>
        $user['country_phone_code']
            ? (string)$user['country_phone_code']
            : null,

    'phone_number' =>
        $phoneNumber,

    'phone_visible' =>
        $canViewPhone,

    'date_of_birth' =>
        $isOwner
            ? $user['date_of_birth']
            : null,

    'email_verified' =>
        (bool)$user['email_verified'],

    'phone_verified' =>
        (bool)$user['phone_verified'],

    'identity_verified' =>
        (bool)$user['identity_verified'],

    'age_verified' =>
        (bool)$user['age_verified'],

    'bio' =>
        $user['bio']
            ? (string)$user['bio']
            : '',

    'occupation' =>
        $user['occupation']
            ? (string)$user['occupation']
            : '',

    'education' =>
        $user['education']
            ? (string)$user['education']
            : '',

    'city' =>
        $user['city']
            ? (string)$user['city']
            : '',

    'location' =>
        $user['city']
            ? (string)$user['city']
            : '',

    'relationship_status' =>
        $user['relationship_status']
            ? (string)$user['relationship_status']
            : '',

    'looking_for' =>
        $user['looking_for']
            ? (string)$user['looking_for']
            : '',

    'interests' =>
        $user['interests']
            ? (string)$user['interests']
            : '',

    'profile_visibility' =>
        (string)(
            $user['profile_visibility']
            ?? 'public'
        ),

    'show_online_status' =>
        (bool)(
            $user['show_online_status']
            ?? true
        ),

    'allow_messages' =>
        (bool)(
            $user['allow_messages']
            ?? true
        ),

    'is_online' =>
        $isOnline,

    'connection_status' =>
        $connectionStatus,

    'viewer_has_premium' =>
        $viewerHasPremium,

    'profile_photo' =>
        $photo
            ? (
                $photo['thumbnail_path']
                ?: $photo['file_path']
            )
            : null,

    'profile_photo_original' =>
        $isOwner && $photo
            ? $photo['file_path']
            : null,

    'profile_photo_status' =>
        $photo
            ? (string)$photo['approval_status']
            : 'none',

    'created_at' =>
        (string)$user['created_at']

];


/* ============================================================
   RESPONSE
============================================================ */

profileResponse(
    true,
    'Profile loaded successfully.',
    [
        'profile' =>
            $profile,

        'data' =>
            $profile
    ]
);