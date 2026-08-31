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


/* ============================================================
   RESPONSE
============================================================ */

function profileViewResponse(
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
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    profileViewResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   TARGET USER
============================================================ */

$targetUserId =
    (int) (
        $_GET['user_id']
        ??
        $_GET['id']
        ??
        0
    );


if ($targetUserId <= 0) {

    profileViewResponse(
        false,
        'User ID is required.',
        [
            'code' => 'USER_ID_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   CURRENT USER
============================================================ */

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE VIEW DB] ' .
        $e->getMessage()
    );

    profileViewResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   LOAD PROFILE
============================================================ */

try {

    $stmt = $pdo->prepare(
        "
        SELECT

            u.id,
            u.username,
            u.full_names,
            u.gender,
            u.country_id,
            u.date_of_birth,

            c.name AS country_name,
            c.iso2,
            c.iso3,
            c.flag_code,

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
            p.allow_messages,

            up.is_online,
            up.last_seen_at

        FROM users u

        INNER JOIN profiles p
            ON p.user_id = u.id

        LEFT JOIN countries c
            ON c.id = u.country_id

        LEFT JOIN user_presence up
            ON up.user_id = u.id

        WHERE u.id = :user_id

        LIMIT 1
        "
    );

    $stmt->execute([
        ':user_id' => $targetUserId
    ]);

    $profile = $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE VIEW QUERY] ' .
        $e->getMessage()
    );

    profileViewResponse(
        false,
        'Unable to load the profile.',
        [
            'code' => 'PROFILE_QUERY_FAILED'
        ],
        500
    );
}


if (!$profile) {

    profileViewResponse(
        false,
        'Profile not found.',
        [
            'code' => 'PROFILE_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   ACCOUNT AVAILABILITY
============================================================ */

try {

    $accountStmt = $pdo->prepare(
        "
        SELECT

            is_active,
            is_suspended,
            is_deleted,
            account_status

        FROM users

        WHERE id = :user_id

        LIMIT 1
        "
    );

    $accountStmt->execute([
        ':user_id' => $targetUserId
    ]);

    $account = $accountStmt->fetch();

} catch (Throwable $e) {

    profileViewResponse(
        false,
        'Unable to verify this account.',
        [
            'code' => 'ACCOUNT_CHECK_FAILED'
        ],
        500
    );
}


if (
    !$account
    ||
    (int) $account['is_deleted'] === 1
    ||
    (int) $account['is_suspended'] === 1
    ||
    (int) $account['is_active'] !== 1
) {

    profileViewResponse(
        false,
        'This profile is not available.',
        [
            'code' => 'PROFILE_UNAVAILABLE'
        ],
        404
    );
}


/* ============================================================
   PRIVACY CHECK
============================================================ */

$isOwner =
    $currentUserId > 0 &&
    $currentUserId === $targetUserId;


/*
|--------------------------------------------------------------------------
| If another user's profile is private, do not expose it.
|--------------------------------------------------------------------------
*/

if (
    !$isOwner
    &&
    $profile['profile_visibility'] === 'private'
) {

    profileViewResponse(
        false,
        'This profile is private.',
        [
            'code' => 'PROFILE_PRIVATE'
        ],
        403
    );
}


/* ============================================================
   BLOCK CHECK
============================================================ */

if (
    $currentUserId > 0
    &&
    !$isOwner
) {

    try {

        $blockStmt = $pdo->prepare(
            "
            SELECT id

            FROM blocked_users

            WHERE
                (
                    user_id = :current_user
                    AND
                    blocked_user_id = :target_user
                )

                OR

                (
                    user_id = :target_user2
                    AND
                    blocked_user_id = :current_user2
                )

            LIMIT 1
            "
        );

        $blockStmt->execute(
            [
                ':current_user' =>
                    $currentUserId,

                ':target_user' =>
                    $targetUserId,

                ':target_user2' =>
                    $targetUserId,

                ':current_user2' =>
                    $currentUserId
            ]
        );

        $blocked =
            $blockStmt->fetch();

    } catch (Throwable $e) {

        $blocked = false;

    }


    if ($blocked) {

        profileViewResponse(
            false,
            'This profile cannot be viewed.',
            [
                'code' =>
                    'PROFILE_BLOCKED'
            ],
            403
        );
    }

}


/* ============================================================
   AGE
============================================================ */

$age = null;

if (
    !empty(
        $profile['date_of_birth']
    )
) {

    try {

        $birthDate =
            new DateTime(
                (string)
                $profile['date_of_birth']
            );

        $today =
            new DateTime();

        $age =
            $birthDate->diff(
                $today
            )->y;

    } catch (Throwable $e) {

        $age = null;

    }

}


/* ============================================================
   ONLINE
============================================================ */

$isOnline =
    (bool)
    $profile['is_online'];


if (
    (int)
    $profile['show_online_status']
    !==
    1
) {

    $isOnline =
        false;

}


if (
    !empty(
        $profile['last_seen_at']
    )
) {

    $lastSeen =
        strtotime(
            (string)
            $profile['last_seen_at']
        );

    if (
        $lastSeen !== false
        &&
        time() - $lastSeen <= 300
        &&
        (int)
        $profile['show_online_status']
        === 1
    ) {

        $isOnline = true;

    }

}


/* ============================================================
   APPROVED PHOTOS
============================================================ */

$photos = [];

try {

    $photoStmt = $pdo->prepare(
        "
        SELECT

            id,
            file_name,
            file_path,
            thumbnail_path,
            mime_type,
            file_size,
            width,
            height,
            photo_type,
            is_primary,
            is_featured,
            uploaded_at

        FROM photos

        WHERE user_id = :user_id

          AND approval_status = 'approved'

        ORDER BY

            is_primary DESC,
            is_featured DESC,
            uploaded_at DESC,
            id DESC
        "
    );

    $photoStmt->execute([
        ':user_id' => $targetUserId
    ]);

    $photoRows =
        $photoStmt->fetchAll();

} catch (Throwable $e) {

    $photoRows = [];

}


foreach (
    $photoRows
    as $photo
) {

    $photos[] = [

        'id' =>
            (int)
            $photo['id'],

        'file_name' =>
            $photo['file_name'],

        'file_path' =>
            $photo['file_path'],

        'thumbnail_path' =>
            $photo['thumbnail_path'],

        'mime_type' =>
            $photo['mime_type'],

        'file_size' =>
            $photo['file_size']
            !==
            null
                ?
                (int)
                $photo['file_size']
                :
                null,

        'width' =>
            $photo['width']
            !==
            null
                ?
                (int)
                $photo['width']
                :
                null,

        'height' =>
            $photo['height']
            !==
            null
                ?
                (int)
                $photo['height']
                :
                null,

        'photo_type' =>
            $photo['photo_type'],

        'is_primary' =>
            (bool)
            $photo['is_primary'],

        'is_featured' =>
            (bool)
            $photo['is_featured'],

        'uploaded_at' =>
            $photo['uploaded_at']

    ];

}


/* ============================================================
   CONNECTION STATUS
============================================================ */

$connectionStatus =
    'none';


$connectionId =
    null;


if (
    $currentUserId > 0
    &&
    !$isOwner
) {

    try {

        $connectionStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    status,
                    initiated_by

                FROM connections

                WHERE

                    user_low_id =
                        LEAST(
                            :u1,
                            :u2
                        )

                    AND

                    user_high_id =
                        GREATEST(
                            :u3,
                            :u4
                        )

                ORDER BY id DESC

                LIMIT 1
                "
            );

        $connectionStmt->execute(
            [

                ':u1' =>
                    $currentUserId,

                ':u2' =>
                    $targetUserId,

                ':u3' =>
                    $currentUserId,

                ':u4' =>
                    $targetUserId

            ]
        );

        $connection =
            $connectionStmt->fetch();

    } catch (Throwable $e) {

        $connection = false;

    }


    if ($connection) {

        $connectionId =
            (int)
            $connection['id'];

        $connectionStatus =
            $connection['status'];

    }

}


/* ============================================================
   CAN MESSAGE
============================================================ */

$canMessage =
    (bool)
    $profile['allow_messages'];


/* ============================================================
   RESPONSE
============================================================ */

profileViewResponse(
    true,
    'Profile loaded successfully.',
    [

        'profile' => [

            'id' =>
                (int)
                $profile['id'],

            'username' =>
                $profile['username'],

            'full_names' =>
                $profile['full_names'],

            'display_name' =>
                $profile['display_name']
                ??
                $profile['full_names'],

            'gender' =>
                $profile['gender'],

            'age' =>
                $age,

            'country' => [

                'id' =>
                    $profile['country_id']
                    !== null
                        ?
                        (int)
                        $profile['country_id']
                        :
                        null,

                'name' =>
                    $profile['country_name'],

                'iso2' =>
                    $profile['iso2'],

                'iso3' =>
                    $profile['iso3'],

                'flag_code' =>
                    $profile['flag_code']

            ],

            'bio' =>
                $profile['bio'],

            'occupation' =>
                $profile['occupation'],

            'education' =>
                $profile['education'],

            'city' =>
                $profile['city'],

            'relationship_status' =>
                $profile['relationship_status'],

            'looking_for' =>
                $profile['looking_for'],

            'interests' =>
                $profile['interests'],

            'online' =>
                $isOnline,

            'last_seen_at' =>
                (
                    (int)
                    $profile['show_online_status']
                    === 1
                        ?
                        $profile['last_seen_at']
                        :
                        null
                ),

            'photos' =>
                $photos

        ],

        'is_owner' =>
            $isOwner,

        'can_message' =>
            $canMessage,

        'connection' => [

            'id' =>
                $connectionId,

            'status' =>
                $connectionStatus

        ]

    ]
);