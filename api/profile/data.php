<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

$currentUserId =
    profileRequireAuth();

try {

    $pdo =
        profileDb();

    $request =
        resolveProfileRequest(
            $pdo,
            $currentUserId
        );

    $targetUserId =
        (int)$request['user_id'];

    $isOwner =
        (bool)$request['is_owner'];

    $stmt =
        $pdo->prepare(
            "
            SELECT
                u.id,
                u.username,
                u.full_names,
                u.gender,
                u.email,
                u.country_id,
                u.phone_number,
                u.phone_e164,
                u.date_of_birth,
                u.account_status,
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
                up.last_seen_at AS presence_last_seen_at,

                w.whatsapp_number

            FROM users u

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            LEFT JOIN user_presence up
                ON up.user_id = u.id

            LEFT JOIN user_whatsapp_numbers w
                ON w.user_id = u.id
               AND w.is_active = 1

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

    if (!$isOwner) {

        if (
            strtolower(
                trim(
                    (string)$user['account_status']
                )
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

        if (
            strtolower(
                trim(
                    (string)(
                        $user['profile_visibility']
                        ?? 'public'
                    )
                )
            ) !== 'public'
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
    }

    $isOnline =
        (bool)(
            $user['is_online']
            ?? false
        );

    if (
        (bool)(
            $user['show_online_status']
            ?? true
        )
        && !$isOnline
        && !empty(
            $user['presence_last_seen_at']
        )
    ) {

        try {

            $lastSeen =
                new DateTime(
                    (string)$user['presence_last_seen_at']
                );

            $seconds =
                time()
                - $lastSeen->getTimestamp();

            $isOnline =
                $seconds >= 0
                && $seconds <= 600;

        } catch (Throwable) {

            $isOnline =
                false;
        }
    }

    $viewerPremium =
        profileHasPremium(
            $pdo,
            $currentUserId
        );

    $profilePremium =
        profileHasPremium(
            $pdo,
            $targetUserId
        );

    $connection =
        $isOwner
            ? null
            : profileGetConnection(
                $pdo,
                $currentUserId,
                $targetUserId
            );

    $connectionStatus =
        $connection['status']
        ?? null;

    $isConnected =
        profileIsConnected(
            $connection
        );

    $initiatedByMe =
        $connection
        && (int)(
            $connection['initiated_by']
            ?? 0
        ) === $currentUserId;

    /*
     * IMPORTANT:
     * Either party having Premium is enough for chat,
     * but the connection MUST be active.
     */
    $canChat =
        !$isOwner
        && $isConnected
        && (
            $viewerPremium
            || $profilePremium
        )
        && (
            (bool)(
                $user['allow_messages']
                ?? true
            )
        );

    /*
     * WhatsApp is deliberately stricter:
     * active connection + viewer Premium.
     */
    $canViewContact =
        $isOwner
        || (
            $isConnected
            && $viewerPremium
        );

    $private = [
        'email' =>
            $isOwner
                ? (string)$user['email']
                : null,

        'phone_number' =>
            $canViewContact
                ? (string)(
                    $user['phone_number']
                    ?? ''
                )
                : null,

        'phone_e164' =>
            $canViewContact
                ? (string)(
                    $user['phone_e164']
                    ?? ''
                )
                : null,

        'whatsapp_number' =>
            $canViewContact
                ? (string)(
                    $user['whatsapp_number']
                    ?? ''
                )
                : null,

        'date_of_birth' =>
            $isOwner
                ? $user['date_of_birth']
                : null
    ];

    $photoStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                file_name,
                file_path,
                thumbnail_path,
                mime_type,
                photo_type,
                approval_status,
                is_primary,
                is_featured,
                uploaded_at
            FROM photos
            WHERE user_id = :user_id
              AND approval_status = 'approved'
              AND photo_type = 'profile'
            ORDER BY
                is_primary DESC,
                is_featured DESC,
                id DESC
            LIMIT 1
            "
        );

    $photoStmt->execute([
        ':user_id' =>
            $targetUserId
    ]);

    $primaryPhoto =
        $photoStmt->fetch(PDO::FETCH_ASSOC)
        ?: null;

    $galleryStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                file_name,
                file_path,
                thumbnail_path,
                mime_type,
                photo_type,
                approval_status,
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
            LIMIT 200
            "
        );

    $galleryStmt->execute([
        ':user_id' =>
            $targetUserId
    ]);

    $gallery =
        $galleryStmt->fetchAll(PDO::FETCH_ASSOC);

    /*
     * Only accepted/connected members are displayed
     * in the profile connection list.
     */
    $connectionsStmt =
        $pdo->prepare(
            "
            SELECT
                c.id AS connection_id,

                CASE
                    WHEN c.user_id = :profile_a
                        THEN c.connected_user_id
                    ELSE c.user_id
                END AS other_user_id,

                c.status,
                c.connected_at,

                u.username,
                u.full_names,
                u.gender,

                pr.display_name,

                co.name AS country_name,

                ph.file_path,
                ph.thumbnail_path,

                up.is_online,
                up.last_seen_at

            FROM connections c

            INNER JOIN users u
                ON u.id =
                    CASE
                        WHEN c.user_id = :profile_b
                            THEN c.connected_user_id
                        ELSE c.user_id
                    END

            LEFT JOIN profiles pr
                ON pr.user_id = u.id

            LEFT JOIN countries co
                ON co.id = u.country_id

            LEFT JOIN photos ph
                ON ph.user_id = u.id
               AND ph.approval_status = 'approved'
               AND ph.photo_type = 'profile'
               AND ph.is_primary = 1

            LEFT JOIN user_presence up
                ON up.user_id = u.id

            WHERE
                (
                    c.user_id = :profile_c
                    OR c.connected_user_id = :profile_d
                )

                AND c.status IN (
                    'accepted',
                    'connected'
                )

                AND u.is_active = 1
                AND u.is_suspended = 0
                AND u.is_deleted = 0

            ORDER BY
                c.connected_at DESC,
                c.id DESC

            LIMIT 100
            "
        );

    $connectionsStmt->execute(
        [
            ':profile_a' =>
                $targetUserId,

            ':profile_b' =>
                $targetUserId,

            ':profile_c' =>
                $targetUserId,

            ':profile_d' =>
                $targetUserId
        ]
    );

    $connectionRows =
        $connectionsStmt->fetchAll(PDO::FETCH_ASSOC);

    $connections = [];

    foreach (
        $connectionRows
        as $row
    ) {

        $otherId =
            (int)$row['other_user_id'];

        $connections[] = [
            'connection_id' =>
                (int)$row['connection_id'],

            /*
             * Internal ID is only returned to the authenticated
             * browser API. The browser URL uses profile_code.
             */
            'user_id' =>
                $otherId,

            'username' =>
                (string)(
                    $row['username']
                    ?? ''
                ),

            'full_name' =>
                (string)(
                    $row['display_name']
                    ?: (
                        $row['full_names']
                        ?: (
                            $row['username']
                            ?: 'Member'
                        )
                    )
                ),

            'gender' =>
                (string)(
                    $row['gender']
                    ?? ''
                ),

            'country_name' =>
                $row['country_name'] !== null
                    ? (string)$row['country_name']
                    : null,

            'profile_photo' =>
                $row['thumbnail_path']
                ?: (
                    $row['file_path']
                    ?: null
                ),

            'photo_url' =>
                $row['thumbnail_path']
                ?: (
                    $row['file_path']
                    ?: null
                ),

            'is_online' =>
                (bool)(
                    $row['is_online']
                    ?? false
                ),

            'status' =>
                (string)$row['status'],

            'connected_at' =>
                $row['connected_at'] !== null
                    ? (string)$row['connected_at']
                    : null,

            'profile_code' =>
                ensureProfileCode(
                    $pdo,
                    $otherId
                )
        ];
    }

    $postCountStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)
            FROM posts
            WHERE user_id = :user_id
              AND deleted_at IS NULL
              AND (
                    :is_owner = 1
                    OR (
                        approval_status = 'approved'
                        AND visibility = 'public'
                    )
              )
            "
        );

    $postCountStmt->execute(
        [
            ':user_id' =>
                $targetUserId,

            ':is_owner' =>
                $isOwner
                    ? 1
                    : 0
        ]
    );

    $postCount =
        (int)$postCountStmt->fetchColumn();

    $connectionCountStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)
            FROM connections
            WHERE (
                    user_id = :user_a
                    OR connected_user_id = :user_b
                  )
              AND status IN (
                    'accepted',
                    'connected'
              )
            "
        );

    $connectionCountStmt->execute(
        [
            ':user_a' =>
                $targetUserId,

            ':user_b' =>
                $targetUserId
        ]
    );

    $connectionCount =
        (int)$connectionCountStmt->fetchColumn();

    $followersStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)
            FROM user_follows
            WHERE following_id = :user_id
            "
        );

    $followersStmt->execute([
        ':user_id' =>
            $targetUserId
    ]);

    $followersCount =
        (int)$followersStmt->fetchColumn();

    $followingStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)
            FROM user_follows
            WHERE follower_id = :user_id
            "
        );

    $followingStmt->execute([
        ':user_id' =>
            $targetUserId
    ]);

    $followingCount =
        (int)$followingStmt->fetchColumn();

    $isFollowing =
        false;

    if (!$isOwner) {

        $followStmt =
            $pdo->prepare(
                "
                SELECT id
                FROM user_follows
                WHERE follower_id = :follower
                  AND following_id = :following
                LIMIT 1
                "
            );

        $followStmt->execute(
            [
                ':follower' =>
                    $currentUserId,

                ':following' =>
                    $targetUserId
            ]
        );

        $isFollowing =
            (bool)$followStmt->fetchColumn();
    }

    $profileCode =
        ensureProfileCode(
            $pdo,
            $targetUserId
        );

    $profile = [
        'id' =>
            $targetUserId,

        'user_id' =>
            $targetUserId,

        'username' =>
            (string)$user['username'],

        'full_names' =>
            (string)$user['full_names'],

        'full_name' =>
            (string)$user['full_names'],

        'display_name' =>
            $user['display_name']
                ? (string)$user['display_name']
                : (string)$user['full_names'],

        'gender' =>
            (string)$user['gender'],

        'country_id' =>
            $user['country_id'] !== null
                ? (int)$user['country_id']
                : null,

        'country_name' =>
            $user['country_name']
                ? (string)$user['country_name']
                : '',

        'country_iso2' =>
            $user['country_iso2']
                ? strtoupper(
                    (string)$user['country_iso2']
                )
                : '',

        'country_iso3' =>
            $user['country_iso3']
                ? strtoupper(
                    (string)$user['country_iso3']
                )
                : '',

        'country_phone_code' =>
            $user['country_phone_code']
                ? (string)$user['country_phone_code']
                : '',

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
            strtolower(
                trim(
                    (string)(
                        $user['profile_visibility']
                        ?? 'public'
                    )
                )
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

        'email_verified' =>
            (bool)$user['email_verified'],

        'phone_verified' =>
            (bool)$user['phone_verified'],

        'identity_verified' =>
            (bool)$user['identity_verified'],

        'age_verified' =>
            (bool)$user['age_verified'],

        'is_online' =>
            $isOnline,

        'created_at' =>
            (string)$user['created_at'],

        'profile_photo' =>
            $primaryPhoto
                ? (
                    $primaryPhoto['thumbnail_path']
                    ?: $primaryPhoto['file_path']
                )
                : null
    ];

    profileJsonResponse(
        true,
        'Profile loaded successfully.',
        [
            'profile' =>
                $profile,

            'private' =>
                $private,

            'gallery' =>
                $gallery,

            'connections' =>
                $connections,

            'profile_code' =>
                $profileCode,

            'connection_status' =>
                $connectionStatus,

            'connection_initiated_by_me' =>
                $initiatedByMe,

            'is_connected' =>
                $isConnected,

            'is_following' =>
                $isFollowing,

            'followers_count' =>
                $followersCount,

            'following_count' =>
                $followingCount,

            'connections_count' =>
                $connectionCount,

            'post_count' =>
                $postCount,

            'posts_count' =>
                $postCount,

            'photos_count' =>
                count($gallery),

            'viewer_has_premium' =>
                $viewerPremium,

            'profile_has_premium' =>
                $profilePremium,

            'can_chat' =>
                $canChat,

            'can_view_contact' =>
                $canViewContact,

            'is_own_profile' =>
                $isOwner
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE DATA] ' .
        $e->getMessage()
    );

    profileJsonResponse(
        false,
        'Unable to load this profile.',
        [
            'code' =>
                'PROFILE_QUERY_ERROR'
        ],
        500
    );
}