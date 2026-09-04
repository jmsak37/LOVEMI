<?php

declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI
 * PROFILE POSTS API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\profile\posts.php
 *
 * Purpose:
 * - Load posts belonging to the requested profile.
 * - Allow the profile owner to see their own posts.
 * - Allow other users to see only approved public posts.
 * - Return persisted like/reaction state for the current viewer.
 * - Return persisted like/comment totals.
 * - Return post media.
 * - Return secure video stream URLs for videos.
 * - Never expose an internal user ID as the public profile identifier.
 * - Disable browser/proxy caching.
 *
 * ============================================================
 */

require_once __DIR__ . '/_helper.php';


/* ============================================================
   RESPONSE HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   AUTHENTICATION
============================================================ */

$currentUserId = profileRequireAuth();


/* ============================================================
   MAIN
============================================================ */

try {

    $pdo = profileDb();


    /* ========================================================
       RESOLVE PROFILE

       The helper resolves:

       - profile.html
       - profile.html?code=XXXX

       into the real database user ID internally.

       The internal ID is never taken from the browser URL.
    ======================================================== */

    $request = resolveProfileRequest(
        $pdo,
        $currentUserId
    );


    $targetUserId = (int)($request['user_id'] ?? 0);

    $isOwner = (bool)($request['is_owner'] ?? false);

    $profileCode = (string)($request['code'] ?? '');


    if ($targetUserId <= 0) {

        profileJsonResponse(
            false,
            'The requested profile could not be resolved.',
            [
                'code' => 'PROFILE_RESOLVE_FAILED'
            ],
            404
        );
    }


    /* ========================================================
       PAGINATION
    ======================================================== */

    $page = max(
        1,
        (int)($_GET['page'] ?? 1)
    );


    $limit = min(
        20,
        max(
            1,
            (int)($_GET['limit'] ?? 10)
        )
    );


    $offset = ($page - 1) * $limit;


    /* ========================================================
       VERIFY PROFILE
    ======================================================== */

    $profileStmt = $pdo->prepare(
        '
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
        '
    );


    $profileStmt->execute(
        [
            ':user_id' => $targetUserId
        ]
    );


    $profile = $profileStmt->fetch(
        PDO::FETCH_ASSOC
    );


    if (!$profile) {

        profileJsonResponse(
            false,
            'Profile not found.',
            [
                'code' => 'PROFILE_NOT_FOUND'
            ],
            404
        );
    }


    /* ========================================================
       ACCOUNT AVAILABILITY
    ======================================================== */

    if (
        (int)$profile['is_active'] !== 1
        ||
        (int)$profile['is_suspended'] === 1
        ||
        (int)$profile['is_deleted'] === 1
    ) {

        profileJsonResponse(
            false,
            'This profile is currently unavailable.',
            [
                'code' => 'PROFILE_UNAVAILABLE'
            ],
            403
        );
    }


    /* ========================================================
       PUBLIC PROFILE RULES

       Owner:
       - can see all of their posts according to their account.

       Other viewer:
       - must be approved
       - email verified
       - profile public
       - post approved
       - post public
    ======================================================== */

    if (!$isOwner) {

        if (
            (int)$profile['email_verified'] !== 1
            ||
            strtolower(
                (string)$profile['account_status']
            ) !== 'approved'
            ||
            strtolower(
                trim(
                    (string)(
                        $profile['profile_visibility']
                        ??
                        'public'
                    )
                )
            ) !== 'public'
        ) {

            profileJsonResponse(
                false,
                'Posts are not available.',
                [
                    'code' => 'POSTS_UNAVAILABLE'
                ],
                403
            );
        }
    }


    $ownerFilter = $isOwner ? 1 : 0;


    /* ========================================================
       TOTAL POSTS
    ======================================================== */

    $totalStmt = $pdo->prepare(
        '
        SELECT COUNT(*)
        FROM posts
        WHERE user_id = :user_id
          AND deleted_at IS NULL
          AND (
              :owner_count = 1
              OR (
                  approval_status = \'approved\'
                  AND visibility = \'public\'
              )
          )
        '
    );


    $totalStmt->execute(
        [
            ':user_id' => $targetUserId,
            ':owner_count' => $ownerFilter
        ]
    );


    $total = (int)$totalStmt->fetchColumn();


    /* ========================================================
       LOAD POSTS

       IMPORTANT:
       my_reaction is read directly from post_reactions.

       Therefore:
       - Like is stored in DB.
       - Reloading the page does not lose the like.
       - The profile page knows whether the current viewer
         already liked a post.
    ======================================================== */

    $sql = "
        SELECT
            p.id AS post_id,
            p.user_id,
            p.content,
            p.visibility,
            p.approval_status,
            p.is_featured,
            p.created_at,
            p.updated_at,
            p.approved_at,

            u.username,
            u.full_names,
            u.gender,
            u.email_verified,

            pr.display_name,
            pr.city,

            c.name AS country_name,

            (
                SELECT ph.file_path
                FROM photos ph
                WHERE ph.user_id = p.user_id
                  AND ph.photo_type = 'profile'
                  AND ph.approval_status = 'approved'
                  AND ph.is_primary = 1
                ORDER BY ph.id DESC
                LIMIT 1
            ) AS profile_photo,

            (
                SELECT ph.thumbnail_path
                FROM photos ph
                WHERE ph.user_id = p.user_id
                  AND ph.photo_type = 'profile'
                  AND ph.approval_status = 'approved'
                  AND ph.is_primary = 1
                ORDER BY ph.id DESC
                LIMIT 1
            ) AS profile_thumbnail,

            (
                SELECT COUNT(*)
                FROM post_reactions prl
                WHERE prl.post_id = p.id
                  AND prl.reaction = 'like'
            ) AS like_count,

            (
                SELECT COUNT(*)
                FROM post_comments pc
                WHERE pc.post_id = p.id
            ) AS comment_count,

            (
                SELECT prx.reaction
                FROM post_reactions prx
                WHERE prx.post_id = p.id
                  AND prx.user_id = :viewer_id
                ORDER BY prx.id DESC
                LIMIT 1
            ) AS my_reaction

        FROM posts p

        INNER JOIN users u
            ON u.id = p.user_id

        LEFT JOIN profiles pr
            ON pr.user_id = p.user_id

        LEFT JOIN countries c
            ON c.id = u.country_id

        WHERE p.user_id = :target_user_id
          AND p.deleted_at IS NULL

          AND (
              :owner_rows = 1

              OR (
                  p.approval_status = 'approved'
                  AND p.visibility = 'public'
              )
          )

        ORDER BY
            p.created_at DESC,
            p.id DESC

        LIMIT {$limit}
        OFFSET {$offset}
    ";


    $stmt = $pdo->prepare(
        $sql
    );


    $stmt->execute(
        [
            ':viewer_id' => $currentUserId,
            ':target_user_id' => $targetUserId,
            ':owner_rows' => $ownerFilter
        ]
    );


    $rows = $stmt->fetchAll(
        PDO::FETCH_ASSOC
    );


    /* ========================================================
       NO POSTS
    ======================================================== */

    if (!$rows) {

        profileJsonResponse(
            true,
            'No posts found.',
            [
                'posts' => [],
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'has_more' => false
            ]
        );
    }


    /* ========================================================
       POST IDS
    ======================================================== */

    $postIds = array_map(
        static function (array $row): int {

            return (int)$row['post_id'];

        },
        $rows
    );


    if (!$postIds) {

        profileJsonResponse(
            true,
            'No posts found.',
            [
                'posts' => [],
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'has_more' => false
            ]
        );
    }


    /* ========================================================
       SAFE IN-QUERY PLACEHOLDERS
    ======================================================== */

    $placeholders = implode(
        ',',
        array_fill(
            0,
            count($postIds),
            '?'
        )
    );


    /* ========================================================
       LOAD MEDIA

       Photos table is used for both:
       - images
       - videos

       Videos are returned with:
       - no public file path for external viewers
       - protected stream_url

       The actual file is streamed by:
       api/profile/video-stream.php
    ======================================================== */

    $mediaStmt = $pdo->prepare(
        "
        SELECT
            pp.post_id,
            pp.photo_id,
            pp.display_order,

            ph.file_name,
            ph.file_path,
            ph.thumbnail_path,
            ph.mime_type,
            ph.photo_type,
            ph.approval_status

        FROM post_photos pp

        INNER JOIN photos ph
            ON ph.id = pp.photo_id

        INNER JOIN posts p2
            ON p2.id = pp.post_id

        WHERE pp.post_id IN ({$placeholders})

          AND (
              ph.approval_status = 'approved'
              OR p2.user_id = ?
          )

        ORDER BY
            pp.post_id ASC,
            pp.display_order ASC,
            pp.id ASC
        "
    );


    $mediaParams = $postIds;

    /*
     * Owner may see their own media even if an older database
     * has not yet marked the media approved.
     */
    $mediaParams[] = $targetUserId;


    $mediaStmt->execute(
        $mediaParams
    );


    $mediaRows = $mediaStmt->fetchAll(
        PDO::FETCH_ASSOC
    );


    /* ========================================================
       MEDIA MAP
    ======================================================== */

    $mediaMap = [];


    foreach ($mediaRows as $media) {

        $postId = (int)$media['post_id'];


        if (!isset($mediaMap[$postId])) {

            $mediaMap[$postId] = [];
        }


        $mimeType = strtolower(
            trim(
                (string)($media['mime_type'] ?? '')
            )
        );


        $isVideo = str_starts_with(
            $mimeType,
            'video/'
        );


        $filePath = (string)(
            $media['file_path']
            ??
            ''
        );


        $thumbnailPath = (string)(
            $media['thumbnail_path']
            ??
            ''
        );


        /*
         * External viewers must not receive a direct video path.
         *
         * The browser receives a protected URL instead.
         */

        $publicUrl = '';


        if (!$isVideo || $isOwner) {

            $publicUrl = $filePath;
        }


        /*
         * Protected stream URL for all videos.
         *
         * For the profile owner and external viewer this still
         * goes through video-stream.php.
         *
         * This prevents exposing the physical upload path.
         */

        $streamUrl = '';


        if ($isVideo) {

            /*
             * The profile code is already resolved and validated
             * by resolveProfileRequest().
             *
             * We pass the same opaque code to the stream endpoint.
             */

            if ($profileCode !== '') {

                $streamUrl =
                    'api/profile/video-stream.php'
                    .
                    '?code='
                    .
                    rawurlencode(
                        $profileCode
                    )
                    .
                    '&media='
                    .
                    (int)$media['photo_id'];
            }
        }


        $mediaMap[$postId][] = [

            'photo_id' =>
                (int)$media['photo_id'],

            'file_name' =>
                (string)(
                    $media['file_name']
                    ??
                    ''
                ),

            'url' =>
                $publicUrl,

            'file_path' =>
                $isOwner
                    ? $filePath
                    : '',

            'stream_url' =>
                $streamUrl,

            'thumbnail' =>
                $thumbnailPath !== ''
                    ? $thumbnailPath
                    : $filePath,

            'thumbnail_path' =>
                $thumbnailPath,

            'mime_type' =>
                $mimeType,

            'photo_type' =>
                (string)(
                    $media['photo_type']
                    ??
                    ''
                ),

            'approval_status' =>
                (string)(
                    $media['approval_status']
                    ??
                    ''
                ),

            'display_order' =>
                (int)(
                    $media['display_order']
                    ??
                    0
                ),
        ];
    }


    /* ========================================================
       BUILD RESPONSE
    ======================================================== */

    $posts = [];


    foreach ($rows as $row) {

        $postId = (int)$row['post_id'];


        $myReaction =
            $row['my_reaction'] !== null
                ? (string)$row['my_reaction']
                : null;


        $displayName =
            $row['display_name']
            ? (string)$row['display_name']
            :
            (
                $row['full_names']
                ?
                (string)$row['full_names']
                :
                (
                    $row['username']
                    ?
                    (string)$row['username']
                    :
                    'Member'
                )
            );


        $posts[] = [

            /*
             * IDs below are post IDs, not user IDs.
             * The profile HTML uses the post ID for post actions.
             */
            'id' =>
                $postId,

            'post_id' =>
                $postId,


            /*
             * Internal user ID is required by the API consumer
             * for server/database operations, but it is not used
             * as the public profile address.
             */
            'user_id' =>
                (int)$row['user_id'],


            'username' =>
                (string)(
                    $row['username']
                    ??
                    ''
                ),


            'full_name' =>
                $displayName,


            'full_names' =>
                (string)(
                    $row['full_names']
                    ??
                    ''
                ),


            'display_name' =>
                $displayName,


            'gender' =>
                (string)(
                    $row['gender']
                    ??
                    ''
                ),


            'country_name' =>
                (string)(
                    $row['country_name']
                    ??
                    ''
                ),


            'city' =>
                (string)(
                    $row['city']
                    ??
                    ''
                ),


            'profile_photo' =>
                $row['profile_photo']
                    ? (string)$row['profile_photo']
                    : null,


            'profile_thumbnail' =>
                $row['profile_thumbnail']
                    ? (string)$row['profile_thumbnail']
                    : null,


            'content' =>
                (string)(
                    $row['content']
                    ??
                    ''
                ),


            'visibility' =>
                (string)(
                    $row['visibility']
                    ??
                    'public'
                ),


            'approval_status' =>
                (string)(
                    $row['approval_status']
                    ??
                    ''
                ),


            'is_featured' =>
                (bool)(
                    $row['is_featured']
                    ??
                    false
                ),


            'created_at' =>
                (string)(
                    $row['created_at']
                    ??
                    ''
                ),


            'updated_at' =>
                (string)(
                    $row['updated_at']
                    ??
                    ''
                ),


            'approved_at' =>
                $row['approved_at']
                    ? (string)$row['approved_at']
                    : null,


            /*
             * Persisted reaction data.
             *
             * This is what prevents the Like button from appearing
             * unliked after reload.
             */
            'like_count' =>
                (int)(
                    $row['like_count']
                    ??
                    0
                ),

            'likes' =>
                (int)(
                    $row['like_count']
                    ??
                    0
                ),


            /*
             * Persisted comment count.
             */
            'comment_count' =>
                (int)(
                    $row['comment_count']
                    ??
                    0
                ),

            'commentCount' =>
                (int)(
                    $row['comment_count']
                    ??
                    0
                ),


            /*
             * Current viewer's reaction.
             */
            'my_reaction' =>
                $myReaction,

            'reaction' =>
                $myReaction,

            'liked_by_me' =>
                $myReaction === 'like',


            /*
             * Verification.
             */
            'verified' =>
                (bool)(
                    $row['email_verified']
                    ??
                    false
                ),

            'email_verified' =>
                (bool)(
                    $row['email_verified']
                    ??
                    false
                ),


            /*
             * All associated media.
             */
            'media' =>
                $mediaMap[$postId]
                ??
                [],
        ];
    }


    /* ========================================================
       HAS MORE
    ======================================================== */

    $hasMore =
        (
            $offset
            +
            count($posts)
        )
        <
        $total;


    /* ========================================================
       SUCCESS
    ======================================================== */

    profileJsonResponse(
        true,
        'Posts loaded successfully.',
        [
            'posts' =>
                $posts,

            'page' =>
                $page,

            'limit' =>
                $limit,

            'total' =>
                $total,

            'has_more' =>
                $hasMore,
        ]
    );


} catch (Throwable $e) {

    /*
     * Never print PHP errors into the JSON response.
     * Logging is used instead so the browser does not receive:
     *
     * Unexpected token <
     *
     */

    error_log(
        '[LOVEMI PROFILE POSTS] '
        .
        $e->getMessage()
        .
        ' | FILE='
        .
        $e->getFile()
        .
        ' | LINE='
        .
        $e->getLine()
    );


    profileJsonResponse(
        false,
        'Unable to load posts.',
        [
            'code' => 'POST_QUERY_ERROR'
        ],
        500
    );
}