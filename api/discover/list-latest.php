<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function latestResponse(bool $success, string $message, array $extra = [], int $status = 200): never
{
    http_response_code($status);
    echo json_encode(
        array_merge(['success' => $success, 'message' => $message], $extra),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    latestResponse(false, 'Only GET requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$limit = max(1, min(100, (int)($_GET['limit'] ?? 60)));
$offset = max(0, (int)($_GET['offset'] ?? 0));

try {
    $pdo = db();
} catch (Throwable $e) {
    error_log('[LOVEMI LATEST DB] ' . $e->getMessage());
    latestResponse(false, 'Unable to connect to the LOVEMI database.', [
        'code' => 'DATABASE_ERROR',
        'items' => [],
        'posts' => [],
        'profiles' => []
    ], 500);
}

try {
    /*
     * IMPORTANT:
     * Every approved media item is returned as its own chronological activity.
     * That means:
     *   - every approved image/video attached to a public approved post appears;
     *   - every approved profile photo appears when it was uploaded/approved;
     *   - profile text updates without a photo can also appear;
     *   - the newest profile photo is NOT hidden just because an older photo is_primary=1.
     */
    $sql = <<<'SQL'
SELECT *
FROM (
    /* -------------------------------------------------------------
       APPROVED POST MEDIA: one row per approved photo/video
       ------------------------------------------------------------- */
    SELECT
        'post_media' AS item_type,
        CONCAT('post-media-', pp.id) AS activity_key,
        pp.id AS activity_id,
        p.id AS item_id,
        p.id AS post_id,
        NULL AS profile_id,
        p.user_id,
        p.content,
        p.created_at AS post_created_at,
        p.updated_at AS post_updated_at,
        NULL AS profile_updated_at,
        NULL AS profile_photo_id,
        ph.id AS photo_id,
        ph.file_name,
        ph.mime_type,
        CONCAT('api/discover/media.php?photo_id=', ph.id) AS media_url,
        CASE
            WHEN ph.thumbnail_path IS NOT NULL AND ph.thumbnail_path <> '' THEN ph.thumbnail_path
            ELSE NULL
        END AS thumbnail_url,
        1 AS has_media,
        CASE WHEN LOWER(COALESCE(ph.mime_type, '')) LIKE 'video/%' THEN 1 ELSE 0 END AS is_video,
        GREATEST(
            COALESCE(ph.approved_at, ph.uploaded_at, pp.created_at),
            COALESCE(p.approved_at, p.created_at),
            p.updated_at
        ) AS activity_at,
        u.username,
        u.full_names,
        u.gender,
        c.name AS country_name,
        c.iso2 AS country_iso2,
        pr.display_name,
        pr.city,
        p.approval_status,
        p.visibility
    FROM post_photos pp
    INNER JOIN posts p ON p.id = pp.post_id
    INNER JOIN photos ph ON ph.id = pp.photo_id
    INNER JOIN users u ON u.id = p.user_id
    LEFT JOIN roles r ON r.id = u.role_id
    LEFT JOIN countries c ON c.id = u.country_id
    LEFT JOIN profiles pr ON pr.user_id = u.id
    WHERE ph.photo_type = 'post'
      AND ph.approval_status = 'approved'
      AND p.approval_status = 'approved'
      AND p.visibility = 'public'
      AND p.deleted_at IS NULL
      AND u.account_status = 'approved'
      AND u.email_verified = 1
      AND u.is_active = 1
      AND u.is_suspended = 0
      AND u.is_deleted = 0
      AND (r.is_admin_role = 0 OR r.is_admin_role IS NULL)
      AND (pr.profile_visibility = 'public' OR pr.profile_visibility IS NULL)

    UNION ALL

    /* -------------------------------------------------------------
       TEXT-ONLY APPROVED PUBLIC POSTS
       These remain available in the activity feed when there is no media.
       ------------------------------------------------------------- */
    SELECT
        'post' AS item_type,
        CONCAT('post-', p.id) AS activity_key,
        p.id AS activity_id,
        p.id AS item_id,
        p.id AS post_id,
        NULL AS profile_id,
        p.user_id,
        p.content,
        p.created_at AS post_created_at,
        p.updated_at AS post_updated_at,
        NULL AS profile_updated_at,
        NULL AS profile_photo_id,
        NULL AS photo_id,
        NULL AS file_name,
        NULL AS mime_type,
        NULL AS media_url,
        NULL AS thumbnail_url,
        0 AS has_media,
        0 AS is_video,
        GREATEST(
            COALESCE(p.approved_at, p.created_at),
            p.updated_at,
            p.created_at
        ) AS activity_at,
        u.username,
        u.full_names,
        u.gender,
        c.name AS country_name,
        c.iso2 AS country_iso2,
        pr.display_name,
        pr.city,
        p.approval_status,
        p.visibility
    FROM posts p
    INNER JOIN users u ON u.id = p.user_id
    LEFT JOIN roles r ON r.id = u.role_id
    LEFT JOIN countries c ON c.id = u.country_id
    LEFT JOIN profiles pr ON pr.user_id = u.id
    WHERE p.approval_status = 'approved'
      AND p.visibility = 'public'
      AND p.deleted_at IS NULL
      AND u.account_status = 'approved'
      AND u.email_verified = 1
      AND u.is_active = 1
      AND u.is_suspended = 0
      AND u.is_deleted = 0
      AND (r.is_admin_role = 0 OR r.is_admin_role IS NULL)
      AND (pr.profile_visibility = 'public' OR pr.profile_visibility IS NULL)
      AND NOT EXISTS (
          SELECT 1
          FROM post_photos pp2
          INNER JOIN photos ph2 ON ph2.id = pp2.photo_id
          WHERE pp2.post_id = p.id
            AND ph2.photo_type = 'post'
            AND ph2.approval_status = 'approved'
      )

    UNION ALL

    /* -------------------------------------------------------------
       APPROVED PROFILE PHOTOS: one row per approved profile photo
       The newest uploaded/approved profile photo wins chronologically.
       is_primary is deliberately NOT used to hide newer photos.
       ------------------------------------------------------------- */
    SELECT
        'profile_media' AS item_type,
        CONCAT('profile-media-', ph.id) AS activity_key,
        ph.id AS activity_id,
        u.id AS item_id,
        NULL AS post_id,
        pr.id AS profile_id,
        u.id AS user_id,
        NULL AS content,
        NULL AS post_created_at,
        NULL AS post_updated_at,
        pr.updated_at AS profile_updated_at,
        ph.id AS profile_photo_id,
        ph.id AS photo_id,
        ph.file_name,
        ph.mime_type,
        CONCAT('api/discover/media.php?photo_id=', ph.id) AS media_url,
        CASE
            WHEN ph.thumbnail_path IS NOT NULL AND ph.thumbnail_path <> '' THEN ph.thumbnail_path
            ELSE NULL
        END AS thumbnail_url,
        1 AS has_media,
        CASE WHEN LOWER(COALESCE(ph.mime_type, '')) LIKE 'video/%' THEN 1 ELSE 0 END AS is_video,
        COALESCE(ph.approved_at, ph.uploaded_at) AS activity_at,
        u.username,
        u.full_names,
        u.gender,
        c.name AS country_name,
        c.iso2 AS country_iso2,
        pr.display_name,
        pr.city,
        NULL AS approval_status,
        'public' AS visibility
    FROM photos ph
    INNER JOIN users u ON u.id = ph.user_id
    LEFT JOIN roles r ON r.id = u.role_id
    LEFT JOIN countries c ON c.id = u.country_id
    LEFT JOIN profiles pr ON pr.user_id = u.id
    WHERE ph.photo_type = 'profile'
      AND ph.approval_status = 'approved'
      AND u.account_status = 'approved'
      AND u.email_verified = 1
      AND u.is_active = 1
      AND u.is_suspended = 0
      AND u.is_deleted = 0
      AND (r.is_admin_role = 0 OR r.is_admin_role IS NULL)
      AND (pr.profile_visibility = 'public' OR pr.profile_visibility IS NULL)
      AND NOT EXISTS (
          SELECT 1
          FROM photos newer_profile
          WHERE newer_profile.user_id = ph.user_id
            AND newer_profile.photo_type = 'profile'
            AND newer_profile.approval_status = 'approved'
            AND (
                COALESCE(newer_profile.approved_at, newer_profile.uploaded_at) > COALESCE(ph.approved_at, ph.uploaded_at)
                OR (
                    COALESCE(newer_profile.approved_at, newer_profile.uploaded_at) = COALESCE(ph.approved_at, ph.uploaded_at)
                    AND newer_profile.id > ph.id
                )
            )
      )

    UNION ALL

    /* -------------------------------------------------------------
       PROFILE TEXT UPDATE WITHOUT A PROFILE PHOTO
       This is only used when the profile exists and has a public profile.
       ------------------------------------------------------------- */
    SELECT
        'profile' AS item_type,
        CONCAT('profile-', u.id) AS activity_key,
        u.id AS activity_id,
        u.id AS item_id,
        NULL AS post_id,
        pr.id AS profile_id,
        u.id AS user_id,
        NULL AS content,
        NULL AS post_created_at,
        NULL AS post_updated_at,
        pr.updated_at AS profile_updated_at,
        NULL AS profile_photo_id,
        NULL AS photo_id,
        NULL AS file_name,
        NULL AS mime_type,
        NULL AS media_url,
        NULL AS thumbnail_url,
        0 AS has_media,
        0 AS is_video,
        GREATEST(
            COALESCE(pr.updated_at, u.updated_at, u.created_at),
            COALESCE(u.updated_at, u.created_at)
        ) AS activity_at,
        u.username,
        u.full_names,
        u.gender,
        c.name AS country_name,
        c.iso2 AS country_iso2,
        pr.display_name,
        pr.city,
        NULL AS approval_status,
        'public' AS visibility
    FROM users u
    INNER JOIN profiles pr ON pr.user_id = u.id
    LEFT JOIN roles r ON r.id = u.role_id
    LEFT JOIN countries c ON c.id = u.country_id
    WHERE u.account_status = 'approved'
      AND u.email_verified = 1
      AND u.is_active = 1
      AND u.is_suspended = 0
      AND u.is_deleted = 0
      AND (r.is_admin_role = 0 OR r.is_admin_role IS NULL)
      AND (pr.profile_visibility = 'public' OR pr.profile_visibility IS NULL)
      AND NOT EXISTS (
          SELECT 1
          FROM photos pph
          WHERE pph.user_id = u.id
            AND pph.photo_type = 'profile'
            AND pph.approval_status = 'approved'
      )
) feed
ORDER BY feed.activity_at DESC, feed.activity_id DESC
LIMIT :limit OFFSET :offset
SQL;

    $stmt = $pdo->prepare($sql);
    $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
    $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $items = [];
    $posts = [];
    $profiles = [];

    foreach ($rows as $row) {
        $itemType = (string)$row['item_type'];
        $item = [
            'item_type' => $itemType,
            'activity_key' => (string)$row['activity_key'],
            'activity_id' => (int)$row['activity_id'],
            'item_id' => (int)$row['item_id'],
            'id' => $row['post_id'] !== null ? (int)$row['post_id'] : (int)$row['item_id'],
            'post_id' => $row['post_id'] !== null ? (int)$row['post_id'] : null,
            'profile_id' => $row['profile_id'] !== null ? (int)$row['profile_id'] : null,
            'user_id' => (int)$row['user_id'],
            'username' => (string)$row['username'],
            'full_names' => (string)$row['full_names'],
            'full_name' => (string)$row['full_names'],
            'display_name' => $row['display_name'] !== null ? (string)$row['display_name'] : null,
            'gender' => (string)$row['gender'],
            'country_name' => $row['country_name'] !== null ? (string)$row['country_name'] : null,
            'country_iso2' => $row['country_iso2'] !== null ? (string)$row['country_iso2'] : null,
            'city' => $row['city'] !== null ? (string)$row['city'] : null,
            'content' => $row['content'] !== null ? (string)$row['content'] : '',
            'profile_updated_at' => $row['profile_updated_at'] !== null ? (string)$row['profile_updated_at'] : null,
            'profile_photo_id' => $row['profile_photo_id'] !== null ? (int)$row['profile_photo_id'] : null,
            'profile_media_url' => $row['profile_photo_id'] !== null
                ? 'api/discover/media.php?photo_id=' . (int)$row['profile_photo_id']
                : null,
            'activity_at' => (string)$row['activity_at'],
            'created_at' => $row['post_created_at'] !== null
                ? (string)$row['post_created_at']
                : (string)$row['activity_at'],
            'updated_at' => $row['post_updated_at'] !== null ? (string)$row['post_updated_at'] : null,
            'photo_id' => $row['photo_id'] !== null ? (int)$row['photo_id'] : null,
            'file_name' => $row['file_name'] !== null ? (string)$row['file_name'] : null,
            'mime_type' => $row['mime_type'] !== null ? (string)$row['mime_type'] : null,
            'media_url' => $row['media_url'] !== null ? (string)$row['media_url'] : null,
            'thumbnail_url' => $row['thumbnail_url'] !== null ? (string)$row['thumbnail_url'] : null,
            'has_media' => (bool)$row['has_media'],
            'is_video' => (bool)$row['is_video'],
        ];

        $items[] = $item;
        if (in_array($itemType, ['post', 'post_media'], true)) {
            $posts[] = $item;
        } else {
            $profiles[] = $item;
        }
    }

    latestResponse(true, 'Latest LOVEMI activity loaded successfully.', [
        'count' => count($items),
        'items' => $items,
        'posts' => $posts,
        'profiles' => $profiles,
        'has_more' => count($items) === $limit,
        'limit' => $limit,
        'offset' => $offset,
    ]);
} catch (Throwable $e) {
    error_log('[LOVEMI LATEST QUERY] ' . $e->getMessage());
    latestResponse(false, 'Unable to load latest LOVEMI activity from the database.', [
        'code' => 'LATEST_QUERY_FAILED',
        'items' => [],
        'posts' => [],
        'profiles' => []
    ], 500);
}
