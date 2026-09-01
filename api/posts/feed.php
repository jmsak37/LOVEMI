<?php
/**
 * ============================================================
 * LOVEMI - DASHBOARD POSTS FEED API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\posts\feed.php
 *
 * Database source:
 * posts
 * post_photos
 * photos
 * users
 * profiles
 * countries
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function feedResponse(
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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    feedResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';

session_set_cookie_params(
    [
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]
);

if (
    session_status() !== PHP_SESSION_ACTIVE
) {
    session_start();
}


/* ============================================================
   USER SESSION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

$sessionToken =
    isset($_SESSION['lovemi_session_token'])
        ? trim((string)$_SESSION['lovemi_session_token'])
        : '';

if (
    $userId <= 0
    ||
    $sessionToken === ''
) {

    feedResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED'
        ],
        401
    );
}


try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FEED DB] ' .
        $e->getMessage()
    );

    feedResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   VALIDATE SESSION
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );

try {

    $sessionStmt =
        $pdo->prepare(
            "
            SELECT
                us.id,
                us.user_id,
                us.expires_at,
                us.revoked_at,
                us.two_factor_passed,

                u.username,
                u.full_names,
                u.gender,
                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted

            FROM user_sessions us

            INNER JOIN users u
                ON u.id = us.user_id

            WHERE
                us.session_token_hash = :token

            LIMIT 1
            "
        );

    $sessionStmt->execute(
        [
            ':token' =>
                $tokenHash
        ]
    );

    $session =
        $sessionStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FEED SESSION] ' .
        $e->getMessage()
    );

    feedResponse(
        false,
        'Unable to validate your session.',
        [],
        500
    );
}


if (!$session) {

    feedResponse(
        false,
        'Your login session is invalid.',
        [],
        401
    );
}


if (
    (int)$session['user_id']
    !==
    $userId
) {

    feedResponse(
        false,
        'Invalid login session.',
        [],
        401
    );
}


if (
    $session['revoked_at'] !== null
) {

    feedResponse(
        false,
        'Your login session has been revoked.',
        [],
        401
    );
}


$expiry =
    strtotime(
        (string)$session['expires_at']
    );

if (
    $expiry === false
    ||
    $expiry <= time()
) {

    feedResponse(
        false,
        'Your login session has expired.',
        [],
        401
    );
}


if (
    !(bool)$session['two_factor_passed']
) {

    feedResponse(
        false,
        'Two-step verification is required.',
        [
            'code' => 'TWO_FACTOR_REQUIRED'
        ],
        401
    );
}


if (
    !(bool)$session['email_verified']
    ||
    !(bool)$session['is_active']
    ||
    (bool)$session['is_suspended']
    ||
    (bool)$session['is_deleted']
) {

    feedResponse(
        false,
        'Your account is unavailable.',
        [],
        403
    );
}


/* ============================================================
   ENSURE REACTION TABLE
   ============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS post_reactions
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            post_id BIGINT UNSIGNED NOT NULL,
            user_id BIGINT UNSIGNED NOT NULL,
            reaction VARCHAR(20) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            UNIQUE KEY uq_post_reaction_user
                (post_id, user_id),

            KEY idx_post_reactions_post
                (post_id),

            KEY idx_post_reactions_user
                (user_id),

            CONSTRAINT fk_post_reaction_post
                FOREIGN KEY (post_id)
                REFERENCES posts(id)
                ON DELETE CASCADE,

            CONSTRAINT fk_post_reaction_user
                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FEED REACTION TABLE] ' .
        $e->getMessage()
    );

}


/* ============================================================
   LIMIT
============================================================ */

$limit =
    max(
        1,
        min(
            50,
            (int)(
                $_GET['limit']
                ??
                30
            )
        )
    );


$offset =
    max(
        0,
        (int)(
            $_GET['offset']
            ??
            0
        )
    );


/* ============================================================
   VIEWER PREMIUM
============================================================ */

$viewerPremium =
    false;

try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT s.id

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id = s.service_id

            WHERE
                s.user_id = :user_id

              AND sv.slug = 'lovemi-premium'

              AND s.status = 'active'

              AND s.start_at <= CURRENT_TIMESTAMP

              AND s.end_at > CURRENT_TIMESTAMP

            LIMIT 1
            "
        );

    $premiumStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );

    $viewerPremium =
        (bool)
        $premiumStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FEED PREMIUM] ' .
        $e->getMessage()
    );

}


/* ============================================================
   VIEWER PROFILE PHOTO
============================================================ */

$viewerStmt =
    $pdo->prepare(
        "
        SELECT

            u.id,
            u.username,
            u.full_names,
            u.gender,

            c.name AS country_name,
            c.iso2 AS country_iso2,

            (
                SELECT ph.file_path

                FROM photos ph

                WHERE
                    ph.user_id = u.id

                  AND ph.photo_type = 'profile'

                  AND ph.approval_status = 'approved'

                  AND ph.is_primary = 1

                ORDER BY
                    ph.id DESC

                LIMIT 1
            ) AS profile_photo

        FROM users u

        LEFT JOIN countries c
            ON c.id = u.country_id

        WHERE
            u.id = :user_id

        LIMIT 1
        "
    );

$viewerStmt->execute(
    [
        ':user_id' =>
            $userId
    ]
);

$viewer =
    $viewerStmt->fetch();


if (!$viewer) {

    feedResponse(
        false,
        'Your account could not be found.',
        [],
        404
    );
}


/* ============================================================
   POSTS
============================================================ */

$sql = "
    SELECT

        p.id AS post_id,
        p.user_id,

        p.content,
        p.visibility,
        p.approval_status,

        p.created_at,
        p.updated_at,

        u.username,
        u.full_names,
        u.gender,
        u.email_verified,

        c.name AS country_name,
        c.iso2 AS country_iso2,

        (
            SELECT ph_profile.file_path

            FROM photos ph_profile

            WHERE
                ph_profile.user_id = u.id

              AND ph_profile.photo_type = 'profile'

              AND ph_profile.approval_status = 'approved'

              AND ph_profile.is_primary = 1

            ORDER BY
                ph_profile.id DESC

            LIMIT 1
        ) AS profile_photo,

        ph.id AS photo_id,
        ph.file_path AS post_image,
        ph.thumbnail_path AS post_thumbnail,
        ph.mime_type,

        COALESCE(
            (
                SELECT COUNT(*)

                FROM post_reactions pr_like

                WHERE
                    pr_like.post_id = p.id

                  AND pr_like.reaction = 'like'
            ),
            0
        ) AS like_count,

        COALESCE(
            (
                SELECT COUNT(*)

                FROM post_reactions pr_dislike

                WHERE
                    pr_dislike.post_id = p.id

                  AND pr_dislike.reaction = 'dislike'
            ),
            0
        ) AS dislike_count,

        (
            SELECT pr_me.reaction

            FROM post_reactions pr_me

            WHERE
                pr_me.post_id = p.id

              AND pr_me.user_id = :viewer_reaction_user

            LIMIT 1
        ) AS my_reaction

    FROM posts p

    INNER JOIN users u
        ON u.id = p.user_id

    LEFT JOIN countries c
        ON c.id = u.country_id

    LEFT JOIN post_photos pp
        ON pp.post_id = p.id
       AND pp.display_order = 1

    LEFT JOIN photos ph
        ON ph.id = pp.photo_id
       AND ph.approval_status = 'approved'

    WHERE

        p.approval_status = 'approved'

      AND p.visibility = 'public'

      AND p.deleted_at IS NULL

      AND u.is_active = 1

      AND u.is_suspended = 0

      AND u.is_deleted = 0

      AND u.email_verified = 1

      AND NOT EXISTS
      (
          SELECT 1

          FROM blocked_users b1

          WHERE
              b1.user_id = :block_viewer_a

            AND b1.blocked_user_id = u.id
      )

      AND NOT EXISTS
      (
          SELECT 1

          FROM blocked_users b2

          WHERE
              b2.user_id = u.id

            AND b2.blocked_user_id = :block_viewer_b
      )

    ORDER BY

        p.created_at DESC,
        p.id DESC

    LIMIT :limit
    OFFSET :offset
";


try {

    $stmt =
        $pdo->prepare(
            $sql
        );

    $stmt->bindValue(
        ':viewer_reaction_user',
        $userId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':block_viewer_a',
        $userId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':block_viewer_b',
        $userId,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':limit',
        $limit,
        PDO::PARAM_INT
    );

    $stmt->bindValue(
        ':offset',
        $offset,
        PDO::PARAM_INT
    );

    $stmt->execute();

    $rows =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FEED QUERY] ' .
        $e->getMessage()
    );

    feedResponse(
        false,
        'The latest posts could not be loaded.',
        [],
        500
    );
}


/* ============================================================
   CLEAN POSTS
============================================================ */

$posts =
    [];

foreach (
    $rows as $row
) {

    $mime =
        strtolower(
            trim(
                (string)(
                    $row['mime_type']
                    ??
                    ''
                )
            )
        );


    $mediaType =
        str_starts_with(
            $mime,
            'video/'
        )
            ?
            'video'
            :
            (
                str_starts_with(
                    $mime,
                    'image/'
                )
                    ?
                    'image'
                    :
                    ''
            );


    $posts[] = [

        'post_id' =>
            (int)
            $row['post_id'],

        'user_id' =>
            (int)
            $row['user_id'],

        'username' =>
            (string)
            $row['username'],

        'full_name' =>
            (string)
            $row['full_names'],

        'gender' =>
            (string)
            $row['gender'],

        'country_name' =>
            $row['country_name'] !== null
                ?
                (string)
                $row['country_name']
                :
                null,

        'country_iso2' =>
            $row['country_iso2'] !== null
                ?
                strtoupper(
                    (string)
                    $row['country_iso2']
                )
                :
                null,

        'email_verified' =>
            (bool)
            $row['email_verified'],

        'profile_photo' =>
            $row['profile_photo'] !== null
                ?
                (string)
                $row['profile_photo']
                :
                null,

        'content' =>
            (string)
            (
                $row['content']
                ??
                ''
            ),

        'post_image' =>
            $row['post_image'] !== null
                ?
                (string)
                $row['post_image']
                :
                null,

        'post_thumbnail' =>
            $row['post_thumbnail'] !== null
                ?
                (string)
                $row['post_thumbnail']
                :
                null,

        'mime_type' =>
            $mime,

        'media_type' =>
            $mediaType,

        'like_count' =>
            (int)
            $row['like_count'],

        'dislike_count' =>
            (int)
            $row['dislike_count'],

        'my_reaction' =>
            $row['my_reaction'] !== null
                ?
                (string)
                $row['my_reaction']
                :
                null,

        'posted_at' =>
            (string)
            $row['created_at']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

feedResponse(
    true,
    'Latest approved posts loaded.',
    [

        'data' => [

            'viewer' => [

                'id' =>
                    (int)
                    $viewer['id'],

                'username' =>
                    (string)
                    $viewer['username'],

                'full_name' =>
                    (string)
                    $viewer['full_names'],

                'gender' =>
                    (string)
                    $viewer['gender'],

                'country_name' =>
                    $viewer['country_name'],

                'country_iso2' =>
                    $viewer['country_iso2'],

                'profile_photo' =>
                    $viewer['profile_photo'],

                'premium_active' =>
                    $viewerPremium

            ],

            'posts' =>
                $posts,

            'count' =>
                count(
                    $posts
                )

        ]

    ]
);