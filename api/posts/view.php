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


function viewResponse(
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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    viewResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

}


$token =
    trim(
        (string)(
            $_GET['token']
            ??
            ''
        )
    );


if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $token
    )
) {

    viewResponse(
        false,
        'Invalid post link.',
        [],
        422
    );

}


try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIEW DB] ' .
        $e->getMessage()
    );

    viewResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                ppl.post_id,

                p.user_id,

                p.content,

                p.created_at,
                p.updated_at,

                u.username,
                u.full_names,
                u.gender,
                u.email_verified,

                c.name AS country_name,

                pr.file_path AS profile_photo,

                ph.file_name,
                ph.file_path,
                ph.mime_type,
                ph.thumbnail_path

            FROM post_public_links ppl

            INNER JOIN posts p
                ON p.id = ppl.post_id

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN
            (
                SELECT
                    user_id,
                    file_path

                FROM photos

                WHERE
                    photo_type = 'profile'

                  AND approval_status = 'approved'

                  AND is_primary = 1

                GROUP BY
                    user_id
            ) pr
                ON pr.user_id = u.id

            LEFT JOIN post_photos pp
                ON pp.post_id = p.id
                AND pp.display_order = 1

            LEFT JOIN photos ph
                ON ph.id = pp.photo_id
                AND ph.approval_status = 'approved'

            WHERE

                ppl.public_token = :token

              AND p.approval_status = 'approved'

              AND p.visibility = 'public'

              AND p.deleted_at IS NULL

              AND u.is_active = 1

              AND u.is_suspended = 0

              AND u.is_deleted = 0

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':token' =>
                $token
        ]
    );


    $row =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIEW QUERY] ' .
        $e->getMessage()
    );

    viewResponse(
        false,
        'Unable to load this post.',
        [],
        500
    );

}


if (!$row) {

    viewResponse(
        false,
        'This post is no longer available.',
        [
            'code' =>
                'POST_NOT_AVAILABLE'
        ],
        404
    );

}


/*
 * Update usage timestamp.
 */

try {

    $touch =
        $pdo->prepare(
            "
            UPDATE post_public_links

            SET last_used_at =
                CURRENT_TIMESTAMP

            WHERE public_token =
                :token

            LIMIT 1
            "
        );


    $touch->execute(
        [
            ':token' =>
                $token
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIEW TOUCH] ' .
        $e->getMessage()
    );

}


/*
 * Current visitor.
 */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


/*
 * Make reactions table automatically.
 */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS post_reactions
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            post_id BIGINT UNSIGNED NOT NULL,

            user_id BIGINT UNSIGNED NOT NULL,

            reaction VARCHAR(20) NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY(id),

            UNIQUE KEY uq_post_reaction_user
                (post_id,user_id),

            KEY idx_post_reaction_post
                (post_id),

            CONSTRAINT fk_post_reaction_post
                FOREIGN KEY(post_id)
                REFERENCES posts(id)
                ON DELETE CASCADE,

            CONSTRAINT fk_post_reaction_user
                FOREIGN KEY(user_id)
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
        '[LOVEMI VIEW REACTION TABLE] ' .
        $e->getMessage()
    );

}


$postId =
    (int)
    $row['post_id'];


$likeCount =
    0;


$dislikeCount =
    0;


$myReaction =
    null;


try {

    $reactionStmt =
        $pdo->prepare(
            "
            SELECT

                SUM(
                    CASE
                        WHEN reaction = 'like'
                        THEN 1
                        ELSE 0
                    END
                ) AS likes,

                SUM(
                    CASE
                        WHEN reaction = 'dislike'
                        THEN 1
                        ELSE 0
                    END
                ) AS dislikes

            FROM post_reactions

            WHERE post_id =
                :post_id
            "
        );


    $reactionStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $reactionCounts =
        $reactionStmt->fetch();


    $likeCount =
        (int)(
            $reactionCounts['likes']
            ??
            0
        );


    $dislikeCount =
        (int)(
            $reactionCounts['dislikes']
            ??
            0
        );


    if (
        $currentUserId > 0
    ) {

        $mine =
            $pdo->prepare(
                "
                SELECT reaction

                FROM post_reactions

                WHERE
                    post_id = :post_id

                  AND user_id = :user_id

                LIMIT 1
                "
            );


        $mine->execute(
            [
                ':post_id' =>
                    $postId,

                ':user_id' =>
                    $currentUserId
            ]
        );


        $myReaction =
            $mine->fetchColumn()
            ?:
            null;

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIEW REACTIONS] ' .
        $e->getMessage()
    );

}


/*
 * Comment count.
 */

$commentCount =
    0;


try {

    $commentTable =
        $pdo->query(
            "
            SHOW TABLES LIKE
            'post_comments'
            "
        );


    if (
        $commentTable
        &&
        $commentTable->fetch()
    ) {

        $countStmt =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM post_comments

                WHERE post_id = :post_id
                "
            );


        $countStmt->execute(
            [
                ':post_id' =>
                    $postId
            ]
        );


        $commentCount =
            (int)
            $countStmt->fetchColumn();

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VIEW COMMENTS] ' .
        $e->getMessage()
    );

}


/*
 * No private information is returned.
 */

viewResponse(
    true,
    'Post loaded successfully.',
    [
        'post' =>

            [

                'id' =>
                    $postId,

                'user_id' =>
                    (int)
                    $row['user_id'],

                'full_name' =>
                    (string)
                    $row['full_names'],

                'username' =>
                    (string)
                    $row['username'],

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

                'file_name' =>
                    $row['file_name'] !== null
                        ?
                        (string)
                        $row['file_name']
                        :
                        null,

                'media_url' =>
                    $row['file_path'] !== null
                        ?
                        (string)
                        $row['file_path']
                        :
                        null,

                'mime_type' =>
                    $row['mime_type'] !== null
                        ?
                        (string)
                        $row['mime_type']
                        :
                        null,

                'thumbnail_url' =>
                    $row['thumbnail_path'] !== null
                        ?
                        (string)
                        $row['thumbnail_path']
                        :
                        null,

                'created_at' =>
                    (string)
                    $row['created_at'],

                'like_count' =>
                    $likeCount,

                'dislike_count' =>
                    $dislikeCount,

                'comment_count' =>
                    $commentCount,

                'my_reaction' =>
                    $myReaction,

                'is_owner' =>
                    $currentUserId > 0
                    &&
                    $currentUserId
                    ===
                    (int)
                    $row['user_id']

            ]
    ]
);