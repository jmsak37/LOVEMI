<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');


if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function commentsResponse(
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


try {

    $pdo =
        db();

} catch (Throwable $e) {

    commentsResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS post_comments
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            post_id BIGINT UNSIGNED NOT NULL,

            user_id BIGINT UNSIGNED NOT NULL,

            parent_id BIGINT UNSIGNED NULL,

            body TEXT NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY(id),

            KEY idx_comment_post(post_id),

            KEY idx_comment_user(user_id),

            KEY idx_comment_parent(parent_id)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (Throwable $e) {

    commentsResponse(
        false,
        'Unable to prepare comments.',
        [],
        500
    );

}


$method =
    $_SERVER['REQUEST_METHOD']
    ??
    'GET';


/* ============================================================
   GET
============================================================ */

if (
    $method === 'GET'
) {

    $postId =
        (int)(
            $_GET['post_id']
            ??
            0
        );


    if (
        $postId <= 0
    ) {

        commentsResponse(
            false,
            'Invalid post.',
            [],
            422
        );

    }


    $post =
        $pdo->prepare(
            "
            SELECT id

            FROM posts

            WHERE

                id = :id

              AND approval_status = 'approved'

              AND visibility = 'public'

              AND deleted_at IS NULL

            LIMIT 1
            "
        );


    $post->execute(
        [
            ':id' =>
                $postId
        ]
    );


    if (!$post->fetch()) {

        commentsResponse(
            false,
            'Post not found.',
            [],
            404
        );

    }


    $stmt =
        $pdo->prepare(
            "
            SELECT

                pc.id,
                pc.post_id,
                pc.user_id,
                pc.parent_id,
                pc.body,
                pc.created_at,

                u.username,
                u.full_names,

                u.gender,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id = u.id

                      AND p.photo_type = 'profile'

                      AND p.approval_status = 'approved'

                      AND p.is_primary = 1

                    ORDER BY
                        p.id DESC

                    LIMIT 1

                ) AS avatar

            FROM post_comments pc

            INNER JOIN users u
                ON u.id = pc.user_id

            WHERE

                pc.post_id = :post_id

              AND u.is_active = 1

              AND u.is_suspended = 0

              AND u.is_deleted = 0

            ORDER BY

                pc.created_at ASC,

                pc.id ASC
            "
        );


    $stmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $rows =
        $stmt->fetchAll();


    $comments =
        [];


    foreach (
        $rows as $row
    ) {

        $comments[] =
            [

                'id' =>
                    (int)
                    $row['id'],

                'post_id' =>
                    (int)
                    $row['post_id'],

                'user_id' =>
                    (int)
                    $row['user_id'],

                'parent_id' =>
                    $row['parent_id'] !== null
                        ?
                        (int)
                        $row['parent_id']
                        :
                        0,

                'body' =>
                    (string)
                    $row['body'],

                'username' =>
                    (string)
                    $row['username'],

                'full_name' =>
                    (string)
                    $row['full_names'],

                'gender' =>
                    (string)
                    $row['gender'],

                'avatar' =>
                    $row['avatar'] !== null
                        ?
                        (string)
                        $row['avatar']
                        :
                        null,

                'created_at' =>
                    (string)
                    $row['created_at']

            ];

    }


    commentsResponse(
        true,
        'Comments loaded.',
        [
            'count' =>
                count(
                    $comments
                ),

            'comments' =>
                $comments
        ]
    );

}


/* ============================================================
   POST
============================================================ */

if (
    $method !==
    'POST'
) {

    commentsResponse(
        false,
        'Only GET and POST requests are allowed.',
        [],
        405
    );

}


$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    commentsResponse(
        false,
        'Please log in first.',
        [],
        401
    );

}


$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


$postId =
    (int)(
        $input['post_id']
        ??
        0
    );


$parentId =
    (int)(
        $input['parent_id']
        ??
        0
    );


$body =
    trim(
        (string)(
            $input['body']
            ??
            ''
        )
    );


if (
    $postId <= 0
) {

    commentsResponse(
        false,
        'Invalid post.',
        [],
        422
    );

}


if (
    $body === ''
) {

    commentsResponse(
        false,
        'Please write a comment.',
        [],
        422
    );

}


if (
    mb_strlen(
        $body,
        'UTF-8'
    )
    >
    1000
) {

    commentsResponse(
        false,
        'Comment is too long.',
        [],
        422
    );

}


/* ============================================================
   AUTOMATIC PERSONAL INFO CHECK
============================================================ */

if (
    preg_match(
        '/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i',
        $body
    )
) {

    commentsResponse(
        false,
        'Email addresses are not allowed in comments.',
        [
            'code' =>
                'EMAIL_BLOCKED'
        ],
        422
    );

}


if (
    preg_match(
        '/(?:\+?\d[\d\s().-]{7,}\d)/',
        $body
    )
) {

    commentsResponse(
        false,
        'Phone numbers are not allowed in comments.',
        [
            'code' =>
                'PHONE_BLOCKED'
        ],
        422
    );

}


/* ============================================================
   CUSTOM BLOCK LIST
============================================================ */

$blockFile =
    dirname(
        __DIR__,
        2
    )
    .
    DIRECTORY_SEPARATOR
    .
    'block-personal-information.txt';


if (
    is_file(
        $blockFile
    )
) {

    $lines =
        file(
            $blockFile,
            FILE_IGNORE_NEW_LINES |
            FILE_SKIP_EMPTY_LINES
        )
        ?:
        [];


    $lowerBody =
        mb_strtolower(
            $body,
            'UTF-8'
        );


    foreach (
        $lines as $line
    ) {

        $term =
            trim(
                $line
            );


        if (
            $term === ''
            ||
            str_starts_with(
                $term,
                '#'
            )
        ) {

            continue;

        }


        if (
            mb_strpos(
                $lowerBody,
                mb_strtolower(
                    $term,
                    'UTF-8'
                )
            )
            !==
            false
        ) {

            commentsResponse(
                false,
                'Your comment contains a blocked term.',
                [
                    'code' =>
                        'BLOCKED_TERM'
                ],
                422
            );

        }

    }

}


/* ============================================================
   POST CHECK
============================================================ */

$post =
    $pdo->prepare(
        "
        SELECT id

        FROM posts

        WHERE

            id = :id

          AND approval_status = 'approved'

          AND visibility = 'public'

          AND deleted_at IS NULL

        LIMIT 1
        "
    );


$post->execute(
    [
        ':id' =>
            $postId
    ]
);


if (!$post->fetch()) {

    commentsResponse(
        false,
        'This post is not available.',
        [],
        404
    );

}


/* ============================================================
   PARENT
============================================================ */

if (
    $parentId > 0
) {

    $parent =
        $pdo->prepare(
            "
            SELECT id

            FROM post_comments

            WHERE

                id = :id

              AND post_id = :post_id

            LIMIT 1
            "
        );


    $parent->execute(
        [
            ':id' =>
                $parentId,

            ':post_id' =>
                $postId
        ]
    );


    if (!$parent->fetch()) {

        commentsResponse(
            false,
            'The parent comment does not exist.',
            [],
            422
        );

    }

}


/* ============================================================
   INSERT
============================================================ */

$stmt =
    $pdo->prepare(
        "
        INSERT INTO post_comments
        (
            post_id,
            user_id,
            parent_id,
            body,
            created_at
        )
        VALUES
        (
            :post_id,
            :user_id,
            :parent_id,
            :body,
            CURRENT_TIMESTAMP
        )
        "
    );


$stmt->execute(
    [

        ':post_id' =>
            $postId,

        ':user_id' =>
            $userId,

        ':parent_id' =>
            $parentId > 0
                ?
                $parentId
                :
                null,

        ':body' =>
            $body

    ]
);


$commentId =
    (int)
    $pdo->lastInsertId();


commentsResponse(
    true,
    $parentId > 0
        ?
        'Reply posted successfully.'
        :
        'Comment posted successfully.',
    [
        'comment_id' =>
            $commentId,

        'post_id' =>
            $postId,

        'parent_id' =>
            $parentId
    ],
    201
);