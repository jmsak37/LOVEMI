<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

$currentUserId =
    requireAuthenticatedUser();

$pdo =
    profileDb();


$input =
    json_decode(
        file_get_contents('php://input'),
        true
    );


if (!is_array($input)) {
    $input = [];
}


$postId =
    isset($input['post_id'])
        ? (int)$input['post_id']
        : 0;


if ($postId <= 0) {

    jsonResponse(
        false,
        'Post ID is required.',
        [],
        400
    );
}


/* ============================================================
   POST
============================================================ */

$stmt =
    $pdo->prepare(
        "
        SELECT
            id,
            user_id,
            approval_status,
            visibility,
            deleted_at

        FROM posts

        WHERE id = :post_id

        LIMIT 1
        "
    );


$stmt->execute(
    [
        ':post_id' =>
            $postId
    ]
);


$post =
    $stmt->fetch();


if (!$post) {

    jsonResponse(
        false,
        'Post not found.',
        [],
        404
    );
}


if (
    $post['approval_status'] !== 'approved'
    ||
    $post['visibility'] !== 'public'
    ||
    $post['deleted_at'] !== null
) {

    jsonResponse(
        false,
        'This post is not available.',
        [],
        403
    );
}


/* ============================================================
   EXISTING LIKE
============================================================ */

$existingStmt =
    $pdo->prepare(
        "
        SELECT id

        FROM post_likes

        WHERE post_id = :post_id
          AND user_id = :user_id

        LIMIT 1
        "
    );


$existingStmt->execute(
    [
        ':post_id' =>
            $postId,

        ':user_id' =>
            $currentUserId
    ]
);


$existingLike =
    $existingStmt->fetchColumn();


if ($existingLike) {

    $deleteStmt =
        $pdo->prepare(
            "
            DELETE FROM post_likes

            WHERE post_id = :post_id
              AND user_id = :user_id
            "
        );


    $deleteStmt->execute(
        [
            ':post_id' =>
                $postId,

            ':user_id' =>
                $currentUserId
        ]
    );


    $liked =
        false;

} else {

    $insertStmt =
        $pdo->prepare(
            "
            INSERT INTO post_likes
            (
                post_id,
                user_id
            )
            VALUES
            (
                :post_id,
                :user_id
            )
            "
        );


    $insertStmt->execute(
        [
            ':post_id' =>
                $postId,

            ':user_id' =>
                $currentUserId
        ]
    );


    $liked =
        true;


    $postOwnerId =
        (int)$post['user_id'];


    if (
        $postOwnerId > 0
        &&
        $postOwnerId !== $currentUserId
    ) {

        createNotification(
            $pdo,
            $postOwnerId,
            $currentUserId,
            'post_liked',
            'Someone liked your post',
            'Someone liked your post.',
            'post',
            $postId
        );
    }
}


/* ============================================================
   COUNT
============================================================ */

$countStmt =
    $pdo->prepare(
        "
        SELECT COUNT(*)
        FROM post_likes
        WHERE post_id = :post_id
        "
    );


$countStmt->execute(
    [
        ':post_id' =>
            $postId
    ]
);


$count =
    (int)$countStmt->fetchColumn();


jsonResponse(
    true,
    $liked
        ? 'Post liked.'
        : 'Post unliked.',
    [
        'post_id' =>
            $postId,

        'liked' =>
            $liked,

        'likes_count' =>
            $count
    ]
);