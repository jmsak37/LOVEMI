<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
) {

    jsonResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

$currentUserId =
    requireAuthenticatedUser();

$pdo =
    profileDb();

$input =
    json_decode(
        file_get_contents(
            'php://input'
        )
        ?: '{}',
        true
    );

$input =
    is_array($input)
        ? $input
        : [];

$postId =
    (int)(
        $input['post_id']
        ?? 0
    );

$parentId =
    (int)(
        $input['parent_id']
        ?? $input['parent_comment_id']
        ?? 0
    );

$body =
    trim(
        (string)(
            $input['body']
            ?? $input['comment']
            ?? $input['comment_text']
            ?? ''
        )
    );

if ($postId <= 0) {

    jsonResponse(
        false,
        'Post ID is required.',
        [
            'code' =>
                'POST_ID_REQUIRED'
        ],
        422
    );
}

if ($body === '') {

    jsonResponse(
        false,
        'Please write a comment.',
        [
            'code' =>
                'COMMENT_EMPTY'
        ],
        422
    );
}

if (mb_strlen($body) > 5000) {

    jsonResponse(
        false,
        'Your comment is too long.',
        [
            'code' =>
                'COMMENT_TOO_LONG'
        ],
        422
    );
}

try {

    $postStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                user_id,
                visibility,
                approval_status,
                deleted_at
            FROM posts
            WHERE id = :id
            LIMIT 1
            "
        );

    $postStmt->execute([
        ':id' =>
            $postId
    ]);

    $post =
        $postStmt->fetch(PDO::FETCH_ASSOC);

    if (!$post) {

        jsonResponse(
            false,
            'Post not found.',
            [
                'code' =>
                    'POST_NOT_FOUND'
            ],
            404
        );
    }

    $isPostOwner =
        (int)$post['user_id']
        === $currentUserId;

    if (
        $post['deleted_at'] !== null
        || (
            !$isPostOwner
            && (
                $post['approval_status']
                    !== 'approved'
                || $post['visibility']
                    !== 'public'
            )
        )
    ) {

        jsonResponse(
            false,
            'Comments are not available for this post.',
            [
                'code' =>
                    'COMMENTS_UNAVAILABLE'
            ],
            403
        );
    }

    $parent = null;

    if ($parentId > 0) {

        $parentStmt =
            $pdo->prepare(
                "
                SELECT
                    id,
                    user_id,
                    post_id
                FROM post_comments
                WHERE id = :id
                  AND post_id = :post_id
                LIMIT 1
                "
            );

        $parentStmt->execute(
            [
                ':id' =>
                    $parentId,

                ':post_id' =>
                    $postId
            ]
        );

        $parent =
            $parentStmt->fetch(PDO::FETCH_ASSOC);

        if (!$parent) {

            jsonResponse(
                false,
                'The comment you are replying to was not found.',
                [
                    'code' =>
                        'PARENT_COMMENT_NOT_FOUND'
                ],
                404
            );
        }
    }

    $pdo->beginTransaction();

    try {

        $insert =
            $pdo->prepare(
                "
                INSERT INTO post_comments
                (
                    post_id,
                    user_id,
                    parent_id,
                    body,
                    created_at,
                    updated_at
                )
                VALUES
                (
                    :post_id,
                    :user_id,
                    :parent_id,
                    :body,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                "
            );

        $insert->execute(
            [
                ':post_id' =>
                    $postId,

                ':user_id' =>
                    $currentUserId,

                ':parent_id' =>
                    $parentId > 0
                        ? $parentId
                        : null,

                ':body' =>
                    $body
            ]
        );

        $commentId =
            (int)$pdo->lastInsertId();

        $postOwnerId =
            (int)$post['user_id'];

        if (
            $postOwnerId > 0
            && $postOwnerId !== $currentUserId
        ) {

            createNotification(
                $pdo,
                $postOwnerId,
                $currentUserId,
                'post_commented',
                'New comment on your post',
                'Someone commented on your post.',
                'post',
                $postId
            );
        }

        if (
            $parentId > 0
            && $parent
        ) {

            $parentOwnerId =
                (int)$parent['user_id'];

            if (
                $parentOwnerId > 0
                && $parentOwnerId !== $currentUserId
                && $parentOwnerId !== $postOwnerId
            ) {

                createNotification(
                    $pdo,
                    $parentOwnerId,
                    $currentUserId,
                    'comment_reply',
                    'New reply to your comment',
                    'Someone replied to your comment.',
                    'comment',
                    $parentId
                );
            }
        }

        $pdo->commit();

        jsonResponse(
            true,
            $parentId > 0
                ? 'Reply posted successfully.'
                : 'Comment posted successfully.',
            [
                'comment_id' =>
                    $commentId,

                'post_id' =>
                    $postId,

                'parent_id' =>
                    $parentId > 0
                        ? $parentId
                        : null,

                'body' =>
                    $body
            ],
            201
        );

    } catch (Throwable $e) {

        if (
            $pdo->inTransaction()
        ) {
            $pdo->rollBack();
        }

        throw $e;
    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE COMMENT] ' .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to save the comment.',
        [
            'code' =>
                'COMMENT_STORAGE_ERROR'
        ],
        500
    );
}