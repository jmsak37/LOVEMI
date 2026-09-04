<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$currentUserId = requireAuthenticatedUser();
$pdo = profileDb();

/*
 * Read JSON request.
 */
$input = json_decode(
    file_get_contents('php://input') ?: '{}',
    true
);

$input = is_array($input)
    ? $input
    : [];

/*
 * Accept both normal comments and replies.
 */
$postId = (int)(
    $input['post_id']
    ?? 0
);

$parentId = (int)(
    $input['parent_id']
    ?? $input['parent_comment_id']
    ?? 0
);

$body = trim(
    (string)(
        $input['body']
        ?? $input['comment']
        ?? $input['comment_text']
        ?? ''
    )
);

/*
 * Validate post.
 */
if ($postId <= 0) {
    jsonResponse(
        false,
        'Post ID is required.',
        ['code' => 'POST_ID_REQUIRED'],
        400
    );
}

/*
 * Validate comment body.
 */
if ($body === '') {
    jsonResponse(
        false,
        'Please write a comment.',
        ['code' => 'COMMENT_EMPTY'],
        400
    );
}

/*
 * Maximum comment length.
 */
if (mb_strlen($body) > 5000) {
    jsonResponse(
        false,
        'Your comment is too long.',
        ['code' => 'COMMENT_TOO_LONG'],
        422
    );
}

try {

    /*
     * Verify the post.
     */
    $stmt = $pdo->prepare(
        '
        SELECT
            id,
            user_id,
            approval_status,
            visibility,
            deleted_at
        FROM posts
        WHERE id = :post_id
        LIMIT 1
        '
    );

    $stmt->execute([
        ':post_id' => $postId
    ]);

    $post = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$post) {
        jsonResponse(
            false,
            'Post not found.',
            ['code' => 'POST_NOT_FOUND'],
            404
        );
    }

    $isOwner =
        $currentUserId === (int)$post['user_id'];

    /*
     * Owner can comment on their own post.
     *
     * Other users can comment only on:
     * - approved
     * - public
     * - non-deleted posts
     */
    if (
        $post['deleted_at'] !== null
        || (
            !$isOwner
            && (
                $post['approval_status'] !== 'approved'
                || $post['visibility'] !== 'public'
            )
        )
    ) {
        jsonResponse(
            false,
            'Comments are not available for this post.',
            ['code' => 'COMMENTS_UNAVAILABLE'],
            403
        );
    }

    /*
     * Parent comment.
     *
     * A parent must belong to the same post.
     */
    $parent = null;

    if ($parentId > 0) {

        $parentStmt = $pdo->prepare(
            '
            SELECT
                id,
                user_id,
                post_id
            FROM post_comments
            WHERE id = :id
              AND post_id = :post_id
            LIMIT 1
            '
        );

        $parentStmt->execute([
            ':id' => $parentId,
            ':post_id' => $postId
        ]);

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

    /*
     * Save comment.
     */
    $stmt = $pdo->prepare(
        '
        INSERT INTO post_comments
        (
            post_id,
            user_id,
            parent_id,
            body
        )
        VALUES
        (
            :post_id,
            :user_id,
            :parent_id,
            :body
        )
        '
    );

    $stmt->execute([
        ':post_id' => $postId,

        ':user_id' => $currentUserId,

        ':parent_id' =>
            $parentId > 0
                ? $parentId
                : null,

        ':body' => $body
    ]);

    $commentId =
        (int)$pdo->lastInsertId();

    /*
     * Notify post owner.
     */
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

    /*
     * Notify the parent-comment owner
     * when this is a reply.
     */
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

    /*
     * Return successful result.
     */
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

    error_log(
        '[LOVEMI PROFILE COMMENT] '
        . $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to save the comment.',
        ['code' => 'COMMENT_STORAGE_ERROR'],
        500
    );
}