<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

$currentUserId = requireAuthenticatedUser();
$pdo = profileDb();

$postId = (int)($_GET['post_id'] ?? 0);

if ($postId <= 0) {
    jsonResponse(
        false,
        'Post ID is required.',
        ['code' => 'POST_ID_REQUIRED'],
        400
    );
}

try {
    /*
     * Verify that the post exists and is visible to this viewer.
     */
    $stmt = $pdo->prepare(
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

    $isOwner = $currentUserId === (int)$post['user_id'];

    /*
     * Owner may see their own post.
     * Other members may only see approved public posts.
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
            'Comments are not available.',
            ['code' => 'COMMENTS_UNAVAILABLE'],
            403
        );
    }

    /*
     * Load comments and replies.
     */
    $stmt = $pdo->prepare(
        "
        SELECT
            pc.id,
            pc.post_id,
            pc.user_id,
            pc.parent_id,
            pc.body,
            pc.created_at,
            pc.updated_at,

            u.username,
            u.full_names,
            u.gender,

            pr.display_name,
            pr.city,

            ph.file_path,
            ph.thumbnail_path

        FROM post_comments pc

        INNER JOIN users u
            ON u.id = pc.user_id

        LEFT JOIN profiles pr
            ON pr.user_id = u.id

        LEFT JOIN photos ph
            ON ph.user_id = u.id
           AND ph.approval_status = 'approved'
           AND ph.photo_type = 'profile'
           AND ph.is_primary = 1

        WHERE pc.post_id = :post_id

          AND u.is_active = 1
          AND u.is_suspended = 0
          AND u.is_deleted = 0

        ORDER BY
            pc.created_at ASC,
            pc.id ASC
        "
    );

    $stmt->execute([
        ':post_id' => $postId
    ]);

    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $comments = [];

    foreach ($rows as $row) {
        $parentId = $row['parent_id'] !== null
            ? (int)$row['parent_id']
            : null;

        $name =
            $row['display_name']
            ?: (
                $row['full_names']
                ?: (
                    $row['username']
                    ?: 'Member'
                )
            );

        $avatar =
            $row['thumbnail_path']
            ?: (
                $row['file_path']
                ?: null
            );

        $comments[] = [
            'id' => (int)$row['id'],

            'comment_id' => (int)$row['id'],

            'post_id' => (int)$row['post_id'],

            'user_id' => (int)$row['user_id'],

            'parent_id' => $parentId,

            'parent_comment_id' => $parentId,

            'body' => (string)$row['body'],

            'comment_text' => (string)$row['body'],

            'content' => (string)$row['body'],

            'created_at' => (string)$row['created_at'],

            'updated_at' => (string)$row['updated_at'],

            'username' => (string)$row['username'],

            'full_name' => (string)$name,

            'gender' => (string)$row['gender'],

            'avatar' => $avatar,

            'profile_photo' => $avatar,

            'city' => $row['city'] !== null
                ? (string)$row['city']
                : null
        ];
    }

    jsonResponse(
        true,
        'Comments loaded successfully.',
        [
            'post_id' => $postId,
            'count' => count($comments),
            'comments' => $comments
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE COMMENTS] '
        . $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to load comments.',
        ['code' => 'COMMENTS_QUERY_ERROR'],
        500
    );
}