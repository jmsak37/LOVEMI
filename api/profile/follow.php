<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

/*
 * Only POST is allowed.
 */
if (
    ($_SERVER['REQUEST_METHOD'] ?? 'POST')
    !== 'POST'
) {

    profileJsonResponse(
        false,
        'Only POST requests are allowed.',
        ['code' => 'METHOD_NOT_ALLOWED'],
        405
    );
}

$viewerId =
    profileRequireAuth();

/*
 * Read request JSON.
 */
$input = json_decode(
    file_get_contents('php://input') ?: '{}',
    true
);

$input = is_array($input)
    ? $input
    : $_POST;

/*
 * Target member.
 */
$targetId = (int)(
    $input['user_id']
    ?? $input['target_user_id']
    ?? 0
);

/*
 * Requested action.
 */
$action = strtolower(
    trim(
        (string)(
            $input['action']
            ?? 'follow'
        )
    )
);

/*
 * Validate member.
 */
if (
    $targetId <= 0
    || $targetId === $viewerId
) {

    profileJsonResponse(
        false,
        'Invalid member.',
        ['code' => 'INVALID_TARGET'],
        422
    );
}

/*
 * Validate action.
 */
if (
    !in_array(
        $action,
        ['follow', 'unfollow'],
        true
    )
) {

    profileJsonResponse(
        false,
        'Invalid friend action.',
        ['code' => 'INVALID_ACTION'],
        422
    );
}

try {

    $pdo =
        profileDb();

    /*
     * Verify target user.
     */
    $target = $pdo->prepare(
        '
        SELECT
            id,
            account_status,
            email_verified,
            is_active,
            is_suspended,
            is_deleted
        FROM users
        WHERE id = :id
        LIMIT 1
        '
    );

    $target->execute([
        ':id' => $targetId
    ]);

    $user =
        $target->fetch(PDO::FETCH_ASSOC);

    /*
     * Target must be an approved,
     * active and verified LOVEMI member.
     */
    if (
        !$user
        || (int)$user['is_active'] !== 1
        || (int)$user['is_suspended'] === 1
        || (int)$user['is_deleted'] === 1
        || strtolower(
            (string)$user['account_status']
        ) !== 'approved'
        || (int)$user['email_verified'] !== 1
    ) {

        profileJsonResponse(
            false,
            'This member is unavailable.',
            ['code' => 'TARGET_UNAVAILABLE'],
            403
        );
    }

    /*
     * Friend relationship is required first.
     */
    $connection =
        profileGetConnection(
            $pdo,
            $viewerId,
            $targetId
        );

    if (
        !profileIsConnected($connection)
    ) {

        profileJsonResponse(
            false,
            'You must be friends with this member before changing Friend follow status.',
            ['code' => 'CONNECTION_REQUIRED'],
            403
        );
    }

    /*
     * FOLLOW.
     */
    if ($action === 'follow') {

        $stmt = $pdo->prepare(
            '
            INSERT IGNORE INTO user_follows
            (
                follower_id,
                following_id
            )
            VALUES
            (
                :follower_id,
                :following_id
            )
            '
        );

        $stmt->execute([
            ':follower_id' =>
                $viewerId,

            ':following_id' =>
                $targetId
        ]);

        $following = true;

        $message =
            'You are now following your Friend. You will receive notifications about new posts.';

    } else {

        /*
         * UNFOLLOW.
         */
        $stmt = $pdo->prepare(
            '
            DELETE FROM user_follows
            WHERE follower_id = :follower_id
              AND following_id = :following_id
            '
        );

        $stmt->execute([
            ':follower_id' =>
                $viewerId,

            ':following_id' =>
                $targetId
        ]);

        $following = false;

        $message =
            'You stopped following this Friend.';
    }

    /*
     * Current follower count.
     */
    $count =
        $pdo->prepare(
            '
            SELECT COUNT(*)
            FROM user_follows
            WHERE following_id = :id
            '
        );

    $count->execute([
        ':id' => $targetId
    ]);

    $followers =
        (int)$count->fetchColumn();

    /*
     * Return current relationship state.
     */
    profileJsonResponse(
        true,
        $message,
        [
            'following' =>
                $following,

            'followers_count' =>
                $followers,

            'connected' =>
                true,

            'status' =>
                'accepted'
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FOLLOW] '
        . $e->getMessage()
    );

    profileJsonResponse(
        false,
        'Unable to update Friend follow status.',
        [
            'code' =>
                'FOLLOW_STORAGE_ERROR'
        ],
        500
    );
}