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

function responseBlock(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {
    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    responseBlock(
        false,
        'Only POST requests are allowed.',
        ['code' => 'METHOD_NOT_ALLOWED'],
        405
    );
}

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {
    responseBlock(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}

$raw = file_get_contents('php://input');

$input = json_decode(
    (string) $raw,
    true
);

if (!is_array($input)) {
    $input = $_POST;
}

$blockedUserId =
    (int) (
        $input['blocked_user_id']
        ??
        $input['user_id']
        ??
        0
    );

$reason =
    trim(
        (string)
        (
            $input['reason']
            ??
            'Blocked by user'
        )
    );

if ($blockedUserId <= 0) {
    responseBlock(
        false,
        'The user to block is required.',
        ['code' => 'USER_ID_REQUIRED'],
        422
    );
}

if ($blockedUserId === $currentUserId) {
    responseBlock(
        false,
        'You cannot block your own account.',
        ['code' => 'SELF_BLOCK_NOT_ALLOWED'],
        422
    );
}

if (mb_strlen($reason) > 255) {
    $reason = mb_substr($reason, 0, 255);
}

try {
    $pdo = db();
} catch (Throwable $e) {
    error_log('[LOVEMI BLOCK DB] ' . $e->getMessage());

    responseBlock(
        false,
        'Database connection failed.',
        ['code' => 'DATABASE_ERROR'],
        500
    );
}

/* ------------------------------------------------------------
   Verify target account
------------------------------------------------------------ */

try {
    $stmt = $pdo->prepare(
        "
        SELECT
            id,
            is_active,
            is_suspended,
            is_deleted
        FROM users
        WHERE id = :id
        LIMIT 1
        "
    );

    $stmt->execute([
        ':id' => $blockedUserId
    ]);

    $target = $stmt->fetch();

} catch (Throwable $e) {

    error_log('[LOVEMI BLOCK USER LOOKUP] ' . $e->getMessage());

    responseBlock(
        false,
        'Unable to load the selected account.',
        [],
        500
    );
}

if (!$target) {
    responseBlock(
        false,
        'The selected user does not exist.',
        ['code' => 'USER_NOT_FOUND'],
        404
    );
}

/* ------------------------------------------------------------
   Check existing block
------------------------------------------------------------ */

try {
    $existingStmt = $pdo->prepare(
        "
        SELECT
            id,
            reason
        FROM blocked_users
        WHERE user_id = :user_id
          AND blocked_user_id = :blocked_user_id
        LIMIT 1
        "
    );

    $existingStmt->execute([
        ':user_id' => $currentUserId,
        ':blocked_user_id' => $blockedUserId
    ]);

    $existing = $existingStmt->fetch();

} catch (Throwable $e) {

    error_log('[LOVEMI BLOCK EXISTING] ' . $e->getMessage());

    responseBlock(
        false,
        'Unable to verify the current block status.',
        [],
        500
    );
}

if ($existing) {

    responseBlock(
        true,
        'This user is already blocked.',
        [
            'block_id' => (int) $existing['id'],
            'already_blocked' => true
        ]
    );
}

/* ------------------------------------------------------------
   Create block
------------------------------------------------------------ */

try {

    $pdo->beginTransaction();

    $insertStmt = $pdo->prepare(
        "
        INSERT INTO blocked_users
        (
            user_id,
            blocked_user_id,
            reason
        )
        VALUES
        (
            :user_id,
            :blocked_user_id,
            :reason
        )
        "
    );

    $insertStmt->execute([
        ':user_id' => $currentUserId,
        ':blocked_user_id' => $blockedUserId,
        ':reason' => $reason !== '' ? $reason : null
    ]);

    $blockId =
        (int) $pdo->lastInsertId();

    /*
     * Stop the active connection between the two users.
     */
    $connectionStmt = $pdo->prepare(
        "
        UPDATE connections
        SET
            status = 'blocked'
        WHERE user_low_id =
              LEAST(:user_one, :user_two)
          AND user_high_id =
              GREATEST(:user_three, :user_four)
          AND status IN
              ('pending','accepted','connected')
        "
    );

    $connectionStmt->execute([
        ':user_one' => $currentUserId,
        ':user_two' => $blockedUserId,
        ':user_three' => $currentUserId,
        ':user_four' => $blockedUserId
    ]);

    /*
     * Disable active conversation.
     */
    $conversationStmt = $pdo->prepare(
        "
        UPDATE conversations
        SET status = 'blocked'
        WHERE user_low_id =
              LEAST(:user_one, :user_two)
          AND user_high_id =
              GREATEST(:user_three, :user_four)
          AND status = 'active'
        "
    );

    $conversationStmt->execute([
        ':user_one' => $currentUserId,
        ':user_two' => $blockedUserId,
        ':user_three' => $currentUserId,
        ':user_four' => $blockedUserId
    ]);

    $pdo->commit();

} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('[LOVEMI BLOCK TRANSACTION] ' . $e->getMessage());

    responseBlock(
        false,
        'Unable to block this user.',
        ['code' => 'BLOCK_FAILED'],
        500
    );
}

/* ------------------------------------------------------------
   Response
------------------------------------------------------------ */

responseBlock(
    true,
    'User blocked successfully.',
    [
        'block_id' => $blockId,
        'blocked_user_id' => $blockedUserId,
        'blocked' => true
    ]
);