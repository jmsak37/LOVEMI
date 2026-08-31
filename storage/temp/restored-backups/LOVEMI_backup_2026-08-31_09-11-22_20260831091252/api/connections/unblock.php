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

function responseUnblock(
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
    responseUnblock(
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
    responseUnblock(
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

if ($blockedUserId <= 0) {
    responseUnblock(
        false,
        'The user to unblock is required.',
        ['code' => 'USER_ID_REQUIRED'],
        422
    );
}

if ($blockedUserId === $currentUserId) {
    responseUnblock(
        false,
        'Invalid unblock request.',
        ['code' => 'INVALID_TARGET'],
        422
    );
}

try {
    $pdo = db();
} catch (Throwable $e) {

    error_log('[LOVEMI UNBLOCK DB] ' . $e->getMessage());

    responseUnblock(
        false,
        'Database connection failed.',
        ['code' => 'DATABASE_ERROR'],
        500
    );
}

/* ------------------------------------------------------------
   Remove block
------------------------------------------------------------ */

try {

    $stmt = $pdo->prepare(
        "
        DELETE FROM blocked_users

        WHERE user_id =
              :user_id

          AND blocked_user_id =
              :blocked_user_id

        LIMIT 1
        "
    );

    $stmt->execute([
        ':user_id' => $currentUserId,
        ':blocked_user_id' => $blockedUserId
    ]);

    $removed =
        $stmt->rowCount();

} catch (Throwable $e) {

    error_log('[LOVEMI UNBLOCK] ' . $e->getMessage());

    responseUnblock(
        false,
        'Unable to unblock this user.',
        ['code' => 'UNBLOCK_FAILED'],
        500
    );
}

if ($removed < 1) {

    responseUnblock(
        true,
        'This user was not blocked.',
        [
            'already_unblocked' => true,
            'blocked' => false
        ]
    );
}

/*
 * Do NOT automatically restore an old conversation here.
 * The users must explicitly reconnect through the normal
 * LOVEMI connection flow.
 */

responseUnblock(
    true,
    'User unblocked successfully.',
    [
        'blocked_user_id' => $blockedUserId,
        'blocked' => false
    ]
);