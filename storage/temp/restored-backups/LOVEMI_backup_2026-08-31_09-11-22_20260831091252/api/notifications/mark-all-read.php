<?php
/**
 * ============================================================
 * LOVEMI - MARK ALL NOTIFICATIONS AS READ
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function jsonResponse(
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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    jsonResponse(
        false,
        'Only POST requests are allowed.',
        ['code' => 'METHOD_NOT_ALLOWED'],
        405
    );
}

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {
    jsonResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MARK ALL READ DB] ' .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Database connection failed.',
        ['code' => 'DATABASE_ERROR'],
        500
    );
}

try {

    $pdo->beginTransaction();

    $stmt =
        $pdo->prepare(
            "
            UPDATE notifications

            SET
                is_read = 1,
                read_at = CURRENT_TIMESTAMP

            WHERE user_id = :user_id

              AND is_read = 0
            "
        );

    $stmt->execute(
        [
            ':user_id' => $userId
        ]
    );

    $changed =
        $stmt->rowCount();

    $pdo->commit();

} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        '[LOVEMI MARK ALL READ] ' .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to mark notifications as read.',
        ['code' => 'UPDATE_FAILED'],
        500
    );
}

/* ============================================================
   VERIFY
============================================================ */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM notifications

            WHERE user_id = :user_id

              AND is_read = 0
            "
        );

    $countStmt->execute(
        [
            ':user_id' => $userId
        ]
    );

    $unreadCount =
        (int) $countStmt->fetchColumn();

} catch (Throwable $e) {

    $unreadCount = 0;
}

jsonResponse(
    true,
    $changed > 0
        ? 'All notifications marked as read.'
        : 'There were no unread notifications.',
    [
        'changed' => $changed,
        'unread_count' => $unreadCount
    ]
);