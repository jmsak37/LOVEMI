<?php
/**
 * ============================================================
 * LOVEMI - MARK NOTIFICATION AS READ
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

$raw =
    file_get_contents('php://input');

$input =
    json_decode(
        (string) $raw,
        true
    );

if (!is_array($input)) {
    $input = [];
}

$notificationId =
    isset($_POST['notification_id'])
        ? (int) $_POST['notification_id']
        : (
            isset($_GET['notification_id'])
                ? (int) $_GET['notification_id']
                : (int) ($input['notification_id'] ?? 0)
        );

if ($notificationId <= 0) {
    jsonResponse(
        false,
        'Notification ID is required.',
        ['code' => 'NOTIFICATION_ID_REQUIRED'],
        422
    );
}

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MARK READ DB] ' .
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

    $stmt =
        $pdo->prepare(
            "
            UPDATE notifications

            SET
                is_read = 1,
                read_at = CURRENT_TIMESTAMP

            WHERE id = :notification_id

              AND user_id = :user_id

              AND is_read = 0

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':notification_id' => $notificationId,
            ':user_id' => $userId
        ]
    );

    $changed =
        $stmt->rowCount() > 0;

} catch (Throwable $e) {

    error_log(
        '[LOVEMI MARK READ QUERY] ' .
        $e->getMessage()
    );

    jsonResponse(
        false,
        'Unable to mark the notification as read.',
        ['code' => 'UPDATE_FAILED'],
        500
    );
}

/* ============================================================
   CURRENT UNREAD COUNT
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

/* ============================================================
   RESPONSE
============================================================ */

jsonResponse(
    true,
    $changed
        ? 'Notification marked as read.'
        : 'Notification was already read.',
    [
        'notification_id' => $notificationId,
        'was_changed' => $changed,
        'unread_count' => $unreadCount
    ]
);