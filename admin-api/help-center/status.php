<?php
declare(strict_types=1);
require_once __DIR__ . '/common.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    sc_response(false, 'Only POST requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$pdo = sc_pdo();
sc_ensure_schema($pdo);
sc_admin_auth($pdo);
$in = sc_input();
$id = (int)($in['ticket_id'] ?? 0);
$action = strtolower(sc_clean($in['action'] ?? '', 20));

if ($id <= 0 || !in_array($action, ['solve', 'close', 'reopen'], true)) {
    sc_response(false, 'Invalid ticket action.', ['code' => 'INVALID_ACTION'], 422);
}

$ticket = sc_get_ticket($pdo, $id);
if (!$ticket) {
    sc_response(false, 'Ticket not found.', ['code' => 'TICKET_NOT_FOUND'], 404);
}

try {
    if ($action === 'reopen') {
        $stmt = $pdo->prepare("UPDATE support_tickets
            SET status='awaiting_admin',
                solved_at=NULL,
                closed_at=NULL,
                close_at=NULL,
                last_message_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=:id LIMIT 1");
        $stmt->execute([':id' => $id]);
        sc_response(true, 'Ticket reopened and is now awaiting support.', [
            'status' => 'awaiting_admin',
            'ticket_id' => $id,
        ]);
    }

    // Both Solve and Close result in the ticket being permanently marked as solved.
    // "close" additionally records the exact closure timestamp.
    $stmt = $pdo->prepare("UPDATE support_tickets
        SET status='solved',
            solved_at=COALESCE(solved_at,CURRENT_TIMESTAMP),
            closed_at=CASE WHEN :action='close' THEN CURRENT_TIMESTAMP ELSE closed_at END,
            close_at=NULL,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=:id LIMIT 1");
    $stmt->execute([':action' => $action, ':id' => $id]);

    $message = $action === 'close'
        ? 'Ticket closed and automatically marked as solved.'
        : 'Ticket marked as solved.';

    sc_response(true, $message, [
        'status' => 'solved',
        'closed' => $action === 'close',
        'solved_at' => date('Y-m-d H:i:s'),
        'ticket_id' => $id,
    ]);
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT STATUS] ' . $e->getMessage());
    sc_response(false, 'The ticket status could not be updated.', ['code' => 'STATUS_UPDATE_FAILED'], 500);
}
