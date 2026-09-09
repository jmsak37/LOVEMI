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
if ($id <= 0) sc_response(false, 'Invalid ticket.', ['code' => 'INVALID_TICKET'], 422);

$ticket = sc_get_ticket($pdo, $id);
if (!$ticket) sc_response(false, 'Ticket not found.', ['code' => 'TICKET_NOT_FOUND'], 404);

$status = strtolower((string)($ticket['status'] ?? ''));
if (!in_array($status, ['solved', 'closed'], true) && empty($ticket['solved_at'])) {
    sc_response(false, 'Only solved or closed tickets can be deleted.', ['code' => 'TICKET_NOT_SOLVED'], 409);
}

try {
    $pdo->beginTransaction();
    $pdo->prepare("DELETE FROM notifications WHERE reference_type='support_ticket' AND reference_id=:id")->execute([':id' => $id]);
    $pdo->prepare('DELETE FROM support_ticket_messages WHERE ticket_id=:id')->execute([':id' => $id]);
    $pdo->prepare('DELETE FROM support_ticket_access WHERE ticket_id=:id')->execute([':id' => $id]);
    $pdo->prepare('DELETE FROM support_tickets WHERE id=:id LIMIT 1')->execute([':id' => $id]);
    $pdo->commit();
} catch (Throwable $e) {
    if ($pdo->inTransaction()) $pdo->rollBack();
    error_log('[LOVEMI SUPPORT DELETE] ' . $e->getMessage());
    sc_response(false, 'The solved ticket could not be deleted.', ['code' => 'DELETE_FAILED'], 500);
}

sc_response(true, 'Solved support ticket deleted successfully.', ['ticket_id' => $id]);
