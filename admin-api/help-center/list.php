<?php
declare(strict_types=1);
require_once __DIR__ . '/common.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {
    sc_response(false, 'Only GET requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$pdo = sc_pdo();
sc_ensure_schema($pdo);
$admin = sc_admin_auth($pdo);

$q = sc_clean($_GET['q'] ?? '', 180);
$status = strtolower(sc_clean($_GET['status'] ?? 'all', 30));
$source = strtolower(sc_clean($_GET['source'] ?? 'all', 20));

$where = ['1=1'];
$params = [];

if ($q !== '') {
    $where[] = '(t.name LIKE :q OR t.email LIKE :q OR t.subject LIKE :q OR CAST(t.id AS CHAR) LIKE :q)';
    $params[':q'] = '%' . $q . '%';
}

if (in_array($status, ['open', 'received', 'awaiting_admin', 'awaiting_user', 'solved', 'closed'], true)) {
    $where[] = 't.status=:status';
    $params[':status'] = $status;
}

if (in_array($source, ['help', 'contact', 'direct'], true)) {
    $where[] = 't.source=:source';
    $params[':source'] = $source;
}

$sql = "SELECT
    t.id,
    t.user_id,
    t.name,
    t.email,
    t.category,
    t.subject,
    t.status,
    t.source,
    t.created_at,
    t.updated_at,
    t.last_user_reply_at,
    t.last_admin_reply_at,
    t.last_message_at,
    t.close_at,
    t.solved_at,
    t.closed_at,
    (SELECT m.body FROM support_ticket_messages m WHERE m.ticket_id=t.id ORDER BY m.id DESC LIMIT 1) AS last_message,
    (SELECT m.sender_type FROM support_ticket_messages m WHERE m.ticket_id=t.id ORDER BY m.id DESC LIMIT 1) AS last_sender
    FROM support_tickets t
    WHERE " . implode(' AND ', $where) . "
    ORDER BY COALESCE(t.last_message_at,t.updated_at,t.created_at) DESC, t.id DESC
    LIMIT 300";

$stmt = $pdo->prepare($sql);
$stmt->execute($params);
$tickets = $stmt->fetchAll(PDO::FETCH_ASSOC);

foreach ($tickets as &$t) {
    $t['id'] = (int)$t['id'];
    $t['user_id'] = $t['user_id'] !== null ? (int)$t['user_id'] : null;
    $t['needs_admin_reply'] = ((string)$t['status'] === 'awaiting_admin');
    $t['source_label'] = sc_source_label((string)$t['source']);
    $t['status_label'] = sc_status_label((string)$t['status']);
}
unset($t);

$stats = [];
foreach (['all', 'awaiting_admin', 'awaiting_user', 'solved', 'closed'] as $s) {
    if ($s === 'all') {
        $stats[$s] = (int)$pdo->query('SELECT COUNT(*) FROM support_tickets')->fetchColumn();
    } else {
        $st = $pdo->prepare('SELECT COUNT(*) FROM support_tickets WHERE status=:s');
        $st->execute([':s' => $s]);
        $stats[$s] = (int)$st->fetchColumn();
    }
}

$stats['needs_admin'] = $stats['awaiting_admin'];
$latestAdminNotify = (int)$pdo->query("SELECT COALESCE(MAX(id),0) FROM notifications WHERE reference_type='support_ticket'")->fetchColumn();

sc_response(true, 'Support tickets loaded.', [
    'tickets' => $tickets,
    'stats' => $stats,
    'notification_cursor' => $latestAdminNotify,
    'admin_id' => (int)$admin['id'],
]);
