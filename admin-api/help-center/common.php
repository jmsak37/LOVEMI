<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

const LOVEMI_SUPPORT_EMAIL = 'eduassistasc@gmail.com';
const LOVEMI_SUPPORT_NAME  = 'LOVEMI Support';
const LOVEMI_SUPPORT_CLOSE_HOURS = 48;

function sc_response(bool $success, string $message, array $data = [], int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('Expires: 0');
    header('X-Content-Type-Options: nosniff');
    echo json_encode(array_merge([
        'success' => $success,
        'message' => $message,
    ], $data), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function sc_input(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode((string)$raw, true);
    return is_array($data) ? $data : $_POST;
}

function sc_clean(mixed $value, int $max): string
{
    $v = trim((string)$value);
    return function_exists('mb_substr') ? mb_substr($v, 0, $max, 'UTF-8') : substr($v, 0, $max);
}

function sc_html(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function sc_mail(string $email, string $name, string $subject, string $html, ?string $text = null): bool
{
    try {
        return sendLovemiEmail($email, $name, $subject, $html, $text ?? strip_tags($html));
    } catch (Throwable $e) {
        error_log('[LOVEMI SUPPORT MAIL] ' . $e->getMessage());
        return false;
    }
}

function sc_app_url(): string
{
    $configured = getenv('LOVEMI_APP_URL');
    if (is_string($configured) && trim($configured) !== '') {
        return rtrim(trim($configured), '/');
    }
    $https = ((!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off') || (int)($_SERVER['SERVER_PORT'] ?? 80) === 443);
    $scheme = $https ? 'https' : 'http';
    $host = trim((string)($_SERVER['HTTP_HOST'] ?? $_SERVER['SERVER_NAME'] ?? 'localhost')) ?: 'localhost';
    return $scheme . '://' . $host . '/LOVEMI';
}

function sc_feedback_url(string $token): string
{
    return sc_app_url() . '/Support-Ticket-Feedback.html?token=' . rawurlencode($token);
}

function sc_pdo(): PDO
{
    $pdo = db();
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    return $pdo;
}

function sc_column_exists(PDO $pdo, string $table, string $column): bool
{
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = :table_name AND COLUMN_NAME = :column_name');
    $stmt->execute([':table_name' => $table, ':column_name' => $column]);
    return (int)$stmt->fetchColumn() > 0;
}

function sc_add_column(PDO $pdo, string $table, string $column, string $definition): void
{
    if (!sc_column_exists($pdo, $table, $column)) {
        $pdo->exec("ALTER TABLE `{$table}` ADD COLUMN `{$column}` {$definition}");
    }
}

function sc_ensure_schema(PDO $pdo): void
{
    $pdo->exec("CREATE TABLE IF NOT EXISTS support_ticket_messages (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ticket_id BIGINT UNSIGNED NOT NULL,
        sender_type VARCHAR(20) NOT NULL,
        sender_id BIGINT UNSIGNED NULL,
        sender_name VARCHAR(180) NOT NULL,
        sender_email VARCHAR(190) NOT NULL,
        body TEXT NOT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_stm_ticket (ticket_id),
        KEY idx_stm_created (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $pdo->exec("CREATE TABLE IF NOT EXISTS support_ticket_access (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        ticket_id BIGINT UNSIGNED NOT NULL,
        access_type VARCHAR(20) NOT NULL DEFAULT 'guest',
        token_hash CHAR(64) NOT NULL,
        email_code_hash CHAR(64) NULL,
        email_code_expires_at DATETIME NULL,
        email_code_attempts INT UNSIGNED NOT NULL DEFAULT 0,
        email_code_sent_at DATETIME NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        UNIQUE KEY uq_sta_ticket (ticket_id),
        UNIQUE KEY uq_sta_token (token_hash),
        KEY idx_sta_type (access_type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    foreach ([
        ['source', "VARCHAR(20) NOT NULL DEFAULT 'help'"],
        ['last_user_reply_at', 'DATETIME NULL'],
        ['last_admin_reply_at', 'DATETIME NULL'],
        ['last_message_at', 'DATETIME NULL'],
        ['close_at', 'DATETIME NULL'],
        ['solved_at', 'DATETIME NULL'],
        ['closed_at', 'DATETIME NULL'],
        ['reminder_24_sent', 'TINYINT(1) NOT NULL DEFAULT 0'],
        ['reminder_12_sent', 'TINYINT(1) NOT NULL DEFAULT 0'],
        ['reminder_1_sent', 'TINYINT(1) NOT NULL DEFAULT 0'],
        ['admin_last_reminder_at', 'DATETIME NULL'],
    ] as $col) {
        sc_add_column($pdo, 'support_tickets', $col[0], $col[1]);
    }

    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_support_source ON support_tickets(source)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_support_close ON support_tickets(close_at)");
    $pdo->exec("CREATE INDEX IF NOT EXISTS idx_support_last_message ON support_tickets(last_message_at)");
}

function sc_current_user_id(): int
{
    return (int)($_SESSION['lovemi_user_id'] ?? 0);
}

function sc_current_session(PDO $pdo): ?array
{
    $uid = sc_current_user_id();
    $token = trim((string)($_SESSION['lovemi_session_token'] ?? ''));
    if ($uid <= 0 || $token === '') return null;

    $stmt = $pdo->prepare('SELECT id,user_id,two_factor_passed,expires_at,revoked_at FROM user_sessions WHERE user_id=:uid AND session_token_hash=:hash LIMIT 1');
    $stmt->execute([':uid' => $uid, ':hash' => hash('sha256', $token)]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$row) return null;
    if (!empty($row['revoked_at'])) return null;
    if (!empty($row['expires_at']) && strtotime((string)$row['expires_at']) < time()) return null;
    return $row;
}

function sc_admin_auth(PDO $pdo): array
{
    $uid = sc_current_user_id();
    if ($uid <= 0) sc_response(false, 'Administrator authentication is required.', ['code' => 'ADMIN_AUTH_REQUIRED'], 401);
    $session = sc_current_session($pdo);
    if (!$session || (int)$session['two_factor_passed'] !== 1) {
        sc_response(false, 'Your administrator session has not completed two-step verification.', ['code' => 'ADMIN_2FA_REQUIRED'], 403);
    }

    try {
        $stmt = $pdo->prepare('SELECT u.id,u.username,u.full_names,u.email,u.role_id,r.slug AS role_slug,r.name AS role_name,r.is_admin_role FROM users u LEFT JOIN roles r ON r.id=u.role_id WHERE u.id=:uid LIMIT 1');
        $stmt->execute([':uid' => $uid]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
    } catch (Throwable $e) {
        $stmt = $pdo->prepare('SELECT u.id,u.username,u.full_names,u.email,u.role_id FROM users u WHERE u.id=:uid LIMIT 1');
        $stmt->execute([':uid' => $uid]);
        $admin = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($admin) $admin['role_slug'] = (string)($_SESSION['lovemi_role_slug'] ?? '');
        if ($admin) $admin['is_admin_role'] = in_array(strtolower((string)$admin['role_slug']), ['admin','super_admin','administrator'], true) ? 1 : 0;
    }

    if (!$admin || (int)($admin['is_admin_role'] ?? 0) !== 1) {
        sc_response(false, 'Administrator access is required.', ['code' => 'ADMIN_ACCESS_REQUIRED'], 403);
    }
    return $admin;
}

function sc_user_name(PDO $pdo, int $userId, string $fallbackName = 'LOVEMI Member'): string
{
    if ($userId <= 0) return $fallbackName;
    $stmt = $pdo->prepare('SELECT full_names,username FROM users WHERE id=:id LIMIT 1');
    $stmt->execute([':id' => $userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return trim((string)($row['full_names'] ?? $row['username'] ?? $fallbackName)) ?: $fallbackName;
}

function sc_notify_user(PDO $pdo, int $userId, string $title, string $message, int $ticketId, ?int $senderId = null): void
{
    if ($userId <= 0) return;
    try {
        $stmt = $pdo->prepare('INSERT INTO notifications (user_id,notification_type_id,sender_id,title,message,reference_type,reference_id,is_read) VALUES (:uid,NULL,:sid,:title,:message,\'support_ticket\',:rid,0)');
        $stmt->execute([':uid'=>$userId, ':sid'=>$senderId, ':title'=>$title, ':message'=>$message, ':rid'=>$ticketId]);
    } catch (Throwable $e) {
        error_log('[LOVEMI SUPPORT USER NOTIFICATION] '.$e->getMessage());
    }
}

function sc_notify_admins(PDO $pdo, string $title, string $message, int $ticketId): void
{
    try {
        $stmt = $pdo->query("SELECT u.id FROM users u JOIN roles r ON r.id=u.role_id WHERE r.is_admin_role=1 AND u.is_active=1 AND u.is_suspended=0 AND u.is_deleted=0");
        $admins = $stmt ? $stmt->fetchAll(PDO::FETCH_COLUMN) : [];
    } catch (Throwable $e) {
        $admins = [];
    }
    $insert = $pdo->prepare('INSERT INTO notifications (user_id,notification_type_id,sender_id,title,message,reference_type,reference_id,is_read) VALUES (:uid,NULL,NULL,:title,:message,\'support_ticket\',:rid,0)');
    foreach ($admins as $adminId) {
        try { $insert->execute([':uid'=>(int)$adminId, ':title'=>$title, ':message'=>$message, ':rid'=>$ticketId]); } catch (Throwable $e) { error_log('[LOVEMI SUPPORT ADMIN NOTIFICATION] '.$e->getMessage()); }
    }
}

function sc_get_ticket(PDO $pdo, int $ticketId): ?array
{
    $stmt = $pdo->prepare('SELECT * FROM support_tickets WHERE id=:id LIMIT 1');
    $stmt->execute([':id'=>$ticketId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function sc_get_ticket_by_token(PDO $pdo, string $token): ?array
{
    $hash = hash('sha256', $token);
    $stmt = $pdo->prepare('SELECT a.*,t.* FROM support_ticket_access a JOIN support_tickets t ON t.id=a.ticket_id WHERE a.token_hash=:hash LIMIT 1');
    $stmt->execute([':hash'=>$hash]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    return $row ?: null;
}

function sc_messages(PDO $pdo, int $ticketId): array
{
    $stmt = $pdo->prepare('SELECT id,ticket_id,sender_type,sender_id,sender_name,sender_email,body,created_at FROM support_ticket_messages WHERE ticket_id=:id ORDER BY id ASC');
    $stmt->execute([':id'=>$ticketId]);
    return $stmt->fetchAll(PDO::FETCH_ASSOC);
}

function sc_source_label(string $source): string
{
    return match(strtolower($source)) {
        'contact' => 'Contact Center',
        'direct' => 'Direct Email',
        default => 'Help Center',
    };
}

function sc_status_label(string $status): string
{
    return match(strtolower($status)) {
        'awaiting_admin' => 'Awaiting Support',
        'awaiting_user' => 'Awaiting User',
        'solved' => 'Solved',
        'closed' => 'Closed',
        'received' => 'Received',
        default => 'Open',
    };
}
