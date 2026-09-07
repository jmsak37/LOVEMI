<?php
declare(strict_types=1);

/*
 * ============================================================
 * LOVEMI - CREATE SUPPORT TICKET
 * ============================================================
 *
 * Central email delivery is handled by:
 *   /services/email/email-service.php
 *
 * That service reads the shared local mail configuration from:
 *   /services/email/mail.local.php
 *
 * This endpoint does NOT contain or override SMTP credentials.
 * ============================================================
 */

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');
header('X-Content-Type-Options: nosniff');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

const LOVEMI_SUPPORT_EMAIL = 'eduassistasc@gmail.com';
const LOVEMI_SUPPORT_NAME  = 'LOVEMI Support';

function ticketResponse(bool $success, string $message, array $data = [], int $status = 200): never
{
    http_response_code($status);
    echo json_encode(
        array_merge(['success' => $success, 'message' => $message], $data),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

function requestInput(): array
{
    $raw = file_get_contents('php://input');
    $json = json_decode((string)$raw, true);
    return is_array($json) ? $json : $_POST;
}

function cleanText(mixed $value, int $maxLength): string
{
    $text = trim((string)$value);
    if (function_exists('mb_substr')) {
        return mb_substr($text, 0, $maxLength, 'UTF-8');
    }
    return substr($text, 0, $maxLength);
}

function headerInjection(string $value): bool
{
    return preg_match('/[\r\n]/', $value) === 1;
}

function currentUserId(): ?int
{
    foreach (['lovemi_user_id', 'user_id', 'userId', 'userid'] as $key) {
        if (isset($_SESSION[$key]) && is_numeric($_SESSION[$key])) {
            $id = (int)$_SESSION[$key];
            if ($id > 0) return $id;
        }
    }
    return null;
}

function htmlText(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    ticketResponse(false, 'Only POST requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$input = requestInput();
$name = cleanText($input['name'] ?? '', 120);
$email = cleanText($input['email'] ?? '', 190);
$category = strtolower(cleanText($input['category'] ?? 'other', 40));
$subject = cleanText($input['subject'] ?? '', 180);
$message = cleanText($input['message'] ?? '', 5000);

if ($name === '') ticketResponse(false, 'Your name is required.', ['code' => 'NAME_REQUIRED'], 422);
if ($email === '') ticketResponse(false, 'Your email address is required.', ['code' => 'EMAIL_REQUIRED'], 422);
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || headerInjection($email)) ticketResponse(false, 'Please provide a valid email address.', ['code' => 'INVALID_EMAIL'], 422);
if ($subject === '') ticketResponse(false, 'Subject is required.', ['code' => 'SUBJECT_REQUIRED'], 422);
if (headerInjection($subject)) ticketResponse(false, 'Invalid subject.', ['code' => 'INVALID_SUBJECT'], 422);
if ($message === '') ticketResponse(false, 'Please enter your message.', ['code' => 'MESSAGE_REQUIRED'], 422);

$allowedCategories = ['account','login','premium','profile','connection','report','technical','contact','other'];
if (!in_array($category, $allowedCategories, true)) $category = 'other';

try {
    $pdo = db();
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT DATABASE] ' . $e->getMessage());
    ticketResponse(false, 'Database connection failed.', ['code' => 'DATABASE_ERROR'], 500);
}

$userId = currentUserId();
$currentUser = null;

if ($userId !== null) {
    try {
        $stmt = $pdo->prepare('SELECT id, username, full_names, email FROM users WHERE id = :id LIMIT 1');
        $stmt->execute([':id' => $userId]);
        $currentUser = $stmt->fetch(PDO::FETCH_ASSOC) ?: null;
    } catch (Throwable $e) {
        error_log('[LOVEMI SUPPORT USER LOOKUP] ' . $e->getMessage());
    }
}

/* Create the support table when it is not present yet. */
try {
    $pdo->exec("CREATE TABLE IF NOT EXISTS support_tickets (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        user_id BIGINT UNSIGNED NULL,
        name VARCHAR(120) NOT NULL,
        email VARCHAR(190) NOT NULL,
        category VARCHAR(40) NOT NULL DEFAULT 'other',
        subject VARCHAR(180) NOT NULL,
        message TEXT NOT NULL,
        status VARCHAR(30) NOT NULL DEFAULT 'open',
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_support_user_id (user_id),
        KEY idx_support_email (email),
        KEY idx_support_status (status),
        KEY idx_support_created_at (created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT TABLE] ' . $e->getMessage());
    ticketResponse(false, 'The support system could not be initialized.', ['code' => 'SUPPORT_TABLE_ERROR'], 500);
}

/* Prevent accidental double-submission within five minutes. */
try {
    $stmt = $pdo->prepare('SELECT id FROM support_tickets WHERE email = :email AND subject = :subject AND message = :message AND created_at >= DATE_SUB(CURRENT_TIMESTAMP, INTERVAL 5 MINUTE) ORDER BY id DESC LIMIT 1');
    $stmt->execute([':email' => $email, ':subject' => $subject, ':message' => $message]);
    $duplicateId = $stmt->fetchColumn();
} catch (Throwable $e) {
    $duplicateId = null;
}

if ($duplicateId) {
    ticketResponse(true, 'This support request was already submitted recently.', [
        'ticket_id' => (int)$duplicateId,
        'duplicate' => true,
        'email_sent' => true,
    ], 200);
}

try {
    $stmt = $pdo->prepare('INSERT INTO support_tickets (user_id, name, email, category, subject, message, status) VALUES (:user_id, :name, :email, :category, :subject, :message, :status)');
    $stmt->execute([
        ':user_id' => $userId,
        ':name' => $name,
        ':email' => $email,
        ':category' => $category,
        ':subject' => $subject,
        ':message' => $message,
        ':status' => 'open',
    ]);
    $ticketId = (int)$pdo->lastInsertId();
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT INSERT] ' . $e->getMessage());
    ticketResponse(false, 'The support ticket could not be saved.', ['code' => 'TICKET_SAVE_FAILED'], 500);
}

$ticketNumber = 'LM-TKT-' . str_pad((string)$ticketId, 6, '0', STR_PAD_LEFT);

$safeName = htmlText($name);
$safeEmail = htmlText($email);
$safeCategory = htmlText(ucfirst($category));
$safeSubject = htmlText($subject);
$safeMessage = nl2br(htmlText($message));
$ip = htmlText((string)($_SERVER['REMOTE_ADDR'] ?? 'Unknown'));
$userAgent = htmlText((string)($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown'));

$adminHtml = <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>LOVEMI Support Ticket</title></head>
<body style="margin:0;background:#f7f7fb;font-family:Arial,sans-serif;color:#202638;padding:28px;">
<div style="max-width:700px;margin:auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 35px rgba(0,0,0,.08);">
  <div style="padding:24px;background:linear-gradient(135deg,#6d28d9,#db2777);color:#fff;">
    <div style="font-size:12px;opacity:.86;">LOVEMI SUPPORT</div>
    <h2 style="margin:6px 0 0;">New Support Ticket</h2>
    <div style="margin-top:6px;font-size:13px;">{$ticketNumber}</div>
  </div>
  <div style="padding:28px;">
    <div style="padding:10px 0;border-bottom:1px solid #eee;"><strong>Name</strong><div style="margin-top:4px;">{$safeName}</div></div>
    <div style="padding:10px 0;border-bottom:1px solid #eee;"><strong>Email</strong><div style="margin-top:4px;">{$safeEmail}</div></div>
    <div style="padding:10px 0;border-bottom:1px solid #eee;"><strong>Category</strong><div style="margin-top:4px;">{$safeCategory}</div></div>
    <div style="padding:10px 0;border-bottom:1px solid #eee;"><strong>Subject</strong><div style="margin-top:4px;">{$safeSubject}</div></div>
    <div style="margin-top:20px;padding:18px;background:#faf9fc;border-radius:12px;"><strong>Message</strong><div style="margin-top:10px;line-height:1.65;">{$safeMessage}</div></div>
    <div style="margin-top:18px;font-size:12px;color:#737987;">Ticket ID: {$ticketId}</div>
    <div style="margin-top:5px;font-size:12px;color:#737987;">IP: {$ip}</div>
    <div style="margin-top:5px;font-size:12px;color:#737987;word-break:break-word;">Browser: {$userAgent}</div>
  </div>
  <div style="padding:16px 28px;background:#fafafd;color:#747c8b;font-size:12px;">LOVEMI Support System</div>
</div>
</body>
</html>
HTML;

$adminText = "LOVEMI SUPPORT TICKET\n\nTicket: {$ticketNumber}\nTicket ID: {$ticketId}\nName: {$name}\nEmail: {$email}\nCategory: {$category}\nSubject: {$subject}\n\nMessage:\n{$message}\n\nIP: " . ($_SERVER['REMOTE_ADDR'] ?? 'Unknown');

/*
 * IMPORTANT:
 * This is the only mail call made by the support endpoint.
 * sendLovemiEmail() is the shared service used by the rest of LOVEMI.
 * Its SMTP configuration comes from services/email/mail.local.php.
 */
$adminMailSent = false;
try {
    $adminMailSent = sendLovemiEmail(
        LOVEMI_SUPPORT_EMAIL,
        LOVEMI_SUPPORT_NAME,
        '[LOVEMI SUPPORT] ' . $ticketNumber . ' - ' . $subject,
        $adminHtml,
        $adminText
    );
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT MAIL] ' . $e->getMessage());
    $adminMailSent = false;
}

/* Send an optional confirmation to the requester using the same central service. */
$confirmationSent = false;
if ($adminMailSent) {
    $confirmationHtml = <<<HTML
<!DOCTYPE html>
<html lang="en"><body style="margin:0;background:#f7f7fb;font-family:Arial,sans-serif;padding:28px;">
<div style="max-width:620px;margin:auto;background:#fff;border-radius:18px;overflow:hidden;box-shadow:0 12px 35px rgba(0,0,0,.08);">
  <div style="padding:24px;background:linear-gradient(135deg,#6d28d9,#db2777);color:#fff;"><h2 style="margin:0;">LOVEMI Support</h2></div>
  <div style="padding:28px;"><p>Hello {$safeName},</p><p>We have received your LOVEMI support request.</p><div style="padding:16px;background:#faf9fc;border-radius:12px;"><strong>Ticket number</strong><div style="margin-top:7px;font-size:20px;color:#6d28d9;font-weight:800;">{$ticketNumber}</div><div style="margin-top:10px;"><strong>Subject:</strong> {$safeSubject}</div></div><p style="margin-bottom:0;">Please keep this ticket number for future reference.</p></div>
  <div style="padding:16px 28px;background:#fafafd;color:#747c8b;font-size:12px;">LOVEMI Support • eduassistasc@gmail.com</div>
</div></body></html>
HTML;
    $confirmationText = "Hello {$name},\n\nYour LOVEMI support ticket has been received.\n\nTicket: {$ticketNumber}\nSubject: {$subject}\n\nPlease keep this ticket number for reference.\n\nLOVEMI Support\neduassistasc@gmail.com";
    try {
        $confirmationSent = sendLovemiEmail(
            $email,
            $name,
            'LOVEMI Support Ticket Received - ' . $ticketNumber,
            $confirmationHtml,
            $confirmationText
        );
    } catch (Throwable $e) {
        error_log('[LOVEMI SUPPORT CONFIRMATION] ' . $e->getMessage());
    }
}

if ($adminMailSent) {
    try {
        $stmt = $pdo->prepare("UPDATE support_tickets SET status = 'received', updated_at = CURRENT_TIMESTAMP WHERE id = :id LIMIT 1");
        $stmt->execute([':id' => $ticketId]);
    } catch (Throwable $e) {
        error_log('[LOVEMI SUPPORT STATUS] ' . $e->getMessage());
    }
    ticketResponse(true, 'Your support ticket has been sent successfully.', [
        'ticket_id' => $ticketId,
        'ticket_number' => $ticketNumber,
        'email_sent' => true,
        'confirmation_sent' => $confirmationSent,
        'status' => 'received',
    ], 201);
}

/* The DB record is kept, but the response tells the visitor that delivery failed. */
ticketResponse(false, 'Your support ticket was saved, but the support email could not be delivered. Please try again later.', [
    'ticket_id' => $ticketId,
    'ticket_number' => $ticketNumber,
    'saved' => true,
    'email_sent' => false,
    'status' => 'open',
], 503);
