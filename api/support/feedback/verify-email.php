<?php
declare(strict_types=1);

require_once __DIR__ . '/common.php';

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    fb_out(false, 'Only POST requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$pdo = fb_pdo();
fb_schema($pdo);
$in = fb_in();
$token = trim((string)($in['token'] ?? ''));
$code = preg_replace('/\D/', '', (string)($in['code'] ?? ''));

if ($token === '' || strlen($code) !== 6) {
    fb_out(false, 'Enter the 6-digit verification code.', ['code' => 'INVALID_CODE'], 422);
}

$ticket = fb_access($pdo, $token);
if (!$ticket) {
    fb_out(false, 'This support link is invalid or has expired.', ['code' => 'INVALID_TICKET_LINK'], 404);
}

/* Direct/guest links are already authorized without email verification. */
if ((string)$ticket['access_type'] !== 'account') {
    fb_out(true, 'This support link does not require email verification.', [
        'email_verified' => true,
        'access_granted' => true,
        'verification_required' => 'guest'
    ]);
}

$u = fb_session_user($pdo);
if (!$u || ((int)$u['user_id'] !== (int)$ticket['user_id'])) {
    fb_out(false, 'Please sign in with the LOVEMI account that owns this support ticket.', [
        'code' => 'LOGIN_REQUIRED'
    ], 401);
}

$attempts = (int)($ticket['email_code_attempts'] ?? 0);
if ($attempts >= 5) {
    fb_out(false, 'Too many verification attempts. Request a new code.', ['code' => 'CODE_LOCKED'], 429);
}

$hash = trim((string)($ticket['email_code_hash'] ?? ''));
$expires = trim((string)($ticket['email_code_expires_at'] ?? ''));

if ($hash === '' || $expires === '') {
    fb_out(false, 'No active verification code was found. Request a new code.', ['code' => 'CODE_NOT_FOUND'], 422);
}

if (strtotime($expires) <= time()) {
    fb_out(false, 'That verification code has expired after 2 minutes. Request a new one.', ['code' => 'CODE_EXPIRED'], 422);
}

if (!hash_equals($hash, hash('sha256', $code))) {
    $newAttempts = $attempts + 1;
    $stmt = $pdo->prepare('UPDATE support_ticket_access SET email_code_attempts = :attempts, updated_at = CURRENT_TIMESTAMP WHERE id = :id LIMIT 1');
    $stmt->execute([
        ':attempts' => $newAttempts,
        ':id' => (int)$ticket['access_id']
    ]);

    $remaining = max(0, 5 - $newAttempts);
    fb_out(false, $remaining > 0
        ? 'The verification code is incorrect.'
        : 'Too many incorrect verification attempts. Request a new code.', [
            'code' => $remaining > 0 ? 'CODE_INCORRECT' : 'CODE_LOCKED',
            'attempts_remaining' => $remaining
        ], $remaining > 0 ? 422 : 429);
}

/* Successful email verification lasts for the current support session. */
$_SESSION['lovemi_support_email_verified'][(int)$ticket['access_id']] = time() + 1800;

$clear = $pdo->prepare('UPDATE support_ticket_access SET email_code_hash = NULL, email_code_expires_at = NULL, email_code_attempts = 0, email_code_sent_at = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = :id LIMIT 1');
$clear->execute([':id' => (int)$ticket['access_id']]);

fb_out(true, 'Email verification completed. Continue to Google Authenticator verification.', [
    'email_verified' => true,
    'access_id' => (int)$ticket['access_id'],
    'ticket_id' => (int)$ticket['ticket_id']
]);
