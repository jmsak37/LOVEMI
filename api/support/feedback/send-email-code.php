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

if ($token === '') {
    fb_out(false, 'Secure ticket code is required.', ['code' => 'TOKEN_REQUIRED'], 401);
}

$ticket = fb_access($pdo, $token);
if (!$ticket) {
    fb_out(false, 'This support link is invalid or has expired.', ['code' => 'INVALID_TICKET_LINK'], 404);
}

/* Direct/guest support links never require email verification. */
if ((string)$ticket['access_type'] !== 'account') {
    fb_out(true, 'This support link does not require email verification.', [
        'verification_required' => 'guest',
        'access_granted' => true,
        'expires_in' => 0
    ]);
}

$u = fb_session_user($pdo);
if (!$u || ((int)$u['user_id'] !== (int)$ticket['user_id'])) {
    fb_out(false, 'Please sign in to the LOVEMI account that owns this support ticket before requesting its verification code.', [
        'code' => 'LOGIN_REQUIRED'
    ], 401);
}

$email = trim((string)($u['email'] ?? ''));
$name = trim((string)($u['full_names'] ?? $u['username'] ?? 'LOVEMI Member'));

if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
    fb_out(false, 'The account does not have a valid email address.', ['code' => 'INVALID_ACCOUNT_EMAIL'], 422);
}

/*
 * Verification codes are valid for exactly 2 minutes.
 * Keep a short resend throttle so repeated clicks cannot flood the inbox.
 */
$lastSent = !empty($ticket['email_code_sent_at']) ? strtotime((string)$ticket['email_code_sent_at']) : 0;
if ($lastSent && (time() - $lastSent) < 60 && !empty($ticket['email_code_hash']) && !empty($ticket['email_code_expires_at']) && strtotime((string)$ticket['email_code_expires_at']) > time()) {
    $remaining = max(1, 60 - (time() - $lastSent));
    fb_out(true, 'A verification code was already sent recently. Check your inbox or spam folder.', [
        'cooldown' => $remaining,
        'expires_in' => max(1, strtotime((string)$ticket['email_code_expires_at']) - time()),
        'already_sent' => true
    ]);
}

$code = (string)random_int(100000, 999999);
$ticketNo = 'LM-TKT-' . str_pad((string)$ticket['ticket_id'], 6, '0', STR_PAD_LEFT);
$safeName = fb_esc($name);
$safeTicket = fb_esc($ticketNo);
$safeCode = fb_esc($code);
$logoUrl = fb_esc(fb_app() . '/assets/logo1/logo1.png');
$expiresAtIso = date('c', time() + 120);

$html = '<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f4f3f8;font-family:Arial,Helvetica,sans-serif;color:#18151d;">
<div style="padding:32px 14px;">
  <div style="max-width:650px;margin:0 auto;background:#fff;border:1px solid #e8e3ef;border-radius:22px;overflow:hidden;box-shadow:0 18px 55px rgba(52,29,85,.10);">
    <div style="padding:25px 22px 20px;text-align:center;background:linear-gradient(135deg,#fbf8ff,#fff6fb);border-bottom:1px solid #eee7f5;">
      <img src="' . $logoUrl . '" alt="LOVEMI" style="width:68px;height:68px;object-fit:contain;border-radius:16px;margin:0 auto 10px;display:block;">
      <div style="font-family:Georgia,serif;font-size:30px;font-weight:800;color:#6d28d9;">LOVEMI</div>
      <div style="margin-top:4px;font-size:10px;letter-spacing:2px;color:#918b97;">DISCOVER • CONNECT • MEET</div>
    </div>
    <div style="padding:28px;">
      <div style="font-size:12px;font-weight:800;letter-spacing:1px;text-transform:uppercase;color:#6d28d9;">Support verification</div>
      <h1 style="margin:8px 0 0;font-family:Georgia,serif;font-size:26px;line-height:1.25;color:#18151d;">Your verification code</h1>
      <p style="margin:16px 0 0;font-size:15px;line-height:1.7;color:#554f5b;">Hello ' . $safeName . ',</p>
      <p style="margin:9px 0 0;font-size:14px;line-height:1.7;color:#625c68;">Use the code below to open your secure LOVEMI support conversation.</p>
      <div style="margin:23px 0;padding:20px 16px;border-radius:16px;background:#f1e8ff;border:1px solid #e6daf7;text-align:center;">
        <div style="font-size:12px;font-weight:700;color:#7b7088;">Ticket ' . $safeTicket . '</div>
        <div style="margin-top:9px;font-size:34px;line-height:1;font-weight:900;letter-spacing:10px;color:#6d28d9;">' . $safeCode . '</div>
      </div>
      <div style="padding:13px 14px;border-radius:12px;background:#fff7e8;border:1px solid #fde3a7;color:#8a5a00;font-size:13px;line-height:1.6;">This code expires in <strong>2 minutes</strong>. Only the newest code is valid.</div>
      <p style="margin:18px 0 0;font-size:12px;line-height:1.7;color:#8a8490;">If you did not request this code, you can safely ignore this email and keep your support link private.</p>
    </div>
    <div style="padding:17px 24px;background:#17131d;color:#b8b0bf;text-align:center;font-size:10px;">LOVEMI • Discover • Connect • Meet</div>
  </div>
</div>
</body></html>';

$text = "LOVEMI Support Verification\n\nHello {$name},\n\nYour verification code is {$code}.\nTicket: {$ticketNo}\nThis code expires in 2 minutes.\n\nKeep your secure support link private.";

/* Send first. Do not activate the code in the database unless delivery succeeds. */
try {
    $sent = fb_mail($email, $name, 'LOVEMI Support Verification Code - ' . $ticketNo, $html, $text);
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT VERIFICATION SEND] ' . $e->getMessage());
    $sent = false;
}

if (!$sent) {
    fb_out(false, 'LOVEMI could not send the verification email. Please check the account email address, SMTP configuration, and the server mail log, then try again.', [
        'code' => 'EMAIL_SEND_FAILED',
        'email_mask' => preg_replace('/(^.).*(@.*$)/', '$1***$2', $email)
    ], 503);
}

try {
    $stmt = $pdo->prepare("UPDATE support_ticket_access
        SET email_code_hash = :hash,
            email_code_expires_at = DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 2 MINUTE),
            email_code_attempts = 0,
            email_code_sent_at = CURRENT_TIMESTAMP,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = :id
        LIMIT 1");
    $stmt->execute([
        ':hash' => hash('sha256', $code),
        ':id' => (int)$ticket['access_id']
    ]);
} catch (Throwable $e) {
    error_log('[LOVEMI SUPPORT VERIFICATION SAVE] ' . $e->getMessage());
    /* The email was already sent. Tell the client to request a fresh code. */
    fb_out(false, 'The verification email was sent, but LOVEMI could not activate the code. Please request a new code.', [
        'code' => 'CODE_SAVE_FAILED'
    ], 500);
}

fb_out(true, 'A 6-digit verification code has been sent to your account email. It expires in 2 minutes.', [
    'expires_in' => 120,
    'cooldown' => 60,
    'expires_at' => $expiresAtIso,
    'email_mask' => preg_replace('/(^.).*(@.*$)/', '$1***$2', $email)
]);
