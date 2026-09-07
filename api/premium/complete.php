<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/email-service.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

function paymentCallbackResponse(bool $success, string $message, array $data = [], int $status = 200): never
{
    http_response_code($status);
    echo json_encode(
        array_merge(['success' => $success, 'message' => $message], $data),
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );
    exit;
}

function lovemiAppUrl(): string
{
    $configured = trim((string) (getenv('LOVEMI_APP_URL') ?: ''));
    if ($configured !== '') {
        return rtrim($configured, '/');
    }

    $https = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
    $script = (string) ($_SERVER['SCRIPT_NAME'] ?? '/LOVEMI/api/payments/callback.php');
    $root = rtrim(dirname(dirname(dirname($script))), '/');

    return ($https ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost') . $root;
}

function safeReturnPath(string $path): string
{
    $path = trim($path);
    if (
        $path === '' ||
        preg_match('#^https?://#i', $path) ||
        str_starts_with($path, '//')
    ) {
        return 'dashboard.html';
    }

    return ltrim($path, '/');
}

function paymentPageForMethod(string $method, string $code, string $returnPath): string
{
    $pages = [
        'mpesa'  => 'mpesa-pay.html',
        'paypal' => 'paypal-pay.html',
        'card'   => 'card-pay.html',
    ];

    $page = $pages[strtolower($method)] ?? 'dashboard.html';
    if ($page === 'dashboard.html') {
        return $page;
    }

    return $page
        . '?code=' . rawurlencode($code)
        . '&return=' . rawurlencode($returnPath);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    paymentCallbackResponse(false, 'Only POST requests are allowed.', ['code' => 'METHOD_NOT_ALLOWED'], 405);
}

$webhookSecret = trim((string) (getenv('LOVEMI_PAYMENT_WEBHOOK_SECRET') ?: ''));
$providedSecret = trim((string) ($_SERVER['HTTP_X_LOVEMI_PAYMENT_SECRET'] ?? ''));

if (
    $webhookSecret === '' ||
    $providedSecret === '' ||
    !hash_equals($webhookSecret, $providedSecret)
) {
    paymentCallbackResponse(false, 'Payment callback authorization failed.', ['code' => 'CALLBACK_UNAUTHORIZED'], 401);
}

$input = json_decode(file_get_contents('php://input') ?: '{}', true);
if (!is_array($input)) {
    $input = [];
}

$paymentId = (int) ($input['payment_id'] ?? 0);
$status = strtolower(trim((string) ($input['status'] ?? '')));
$transactionId = trim((string) ($input['gateway_transaction_id'] ?? ''));
$amountPaid = (float) ($input['amount_paid'] ?? 0);
$currency = strtoupper(trim((string) ($input['currency'] ?? '')));

if (
    $paymentId <= 0 ||
    !in_array($status, ['paid', 'failed', 'cancelled'], true)
) {
    paymentCallbackResponse(false, 'Invalid payment callback data.', ['code' => 'INVALID_CALLBACK'], 422);
}

try {
    $pdo = db();
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $pdo->beginTransaction();

    $stmt = $pdo->prepare(
        "SELECT
            p.*,
            s.id AS subscription_id,
            s.status AS subscription_status,
            sv.name AS service_name,
            sv.duration_days,
            u.full_names,
            u.email,
            cu.code AS currency_code,
            cu.symbol AS currency_symbol,
            rr.return_path
         FROM payments p
         INNER JOIN subscriptions s ON s.payment_id = p.id
         INNER JOIN services sv ON sv.id = p.service_id
         INNER JOIN users u ON u.id = p.user_id
         LEFT JOIN currencies cu ON cu.id = p.currency_id
         LEFT JOIN payment_return_routes rr ON rr.payment_id = p.id
         WHERE p.id = :payment_id
         LIMIT 1
         FOR UPDATE"
    );
    $stmt->execute([':payment_id' => $paymentId]);
    $payment = $stmt->fetch();

    if (!$payment) {
        $pdo->rollBack();
        paymentCallbackResponse(false, 'Payment was not found.', ['code' => 'PAYMENT_NOT_FOUND'], 404);
    }

    $returnPath = safeReturnPath((string) ($payment['return_path'] ?? 'dashboard.html'));
    $expected = (float) $payment['amount_expected'];

    /* ---------------------------------------------------------
       SUCCESS VALIDATION
    --------------------------------------------------------- */
    if ($status === 'paid') {
        if (
            $currency !== '' &&
            $currency !== strtoupper((string) $payment['currency_code'])
        ) {
            $pdo->rollBack();
            paymentCallbackResponse(false, 'Payment currency does not match the order.', ['code' => 'CURRENCY_MISMATCH'], 422);
        }

        if ($amountPaid <= 0) {
            $amountPaid = $expected;
        }

        if ($amountPaid + 0.00001 < $expected) {
            $status = 'failed';
        } else {
            /* A payment may have been started while another payment
               was completing. Enforce the maximum of two active Premiums
               again at the final server-side activation point. */
            $limitStmt = $pdo->prepare(
                "SELECT COUNT(*)
                 FROM subscriptions
                 WHERE user_id = :user_id
                   AND status = 'active'
                   AND start_at <= CURRENT_TIMESTAMP
                   AND end_at > CURRENT_TIMESTAMP
                   AND id <> :subscription_id"
            );
            $limitStmt->execute([
                ':user_id' => (int) $payment['user_id'],
                ':subscription_id' => (int) $payment['subscription_id'],
            ]);

            if ((int) $limitStmt->fetchColumn() >= 2) {
                $status = 'failed';
            } else {
                if ((string) $payment['status'] !== 'paid') {
                    $updatePayment = $pdo->prepare(
                        "UPDATE payments
                         SET status = 'paid',
                             gateway_transaction_id = :transaction_id,
                             amount_paid = :amount_paid,
                             paid_at = COALESCE(paid_at, CURRENT_TIMESTAMP),
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = :payment_id
                         LIMIT 1"
                    );
                    $updatePayment->execute([
                        ':transaction_id' => $transactionId !== '' ? $transactionId : null,
                        ':amount_paid' => $amountPaid,
                        ':payment_id' => $paymentId,
                    ]);

                    $updateSubscription = $pdo->prepare(
                        "UPDATE subscriptions
                         SET status = 'active',
                             start_at = COALESCE(start_at, CURRENT_TIMESTAMP),
                             end_at = DATE_ADD(
                                 COALESCE(start_at, CURRENT_TIMESTAMP),
                                 INTERVAL :duration_days DAY
                             ),
                             amount_paid = :amount_paid,
                             updated_at = CURRENT_TIMESTAMP
                         WHERE id = :subscription_id
                         LIMIT 1"
                    );
                    $updateSubscription->execute([
                        ':duration_days' => max(1, (int) $payment['duration_days']),
                        ':amount_paid' => $amountPaid,
                        ':subscription_id' => (int) $payment['subscription_id'],
                    ]);
                }

                /* -------------------------------------------------
                   RECEIPT
                ------------------------------------------------- */
                $pdo->exec(
                    "CREATE TABLE IF NOT EXISTS payment_receipt_access (
                        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                        payment_id BIGINT UNSIGNED NOT NULL,
                        token_hash CHAR(64) NOT NULL,
                        expires_at DATETIME NOT NULL,
                        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (id),
                        UNIQUE KEY uq_receipt_access_hash (token_hash),
                        UNIQUE KEY uq_receipt_access_payment (payment_id),
                        KEY idx_receipt_access_expiry (expires_at)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
                );

                $receiptLookup = $pdo->prepare(
                    'SELECT receipt_number FROM payment_receipts WHERE payment_id = :payment_id LIMIT 1'
                );
                $receiptLookup->execute([':payment_id' => $paymentId]);
                $receiptRow = $receiptLookup->fetch();

                $receiptNumber = $receiptRow['receipt_number']
                    ?? ('RCPT-' . date('YmdHis') . '-' . strtoupper(bin2hex(random_bytes(5))));

                $receiptInsert = $pdo->prepare(
                    "INSERT INTO payment_receipts
                        (payment_id, receipt_number, receipt_path, issued_at)
                     VALUES
                        (:payment_id, :receipt_number, NULL, CURRENT_TIMESTAMP)
                     ON DUPLICATE KEY UPDATE receipt_number = VALUES(receipt_number)"
                );
                $receiptInsert->execute([
                    ':payment_id' => $paymentId,
                    ':receipt_number' => $receiptNumber,
                ]);

                $receiptCode = bin2hex(random_bytes(32));

                $receiptToken = $pdo->prepare(
                    "INSERT INTO payment_receipt_access
                        (payment_id, token_hash, expires_at)
                     VALUES
                        (:payment_id, :token_hash, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 90 DAY))
                     ON DUPLICATE KEY UPDATE
                        token_hash = VALUES(token_hash),
                        expires_at = VALUES(expires_at)"
                );
                $receiptToken->execute([
                    ':payment_id' => $paymentId,
                    ':token_hash' => hash('sha256', $receiptCode),
                ]);

                $pdo->commit();

                $baseUrl = lovemiAppUrl();
                $receiptUrl = $baseUrl . '/receipt.html?code=' . rawurlencode($receiptCode);
                $logoPath = realpath(__DIR__ . '/../../assets/logo1/logo1.png');
                $amountDisplay = (string) ($payment['currency_symbol'] ?? '') . ' ' . number_format($amountPaid, 2);

                $html = '
                <div style="margin:0;background:#f7f7fb;padding:36px;font-family:Arial,sans-serif;">
                    <div style="max-width:650px;margin:auto;background:#fff;border:1px solid #ece8f4;border-radius:24px;padding:34px;">
                        <div style="text-align:center;">
                            <img src="cid:lovemi_logo" alt="LOVEMI" style="width:86px;height:86px;object-fit:contain;">
                            <h1 style="margin:14px 0 4px;color:#6d28d9;">Payment Successful</h1>
                            <p style="margin:0;color:#777;">Your LOVEMI Premium service is active.</p>
                        </div>
                        <p style="color:#333;">Hello <strong>' . htmlspecialchars((string) $payment['full_names'], ENT_QUOTES, 'UTF-8') . '</strong>,</p>
                        <p style="color:#555;line-height:1.7;">We successfully received your payment for <strong>' . htmlspecialchars((string) $payment['service_name'], ENT_QUOTES, 'UTF-8') . '</strong>.</p>
                        <table style="width:100%;border-collapse:collapse;">
                            <tr><td style="padding:10px 0;color:#777;">Service</td><td style="padding:10px 0;text-align:right;"><strong>' . htmlspecialchars((string) $payment['service_name'], ENT_QUOTES, 'UTF-8') . '</strong></td></tr>
                            <tr><td style="padding:10px 0;color:#777;">Payment reference</td><td style="padding:10px 0;text-align:right;"><strong>' . htmlspecialchars((string) $payment['payment_reference'], ENT_QUOTES, 'UTF-8') . '</strong></td></tr>
                            <tr><td style="padding:10px 0;color:#777;">Amount paid</td><td style="padding:10px 0;text-align:right;"><strong>' . htmlspecialchars($amountDisplay, ENT_QUOTES, 'UTF-8') . '</strong></td></tr>
                            <tr><td style="padding:10px 0;color:#777;">Receipt number</td><td style="padding:10px 0;text-align:right;"><strong>' . htmlspecialchars($receiptNumber, ENT_QUOTES, 'UTF-8') . '</strong></td></tr>
                        </table>
                        <div style="text-align:center;margin:28px 0;">
                            <a href="' . htmlspecialchars($receiptUrl, ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;padding:14px 22px;border-radius:12px;background:#6d28d9;color:#fff;text-decoration:none;font-weight:800;">View / Download Receipt</a>
                        </div>
                        <p style="color:#777;line-height:1.6;">The receipt page is protected by a unique secure code.</p>
                        <div style="padding-top:18px;border-top:1px solid #eee;color:#888;font-size:12px;">LOVEMI<br>Discover • Connect • Meet</div>
                    </div>
                </div>';

                sendLovemiPaymentEmail(
                    (string) $payment['email'],
                    (string) $payment['full_names'],
                    'LOVEMI Payment Successful',
                    $html,
                    $logoPath
                );

                paymentCallbackResponse(true, 'Payment completed successfully.', [
                    'payment_id' => $paymentId,
                    'status' => 'paid',
                    'service_name' => $payment['service_name'],
                    'receipt_number' => $receiptNumber,
                    'receipt_url' => $receiptUrl,
                    'return_url' => $returnPath,
                ]);
            }
        }
    }

    /* -------------------------------------------------------------
       FAILURE / CANCELLATION / UNDERPAYMENT
    ------------------------------------------------------------- */
    $updatePayment = $pdo->prepare(
        "UPDATE payments
         SET status = :status,
             gateway_transaction_id = :transaction_id,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = :payment_id
         LIMIT 1"
    );
    $updatePayment->execute([
        ':status' => $status,
        ':transaction_id' => $transactionId !== '' ? $transactionId : null,
        ':payment_id' => $paymentId,
    ]);

    /* Keep the order pending so it can be retried securely. */
    $updateSubscription = $pdo->prepare(
        "UPDATE subscriptions
         SET status = 'pending', updated_at = CURRENT_TIMESTAMP
         WHERE id = :subscription_id
           AND status IN ('pending','cancelled')
         LIMIT 1"
    );
    $updateSubscription->execute([':subscription_id' => (int) $payment['subscription_id']]);

    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS payment_access_tokens (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            payment_id BIGINT UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_payment_access_token_hash (token_hash),
            UNIQUE KEY uq_payment_access_payment (payment_id),
            KEY idx_payment_access_expiry (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
    );

    $newPaymentCode = bin2hex(random_bytes(32));
    $rotateAccess = $pdo->prepare(
        "INSERT INTO payment_access_tokens
            (payment_id, token_hash, expires_at)
         VALUES
            (:payment_id, :token_hash, DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 30 DAY))
         ON DUPLICATE KEY UPDATE
            token_hash = VALUES(token_hash),
            expires_at = VALUES(expires_at)"
    );
    $rotateAccess->execute([
        ':payment_id' => $paymentId,
        ':token_hash' => hash('sha256', $newPaymentCode),
    ]);

    $pdo->commit();

    $baseUrl = lovemiAppUrl();
    $resumeUrl = $baseUrl . '/' . paymentPageForMethod(
        (string) $payment['payment_method'],
        $newPaymentCode,
        $returnPath
    );
    $logoPath = realpath(__DIR__ . '/../../assets/logo1/logo1.png');

    $html = '
    <div style="margin:0;background:#f7f7fb;padding:36px;font-family:Arial,sans-serif;">
        <div style="max-width:650px;margin:auto;background:#fff;border:1px solid #fecaca;border-radius:24px;padding:34px;">
            <div style="text-align:center;">
                <img src="cid:lovemi_logo" alt="LOVEMI" style="width:86px;height:86px;object-fit:contain;">
                <h1 style="margin:14px 0 4px;color:#b91c1c;">Payment Not Completed</h1>
                <p style="margin:0;color:#777;">Your Premium service has not been activated.</p>
            </div>
            <p style="color:#333;">Hello <strong>' . htmlspecialchars((string) $payment['full_names'], ENT_QUOTES, 'UTF-8') . '</strong>,</p>
            <p style="color:#555;line-height:1.7;">The payment for <strong>' . htmlspecialchars((string) $payment['service_name'], ENT_QUOTES, 'UTF-8') . '</strong> was not completed successfully.</p>
            <div style="text-align:center;margin:28px 0;">
                <a href="' . htmlspecialchars($resumeUrl, ENT_QUOTES, 'UTF-8') . '" style="display:inline-block;padding:14px 22px;border-radius:12px;background:#6d28d9;color:#fff;text-decoration:none;font-weight:800;">Complete Payment</a>
            </div>
            <p style="color:#777;font-size:12px;">This continuation link contains a unique secure code and is valid for 30 days.</p>
            <div style="padding-top:18px;border-top:1px solid #eee;color:#888;font-size:12px;">LOVEMI<br>Discover • Connect • Meet</div>
        </div>
    </div>';

    sendLovemiPaymentEmail(
        (string) $payment['email'],
        (string) $payment['full_names'],
        'LOVEMI Payment Not Completed',
        $html,
        $logoPath
    );

    paymentCallbackResponse(true, 'Payment was recorded as ' . $status . '.', [
        'payment_id' => $paymentId,
        'status' => $status,
        'service_name' => $payment['service_name'],
        'resume_url' => $resumeUrl,
        'return_url' => $returnPath,
    ]);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log('[LOVEMI PAYMENT CALLBACK] ' . $e->getMessage());
    paymentCallbackResponse(false, 'Unable to finalize the payment result.', ['code' => 'PAYMENT_FINALIZE_FAILED'], 500);
}
