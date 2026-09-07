<?php
declare(strict_types=1);

/**
 * LOVEMI - Standard Payment Callback
 *
 * This endpoint must only be called by a trusted provider callback
 * after the provider-specific callback has verified authenticity.
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);

    echo json_encode([
        'success' => false,
        'code' => 'METHOD_NOT_ALLOWED',
        'message' => 'Only POST requests are allowed.'
    ]);

    exit;
}

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   RESPONSE
   ============================================================ */

function callbackResponse(
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
        JSON_UNESCAPED_UNICODE
        | JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   ENVIRONMENT
   ============================================================ */

function lovemiEnv(
    string $name,
    ?string $default = null
): ?string {
    $value = getenv($name);

    if ($value === false) {
        return $default;
    }

    $value = trim((string) $value);

    return $value === ''
        ? $default
        : $value;
}


/* ============================================================
   APP URL
   ============================================================ */

function lovemiAppUrl(): string {

    $configured =
        lovemiEnv('LOVEMI_APP_URL');

    if ($configured !== null) {
        return rtrim(
            $configured,
            '/'
        );
    }


    $https =
        !empty($_SERVER['HTTPS'])
        && strtolower(
            (string) $_SERVER['HTTPS']
        ) !== 'off';


    $scheme =
        $https
            ? 'https'
            : 'http';


    $host =
        $_SERVER['HTTP_HOST']
        ?? 'localhost';


    $script =
        str_replace(
            '\\',
            '/',
            (string) (
                $_SERVER['SCRIPT_NAME']
                ?? ''
            )
        );


    $marker =
        '/api/payments/';


    $position =
        strpos(
            $script,
            $marker
        );


    $root =
        $position !== false
            ? substr(
                $script,
                0,
                $position
            )
            : '/LOVEMI';


    return
        $scheme
        . '://'
        . $host
        . rtrim($root, '/');
}


/* ============================================================
   SECURE RETURN PATH
   ============================================================ */

function safeReturnPath(
    ?string $path
): string {

    $fallback =
        'dashboard.html';

    if ($path === null) {
        return $fallback;
    }

    $path =
        trim($path);


    if ($path === '') {
        return $fallback;
    }


    if (
        preg_match(
            '/[\r\n]/',
            $path
        )
        || preg_match(
            '#^[a-z][a-z0-9+\-.]*:#i',
            $path
        )
        || str_starts_with(
            $path,
            '//'
        )
        || str_contains(
            $path,
            '../'
        )
        || str_contains(
            $path,
            '..\\'
        )
    ) {
        return $fallback;
    }


    return ltrim(
        $path,
        '/'
    );
}


/* ============================================================
   PAYMENT PAGE
   ============================================================ */

function paymentPageForMethod(
    string $method
): string {

    switch (
        strtolower(
            trim($method)
        )
    ) {

        case 'mpesa':
            return 'mpesa-pay.html';

        case 'paypal':
            return 'paypal-pay.html';

        case 'card':
            return 'card-pay.html';

        default:
            return 'premium.html';
    }
}


/* ============================================================
   SECURE TOKEN
   ============================================================ */

function secureCode(): string {
    return bin2hex(
        random_bytes(32)
    );
}


/* ============================================================
   PAYMENT ACCESS TOKEN TABLE
   ============================================================ */

function ensurePaymentAccessTable(
    PDO $pdo
): void {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS payment_access_tokens (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            payment_id BIGINT UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            UNIQUE KEY uq_payment_access_payment
                (payment_id),

            UNIQUE KEY uq_payment_access_token
                (token_hash),

            KEY idx_payment_access_expiry
                (expires_at)

        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );
}


/* ============================================================
   CREATE PAYMENT RETRY CODE
   ============================================================ */

function createPaymentRetryCode(
    PDO $pdo,
    int $paymentId
): string {

    ensurePaymentAccessTable(
        $pdo
    );


    $code =
        secureCode();


    $hash =
        hash(
            'sha256',
            $code
        );


    $stmt =
        $pdo->prepare(
            "
            INSERT INTO payment_access_tokens
            (
                payment_id,
                token_hash,
                expires_at
            )
            VALUES
            (
                :payment_id,
                :token_hash,
                DATE_ADD(
                    CURRENT_TIMESTAMP,
                    INTERVAL 30 DAY
                )
            )

            ON DUPLICATE KEY UPDATE
                token_hash =
                    VALUES(token_hash),

                expires_at =
                    VALUES(expires_at)
            "
        );


    $stmt->execute([
        ':payment_id' =>
            $paymentId,

        ':token_hash' =>
            $hash
    ]);


    return $code;
}


/* ============================================================
   CREATE NOTIFICATION
   ============================================================ */

function createPaymentFailureNotification(
    PDO $pdo,
    array $payment,
    string $paymentStatus
): void {

    /*
     * IMPORTANT:
     * notification_types uses "slug", NOT "type".
     */
    $typeStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                name,
                sound_enabled

            FROM notification_types

            WHERE slug = 'payment_failed'

            LIMIT 1
            "
        );


    $typeStmt->execute();


    $notificationType =
        $typeStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (!$notificationType) {
        error_log(
            '[LOVEMI] payment_failed notification type not found.'
        );

        return;
    }


    /*
     * Get the notification sound belonging to notification type 7.
     *
     * The database maps payment_failed to notification7.mp3.
     */
    $audioStmt =
        $pdo->prepare(
            "
            SELECT
                id

            FROM notification_audio

            WHERE notification_type_id = :type_id

              AND is_active = 1

            ORDER BY sort_order ASC, id ASC

            LIMIT 1
            "
        );


    $audioStmt->execute([
        ':type_id' =>
            (int) $notificationType['id']
    ]);


    $audioId =
        $audioStmt->fetchColumn();


    $title =
        $paymentStatus === 'cancelled'
            ? 'Payment Cancelled'
            : 'Payment Failed';


    $message =
        $paymentStatus === 'cancelled'
            ? 'Your payment for '
                . (string) $payment['service_name']
                . ' was cancelled. Your Premium membership was not activated. You can safely continue the payment using the secure payment link sent to your email.'
            : 'Your payment for '
                . (string) $payment['service_name']
                . ' was not completed. Your Premium membership was not activated. A secure payment continuation link has been sent to your email.';


    /*
     * Prevent duplicate notification entries when a provider sends
     * the same callback more than once.
     */
    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM notifications

            WHERE user_id = :user_id

              AND notification_type_id = :type_id

              AND reference_type = 'payment'

              AND reference_id = :payment_id

              AND created_at >= DATE_SUB(
                    CURRENT_TIMESTAMP,
                    INTERVAL 10 MINUTE
                  )

            LIMIT 1
            "
        );


    $duplicateStmt->execute([
        ':user_id' =>
            (int) $payment['user_id'],

        ':type_id' =>
            (int) $notificationType['id'],

        ':payment_id' =>
            (int) $payment['id']
    ]);


    if ($duplicateStmt->fetchColumn()) {
        return;
    }


    /*
     * Insert notification.
     *
     * sender_id is NULL because this notification is generated
     * by LOVEMI automatically.
     */
    $insert =
        $pdo->prepare(
            "
            INSERT INTO notifications
            (
                user_id,
                notification_type_id,
                sender_id,
                title,
                message,
                reference_type,
                reference_id,
                audio_id,
                is_read,
                read_at,
                created_at
            )
            VALUES
            (
                :user_id,
                :notification_type_id,
                NULL,
                :title,
                :message,
                'payment',
                :reference_id,
                :audio_id,
                0,
                NULL,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insert->execute([
        ':user_id' =>
            (int) $payment['user_id'],

        ':notification_type_id' =>
            (int) $notificationType['id'],

        ':title' =>
            $title,

        ':message' =>
            $message,

        ':reference_id' =>
            (int) $payment['id'],

        ':audio_id' =>
            $audioId !== false
                ? (int) $audioId
                : null
    ]);
}


/* ============================================================
   READ REQUEST
   ============================================================ */

$secret =
    lovemiEnv(
        'LOVEMI_PAYMENT_WEBHOOK_SECRET'
    );


if (
    $secret === null
) {
    callbackResponse(
        false,
        'Payment webhook is not configured.',
        [
            'code' =>
                'PAYMENT_WEBHOOK_NOT_CONFIGURED'
        ],
        500
    );
}


$providedSecret =
    trim(
        (string) (
            $_SERVER[
                'HTTP_X_LOVEMI_PAYMENT_SECRET'
            ]
            ?? ''
        )
    );


if (
    $providedSecret === ''
    || !hash_equals(
        $secret,
        $providedSecret
    )
) {

    callbackResponse(
        false,
        'Invalid payment callback authentication.',
        [
            'code' =>
                'INVALID_PAYMENT_WEBHOOK'
        ],
        401
    );
}


$raw =
    file_get_contents(
        'php://input'
    );


if (
    $raw === false
    || trim($raw) === ''
) {

    callbackResponse(
        false,
        'The callback request is empty.',
        [
            'code' =>
                'EMPTY_REQUEST'
        ],
        400
    );
}


try {

    $payload =
        json_decode(
            $raw,
            true,
            512,
            JSON_THROW_ON_ERROR
        );

} catch (Throwable $e) {

    callbackResponse(
        false,
        'Invalid payment callback JSON.',
        [
            'code' =>
                'INVALID_JSON'
        ],
        400
    );
}


if (!is_array($payload)) {

    callbackResponse(
        false,
        'Invalid payment callback payload.',
        [
            'code' =>
                'INVALID_PAYLOAD'
        ],
        400
    );
}


$paymentId =
    filter_var(
        $payload['payment_id'] ?? null,
        FILTER_VALIDATE_INT
    );


if (
    $paymentId === false
    || $paymentId === null
    || $paymentId <= 0
) {

    callbackResponse(
        false,
        'A valid payment_id is required.',
        [
            'code' =>
                'INVALID_PAYMENT_ID'
        ],
        400
    );
}


$status =
    strtolower(
        trim(
            (string) (
                $payload['status']
                ?? ''
            )
        )
    );


if (
    !in_array(
        $status,
        [
            'paid',
            'failed',
            'cancelled'
        ],
        true
    )
) {

    callbackResponse(
        false,
        'Invalid payment status.',
        [
            'code' =>
                'INVALID_PAYMENT_STATUS'
        ],
        400
    );
}


$transactionId =
    trim(
        (string) (
            $payload[
                'gateway_transaction_id'
            ]
            ?? ''
        )
    );


$amountPaid =
    $payload['amount_paid']
    ?? null;


if (
    $amountPaid !== null
    && $amountPaid !== ''
    && !is_numeric($amountPaid)
) {

    callbackResponse(
        false,
        'Invalid amount_paid.',
        [
            'code' =>
                'INVALID_AMOUNT'
        ],
        400
    );
}


$amountPaid =
    $amountPaid !== null
    && $amountPaid !== ''
        ? round(
            (float) $amountPaid,
            2
        )
        : null;


$providerCurrency =
    strtoupper(
        trim(
            (string) (
                $payload['currency']
                ?? ''
            )
        )
    );


/* ============================================================
   DATABASE
   ============================================================ */

try {

    $pdo =
        db();


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );


    $pdo->beginTransaction();


    /*
     * Lock the payment.
     */
    $paymentStmt =
        $pdo->prepare(
            "
            SELECT
                p.*,

                s.name AS service_name,
                s.duration_days,
                s.is_premium,
                s.is_active AS service_active,

                sub.id AS sub_id,
                sub.status AS subscription_status,

                u.full_names,
                u.username,
                u.email,

                c.code AS currency_code,
                c.symbol AS currency_symbol,

                rr.return_path

            FROM payments p

            INNER JOIN services s
                ON s.id = p.service_id

            LEFT JOIN subscriptions sub
                ON sub.id = p.subscription_id

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN currencies c
                ON c.id = p.currency_id

            LEFT JOIN payment_return_routes rr
                ON rr.payment_id = p.id

            WHERE p.id = :payment_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $paymentStmt->execute([
        ':payment_id' =>
            (int) $paymentId
    ]);


    $payment =
        $paymentStmt->fetch();


    if (!$payment) {

        $pdo->rollBack();

        callbackResponse(
            false,
            'Payment not found.',
            [
                'code' =>
                    'PAYMENT_NOT_FOUND'
            ],
            404
        );
    }


    /* ========================================================
       PAID
       ======================================================== */

    if ($status === 'paid') {

        $expected =
            round(
                (float) $payment['amount_expected'],
                2
            );


        $actual =
            $amountPaid !== null
                ? $amountPaid
                : $expected;


        /*
         * Validate currency when provider supplies it.
         */
        $storedCurrency =
            strtoupper(
                (string) (
                    $payment['currency_code']
                    ?? ''
                )
            );


        if (
            $providerCurrency !== ''
            && $storedCurrency !== ''
            && $providerCurrency !== $storedCurrency
        ) {

            $pdo->rollBack();

            callbackResponse(
                false,
                'Payment currency mismatch.',
                [
                    'code' =>
                        'PAYMENT_CURRENCY_MISMATCH'
                ],
                409
            );
        }


        /*
         * Never activate an underpaid transaction.
         */
        if (
            $actual + 0.0001
            < $expected
        ) {

            $update =
                $pdo->prepare(
                    "
                    UPDATE payments

                    SET
                        status = 'failed',
                        gateway_transaction_id =
                            NULLIF(:transaction_id, ''),
                        amount_paid = :amount_paid,
                        updated_at = CURRENT_TIMESTAMP

                    WHERE id = :payment_id
                    "
                );


            $update->execute([
                ':transaction_id' =>
                    $transactionId,

                ':amount_paid' =>
                    $actual,

                ':payment_id' =>
                    (int) $paymentId
            ]);


            if (
                !empty(
                    $payment['sub_id']
                )
            ) {

                $subUpdate =
                    $pdo->prepare(
                        "
                        UPDATE subscriptions

                        SET
                            status = 'cancelled',
                            updated_at = CURRENT_TIMESTAMP

                        WHERE id = :id

                          AND status = 'pending'
                        "
                    );


                $subUpdate->execute([
                    ':id' =>
                        (int) $payment['sub_id']
                ]);
            }


            createPaymentFailureNotification(
                $pdo,
                $payment,
                'failed'
            );


            $retryCode =
                createPaymentRetryCode(
                    $pdo,
                    (int) $paymentId
                );


            $resumeUrl =
                lovemiAppUrl()
                . '/'
                . paymentPageForMethod(
                    (string) $payment['payment_method']
                )
                . '?code='
                . rawurlencode($retryCode)
                . '&return='
                . rawurlencode(
                    safeReturnPath(
                        $payment['return_path'] ?? null
                    )
                );


            $pdo->commit();


            /*
             * Failure email after DB commit.
             */
            try {

                require_once
                    __DIR__
                    . '/../../services/email/main-email-service.php';


                if (
                    function_exists(
                        'sendLovemiPaymentFailedEmail'
                    )
                ) {

                    sendLovemiPaymentFailedEmail(
                        (string) $payment['email'],

                        (string) (
                            $payment['full_names']
                            ?: $payment['username']
                        ),

                        [
                            'payment_reference' =>
                                (string) $payment[
                                    'payment_reference'
                                ],

                            'service_name' =>
                                (string) $payment[
                                    'service_name'
                                ],

                            'payment_method' =>
                                (string) $payment[
                                    'payment_method'
                                ],

                            'gateway' =>
                                (string) $payment[
                                    'gateway'
                                ],

                            'currency' =>
                                $storedCurrency,

                            'amount_expected' =>
                                $expected,

                            'amount_paid' =>
                                $actual,

                            'status' =>
                                'failed',

                            'reason' =>
                                'The amount received was less than the required Premium payment amount.',

                            'continuation_url' =>
                                $resumeUrl
                        ]
                    );
                }

            } catch (Throwable $mailError) {

                error_log(
                    '[LOVEMI PAYMENT UNDERPAYMENT EMAIL] '
                    . $mailError->getMessage()
                );
            }


            callbackResponse(
                false,
                'The payment amount was insufficient.',
                [
                    'code' =>
                        'PAYMENT_UNDERPAID',

                    'payment_id' =>
                        (int) $paymentId,

                    'resume_url' =>
                        $resumeUrl
                ],
                409
            );
        }


        /*
         * User must still have an eligible account.
         */
        if (
            (int) $payment['is_deleted'] === 1
            || (int) $payment['is_suspended'] === 1
            || (int) $payment['is_active'] !== 1
        ) {

            $pdo->rollBack();

            callbackResponse(
                false,
                'The account is not eligible for Premium activation.',
                [
                    'code' =>
                        'ACCOUNT_NOT_ELIGIBLE'
                ],
                409
            );
        }


        /*
         * Maximum two active memberships.
         */
        $activeCountStmt =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM subscriptions

                WHERE user_id = :user_id

                  AND status = 'active'

                  AND start_at IS NOT NULL

                  AND end_at IS NOT NULL

                  AND end_at > CURRENT_TIMESTAMP

                FOR UPDATE
                "
            );


        $activeCountStmt->execute([
            ':user_id' =>
                (int) $payment['user_id']
        ]);


        $activeCount =
            (int) $activeCountStmt->fetchColumn();


        if (
            $activeCount >= 2
            && strtolower(
                (string) $payment[
                    'subscription_status'
                ]
            ) !== 'active'
        ) {

            /*
             * Payment was received, but there are already two
             * active Premium memberships.
             */
            $paymentUpdate =
                $pdo->prepare(
                    "
                    UPDATE payments

                    SET
                        status = 'paid',
                        gateway_transaction_id =
                            NULLIF(:transaction_id, ''),
                        amount_paid = :amount_paid,
                        paid_at = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP

                    WHERE id = :payment_id
                    "
                );


            $paymentUpdate->execute([
                ':transaction_id' =>
                    $transactionId,

                ':amount_paid' =>
                    $actual,

                ':payment_id' =>
                    (int) $paymentId
            ]);


            $pdo->commit();


            callbackResponse(
                false,
                'Payment was received, but the account already has two active Premium memberships.',
                [
                    'code' =>
                        'PREMIUM_LIMIT_REACHED_AFTER_PAYMENT',

                    'payment_id' =>
                        (int) $paymentId,

                    'refund_required' =>
                        true
                ],
                409
            );
        }


        /*
         * Activate subscription.
         */
        $durationDays =
            max(
                1,
                (int) $payment['duration_days']
            );


        $startAt =
            new DateTimeImmutable(
                'now',
                new DateTimeZone('UTC')
            );


        $endAt =
            $startAt->modify(
                '+' . $durationDays . ' days'
            );


        $paymentUpdate =
            $pdo->prepare(
                "
                UPDATE payments

                SET
                    status = 'paid',
                    gateway_transaction_id =
                        NULLIF(:transaction_id, ''),
                    amount_paid = :amount_paid,
                    paid_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP

                WHERE id = :payment_id
                "
            );


        $paymentUpdate->execute([
            ':transaction_id' =>
                $transactionId,

            ':amount_paid' =>
                $actual,

            ':payment_id' =>
                (int) $paymentId
        ]);


        if (
            !empty(
                $payment['sub_id']
            )
        ) {

            $subUpdate =
                $pdo->prepare(
                    "
                    UPDATE subscriptions

                    SET
                        status = 'active',
                        start_at = :start_at,
                        end_at = :end_at,
                        amount_paid = :amount_paid,
                        updated_at = CURRENT_TIMESTAMP

                    WHERE id = :id
                    "
                );


            $subUpdate->execute([
                ':start_at' =>
                    $startAt->format(
                        'Y-m-d H:i:s'
                    ),

                ':end_at' =>
                    $endAt->format(
                        'Y-m-d H:i:s'
                    ),

                ':amount_paid' =>
                    $actual,

                ':id' =>
                    (int) $payment['sub_id']
            ]);
        }


        /*
         * Successful payment notification.
         */
        $successTypeStmt =
            $pdo->prepare(
                "
                SELECT id
                FROM notification_types
                WHERE slug = 'payment_successful'
                LIMIT 1
                "
            );


        $successTypeStmt->execute();


        $successType =
            $successTypeStmt->fetchColumn();


        if ($successType) {

            $successAudioStmt =
                $pdo->prepare(
                    "
                    SELECT id
                    FROM notification_audio
                    WHERE notification_type_id = :type_id
                      AND is_active = 1
                    ORDER BY sort_order ASC, id ASC
                    LIMIT 1
                    "
                );


            $successAudioStmt->execute([
                ':type_id' =>
                    (int) $successType
            ]);


            $successAudio =
                $successAudioStmt->fetchColumn();


            $notification =
                $pdo->prepare(
                    "
                    INSERT INTO notifications
                    (
                        user_id,
                        notification_type_id,
                        sender_id,
                        title,
                        message,
                        reference_type,
                        reference_id,
                        audio_id,
                        is_read,
                        read_at,
                        created_at
                    )
                    VALUES
                    (
                        :user_id,
                        :type_id,
                        NULL,
                        'Payment Successful',
                        :message,
                        'payment',
                        :reference_id,
                        :audio_id,
                        0,
                        NULL,
                        CURRENT_TIMESTAMP
                    )
                    "
                );


            $notification->execute([
                ':user_id' =>
                    (int) $payment['user_id'],

                ':type_id' =>
                    (int) $successType,

                ':message' =>
                    'Your payment for '
                    . (string) $payment['service_name']
                    . ' was successful. Your Premium membership is now active.',

                ':reference_id' =>
                    (int) $paymentId,

                ':audio_id' =>
                    $successAudio !== false
                        ? (int) $successAudio
                        : null
            ]);
        }


        /*
         * At this point payment and Premium activation are committed.
         */
        $pdo->commit();


        /*
         * Return URL.
         */
        $returnUrl =
            lovemiAppUrl()
            . '/'
            . safeReturnPath(
                $payment['return_path'] ?? null
            );


        /*
         * Successful payment email.
         */
        try {

            require_once
                __DIR__
                . '/../../services/email/main-email-service.php';


            if (
                function_exists(
                    'sendLovemiPaymentSuccessEmail'
                )
            ) {

                sendLovemiPaymentSuccessEmail(
                    (string) $payment['email'],

                    (string) (
                        $payment['full_names']
                        ?: $payment['username']
                    ),

                    [
                        'payment_reference' =>
                            (string) $payment[
                                'payment_reference'
                            ],

                        'service_name' =>
                            (string) $payment[
                                'service_name'
                            ],

                        'payment_method' =>
                            (string) $payment[
                                'payment_method'
                            ],

                        'gateway' =>
                            (string) $payment[
                                'gateway'
                            ],

                        'gateway_transaction_id' =>
                            $transactionId,

                        'currency' =>
                            (string) $payment[
                                'currency_code'
                            ],

                        'currency_symbol' =>
                            (string) $payment[
                                'currency_symbol'
                            ],

                        'amount_paid' =>
                            $actual,

                        'base_amount_usd' =>
                            (float) $payment[
                                'base_amount_usd'
                            ],

                        'exchange_rate' =>
                            (float) $payment[
                                'exchange_rate'
                            ],

                        'premium_start_at' =>
                            $startAt->format(
                                'Y-m-d H:i:s'
                            ),

                        'premium_end_at' =>
                            $endAt->format(
                                'Y-m-d H:i:s'
                            ),

                        'return_url' =>
                            $returnUrl
                    ]
                );
            }

        } catch (Throwable $mailError) {

            error_log(
                '[LOVEMI PAYMENT SUCCESS EMAIL] '
                . $mailError->getMessage()
            );
        }


        callbackResponse(
            true,
            'Payment completed and Premium has been activated.',
            [
                'code' =>
                    'PAYMENT_COMPLETED',

                'payment_id' =>
                    (int) $paymentId,

                'payment_reference' =>
                    (string) $payment[
                        'payment_reference'
                    ],

                'status' =>
                    'paid',

                'return_url' =>
                    $returnUrl
            ]
        );
    }


    /* ========================================================
       FAILED / CANCELLED
       ======================================================== */

    if (
        $status === 'failed'
        || $status === 'cancelled'
    ) {

        $paymentUpdate =
            $pdo->prepare(
                "
                UPDATE payments

                SET
                    status = :status,
                    gateway_transaction_id =
                        NULLIF(:transaction_id, ''),
                    amount_paid =
                        COALESCE(
                            :amount_paid,
                            amount_paid
                        ),
                    updated_at = CURRENT_TIMESTAMP

                WHERE id = :payment_id
                "
            );


        $paymentUpdate->execute([
            ':status' =>
                $status,

            ':transaction_id' =>
                $transactionId,

            ':amount_paid' =>
                $amountPaid,

            ':payment_id' =>
                (int) $paymentId
        ]);


        /*
         * Pending subscription must not remain pending forever.
         */
        if (
            !empty(
                $payment['sub_id']
            )
        ) {

            $subscriptionUpdate =
                $pdo->prepare(
                    "
                    UPDATE subscriptions

                    SET
                        status = 'cancelled',
                        updated_at = CURRENT_TIMESTAMP

                    WHERE id = :id

                      AND status = 'pending'
                    "
                );


            $subscriptionUpdate->execute([
                ':id' =>
                    (int) $payment['sub_id']
            ]);
        }


        /*
         * THIS CREATES THE UNREAD NOTIFICATION.
         *
         * It also selects notification7.mp3 through notification_audio.
         */
        createPaymentFailureNotification(
            $pdo,
            $payment,
            $status
        );


        /*
         * Create secure continuation code.
         */
        $retryCode =
            createPaymentRetryCode(
                $pdo,
                (int) $paymentId
            );


        $returnPath =
            safeReturnPath(
                $payment['return_path']
                ?? null
            );


        $resumeUrl =
            lovemiAppUrl()
            . '/'
            . paymentPageForMethod(
                (string) $payment['payment_method']
            )
            . '?code='
            . rawurlencode($retryCode)
            . '&return='
            . rawurlencode($returnPath);


        $returnUrl =
            lovemiAppUrl()
            . '/'
            . $returnPath;


        /*
         * COMMIT BEFORE EMAIL.
         *
         * This guarantees that even if email sending fails,
         * the payment status and notification remain saved.
         */
        $pdo->commit();


        /* ====================================================
           BEAUTIFUL FAILURE / CANCELLED EMAIL
           ==================================================== */

        try {

            require_once
                __DIR__
                . '/../../services/email/main-email-service.php';


            if (
                function_exists(
                    'sendLovemiPaymentFailedEmail'
                )
            ) {

                sendLovemiPaymentFailedEmail(
                    (string) $payment['email'],

                    (string) (
                        $payment['full_names']
                        ?: $payment['username']
                    ),

                    [
                        'payment_reference' =>
                            (string) $payment[
                                'payment_reference'
                            ],

                        'service_name' =>
                            (string) $payment[
                                'service_name'
                            ],

                        'payment_method' =>
                            (string) $payment[
                                'payment_method'
                            ],

                        'gateway' =>
                            (string) $payment[
                                'gateway'
                            ],

                        'gateway_transaction_id' =>
                            $transactionId,

                        'currency' =>
                            (string) (
                                $payment[
                                    'currency_code'
                                ]
                                ?? $providerCurrency
                                ?? ''
                            ),

                        'currency_symbol' =>
                            (string) (
                                $payment[
                                    'currency_symbol'
                                ]
                                ?? ''
                            ),

                        'amount_expected' =>
                            round(
                                (float) $payment[
                                    'amount_expected'
                                ],
                                2
                            ),

                        'amount_paid' =>
                            $amountPaid !== null
                                ? $amountPaid
                                : 0,

                        'status' =>
                            $status,

                        'reason' =>
                            $status === 'cancelled'
                                ? 'The payment was cancelled before it could be completed. No Premium membership was activated.'
                                : 'The payment could not be completed. No Premium membership was activated.',

                        'continuation_url' =>
                            $resumeUrl,

                        'return_url' =>
                            $returnUrl
                    ]
                );

            } else {

                error_log(
                    '[LOVEMI] sendLovemiPaymentFailedEmail() '
                    . 'does not exist in main-email-service.php'
                );
            }

        } catch (Throwable $mailError) {

            /*
             * Email failure must NEVER undo the saved notification
             * or payment status.
             */
            error_log(
                '[LOVEMI PAYMENT FAILURE EMAIL] '
                . $mailError->getMessage()
            );
        }


        callbackResponse(
            true,
            $status === 'cancelled'
                ? 'Payment was cancelled. A secure continuation link is available.'
                : 'Payment failed. A secure continuation link is available.',
            [
                'code' =>
                    $status === 'cancelled'
                        ? 'PAYMENT_CANCELLED'
                        : 'PAYMENT_FAILED',

                'payment_id' =>
                    (int) $paymentId,

                'payment_reference' =>
                    (string) $payment[
                        'payment_reference'
                    ],

                'status' =>
                    $status,

                'resume_url' =>
                    $resumeUrl,

                'return_url' =>
                    $returnUrl
            ]
        );
    }


    /*
     * Safety fallback.
     */
    if (
        isset($pdo)
        && $pdo->inTransaction()
    ) {
        $pdo->rollBack();
    }


    callbackResponse(
        false,
        'The payment callback could not be processed.',
        [
            'code' =>
                'CALLBACK_NOT_PROCESSED'
        ],
        500
    );


} catch (Throwable $e) {

    if (
        isset($pdo)
        && $pdo->inTransaction()
    ) {
        try {
            $pdo->rollBack();
        } catch (Throwable $rollbackError) {
            error_log(
                '[LOVEMI CALLBACK ROLLBACK] '
                . $rollbackError->getMessage()
            );
        }
    }


    error_log(
        '[LOVEMI PAYMENT CALLBACK] '
        . $e->getMessage()
        . ' | File: '
        . $e->getFile()
        . ' | Line: '
        . $e->getLine()
    );


    callbackResponse(
        false,
        'The payment callback could not be completed because of a server error.',
        [
            'code' =>
                'PAYMENT_CALLBACK_ERROR'
        ],
        500
    );
}