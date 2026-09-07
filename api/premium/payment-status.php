<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function paymentStatusResponse(
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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    paymentStatusResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

$userId =
    (int) (
        $_SESSION['lovemi_user_id'] ?? 0
    );

if ($userId <= 0) {

    paymentStatusResponse(
        false,
        'Authentication required.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
        ],
        401
    );
}

$code =
    trim(
        (string) (
            $_GET['code'] ?? ''
        )
    );

if (
    $code === '' ||
    !preg_match(
        '/^[a-f0-9]{64}$/i',
        $code
    )
) {

    paymentStatusResponse(
        false,
        'A valid secure payment code is required.',
        [
            'code' =>
                'INVALID_PAYMENT_CODE'
        ],
        403
    );
}

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

    /*
     * Ensure the receipt table exists.
     * Existing database installations can therefore
     * still use this endpoint after migration.
     */
    $pdo->exec(
        "CREATE TABLE IF NOT EXISTS payment_receipt_access
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            payment_id BIGINT UNSIGNED NOT NULL,

            token_hash CHAR(64) NOT NULL,

            expires_at DATETIME NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            UNIQUE KEY uq_receipt_access_hash
                (token_hash),

            UNIQUE KEY uq_receipt_access_payment
                (payment_id),

            KEY idx_receipt_access_expiry
                (expires_at)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci"
    );

    $query =
        $pdo->prepare(
            "SELECT
                p.*,

                s.id AS subscription_id,

                s.status AS subscription_status,

                s.start_at,

                s.end_at,

                sv.name AS service_name,

                sv.duration_days,

                cu.code AS currency_code,

                cu.symbol AS currency_symbol,

                rr.return_path

             FROM payment_access_tokens pat

             INNER JOIN payments p
                ON p.id =
                    pat.payment_id

             INNER JOIN subscriptions s
                ON s.payment_id =
                    p.id

             INNER JOIN services sv
                ON sv.id =
                    p.service_id

             LEFT JOIN currencies cu
                ON cu.id =
                    p.currency_id

             LEFT JOIN payment_return_routes rr
                ON rr.payment_id =
                    p.id

             WHERE pat.token_hash = :token_hash

               AND pat.expires_at >
                   CURRENT_TIMESTAMP

               AND p.user_id = :user_id

             LIMIT 1"
        );

    $query->execute(
        [
            ':token_hash' =>
                hash(
                    'sha256',
                    $code
                ),

            ':user_id' =>
                $userId
        ]
    );

    $payment =
        $query->fetch();

    if (!$payment) {

        paymentStatusResponse(
            false,
            'This payment link is invalid or expired.',
            [
                'code' =>
                    'PAYMENT_CODE_INVALID'
            ],
            403
        );
    }

    $receiptCode =
        null;

    if (
        (string)
            $payment['status'] ===
        'paid'
    ) {

        $existingReceipt =
            $pdo->prepare(
                "SELECT
                    receipt_number
                 FROM payment_receipts
                 WHERE payment_id = :payment_id
                 LIMIT 1"
            );

        $existingReceipt->execute(
            [
                ':payment_id' =>
                    (int)
                    $payment['id']
            ]
        );

        if ($existingReceipt->fetch()) {

            $receiptCode =
                bin2hex(
                    random_bytes(32)
                );

            /*
             * NOTE:
             * This uses the current schema where
             * one payment owns one receipt access token.
             */
            $receiptToken =
                $pdo->prepare(
                    "INSERT INTO payment_receipt_access
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
                            INTERVAL 90 DAY
                        )
                    )
                    ON DUPLICATE KEY UPDATE
                        token_hash =
                            VALUES(token_hash),

                        expires_at =
                            VALUES(expires_at)"
                );

            $receiptToken->execute(
                [
                    ':payment_id' =>
                        (int)
                        $payment['id'],

                    ':token_hash' =>
                        hash(
                            'sha256',
                            $receiptCode
                        )
                ]
            );
        }
    }

    paymentStatusResponse(
        true,
        'Payment status loaded.',
        [
            'payment' => [
                'id' =>
                    (int)
                    $payment['id'],

                'payment_reference' =>
                    $payment[
                        'payment_reference'
                    ],

                'gateway' =>
                    $payment['gateway'],

                'payment_method' =>
                    $payment[
                        'payment_method'
                    ],

                'status' =>
                    $payment['status'],

                'subscription_id' =>
                    (int)
                    $payment[
                        'subscription_id'
                    ],

                'subscription_status' =>
                    $payment[
                        'subscription_status'
                    ],

                'service_name' =>
                    $payment['service_name'],

                'currency' =>
                    $payment['currency_code'],

                'currency_symbol' =>
                    $payment[
                        'currency_symbol'
                    ],

                'amount_expected' =>
                    $payment[
                        'amount_expected'
                    ],

                'amount_paid' =>
                    $payment[
                        'amount_paid'
                    ],

                'start_at' =>
                    $payment['start_at'],

                'end_at' =>
                    $payment['end_at'],

                'return_path' =>
                    $payment['return_path']
                    ?: 'dashboard.html',

                'payment_code' =>
                    $code,

                'receipt_code' =>
                    $receiptCode
            ]
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PAYMENT STATUS] ' .
        $e->getMessage()
    );

    paymentStatusResponse(
        false,
        'Unable to load payment status.',
        [
            'code' =>
                'PAYMENT_STATUS_ERROR'
        ],
        500
    );
}