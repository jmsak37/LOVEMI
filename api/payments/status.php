<?php
/**
 * ============================================================
 * LOVEMI - PAYMENT STATUS API
 * ============================================================
 *
 * Returns the authenticated user's payment status.
 *
 * This endpoint NEVER changes payment status.
 * Only trusted payment verification/callback processing may
 * activate Premium.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function paymentStatusResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    !in_array(
        $_SERVER['REQUEST_METHOD'] ?? '',
        [
            'GET',
            'POST'
        ],
        true
    )
) {

    paymentStatusResponse(
        false,
        'GET or POST is required.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   USER
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    paymentStatusResponse(
        false,
        'Please log in to view payment status.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
        ],
        401
    );
}


/* ============================================================
   PAYMENT ID
============================================================ */

$paymentId =
    isset(
        $_REQUEST['payment_id']
    )
        ? (int)
          $_REQUEST['payment_id']
        : 0;


$paymentReference =
    trim(
        (string)
        (
            $_REQUEST['payment_reference']
            ??
            ''
        )
    );


if (
    $paymentId <= 0
    &&
    $paymentReference === ''
) {

    paymentStatusResponse(
        false,
        'Payment ID or payment reference is required.',
        [
            'code' =>
                'PAYMENT_IDENTIFIER_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PAYMENT STATUS DB] '
        .
        $e->getMessage()
    );

    paymentStatusResponse(
        false,
        'Unable to connect to the database.',
        [],
        500
    );
}


/* ============================================================
   PAYMENT QUERY
============================================================ */

try {

    if (
        $paymentId > 0
    ) {

        $stmt =
            $pdo->prepare(
                "
                SELECT

                    p.id,
                    p.user_id,
                    p.service_id,
                    p.subscription_id,
                    p.payment_reference,
                    p.gateway,
                    p.gateway_transaction_id,
                    p.payment_method,
                    p.status,
                    p.currency_id,
                    p.base_amount_usd,
                    p.exchange_rate,
                    p.amount_expected,
                    p.amount_paid,
                    p.checkout_reference,
                    p.paid_at,
                    p.created_at,
                    p.updated_at,

                    s.name AS service_name,
                    s.slug AS service_slug,
                    s.duration_days,

                    c.code AS currency_code,
                    c.name AS currency_name,
                    c.symbol AS currency_symbol,
                    c.decimal_places,

                    sub.status AS subscription_status,
                    sub.start_at AS subscription_start,
                    sub.end_at AS subscription_end,
                    sub.usage_limit,
                    sub.usage_used

                FROM payments p

                INNER JOIN services s
                    ON s.id = p.service_id

                LEFT JOIN currencies c
                    ON c.id = p.currency_id

                LEFT JOIN subscriptions sub
                    ON sub.id = p.subscription_id

                WHERE p.id = :payment_id

                  AND p.user_id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [

                ':payment_id' =>
                    $paymentId,

                ':user_id' =>
                    $userId

            ]
        );

    } else {

        $stmt =
            $pdo->prepare(
                "
                SELECT

                    p.id,
                    p.user_id,
                    p.service_id,
                    p.subscription_id,
                    p.payment_reference,
                    p.gateway,
                    p.gateway_transaction_id,
                    p.payment_method,
                    p.status,
                    p.currency_id,
                    p.base_amount_usd,
                    p.exchange_rate,
                    p.amount_expected,
                    p.amount_paid,
                    p.checkout_reference,
                    p.paid_at,
                    p.created_at,
                    p.updated_at,

                    s.name AS service_name,
                    s.slug AS service_slug,
                    s.duration_days,

                    c.code AS currency_code,
                    c.name AS currency_name,
                    c.symbol AS currency_symbol,
                    c.decimal_places,

                    sub.status AS subscription_status,
                    sub.start_at AS subscription_start,
                    sub.end_at AS subscription_end,
                    sub.usage_limit,
                    sub.usage_used

                FROM payments p

                INNER JOIN services s
                    ON s.id = p.service_id

                LEFT JOIN currencies c
                    ON c.id = p.currency_id

                LEFT JOIN subscriptions sub
                    ON sub.id = p.subscription_id

                WHERE p.payment_reference = :payment_reference

                  AND p.user_id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [

                ':payment_reference' =>
                    $paymentReference,

                ':user_id' =>
                    $userId

            ]
        );

    }


    $payment =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PAYMENT STATUS QUERY] '
        .
        $e->getMessage()
    );

    paymentStatusResponse(
        false,
        'Unable to load payment status.',
        [],
        500
    );
}


/* ============================================================
   PAYMENT NOT FOUND
============================================================ */

if (
    !$payment
) {

    paymentStatusResponse(
        false,
        'Payment order not found.',
        [
            'code' =>
                'PAYMENT_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   RECEIPT
============================================================ */

$receipt =
    null;


try {

    $receiptStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                receipt_number,
                receipt_path,
                issued_at

            FROM payment_receipts

            WHERE payment_id = :payment_id

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $receiptStmt->execute(
        [
            ':payment_id' =>
                (int)
                $payment['id']
        ]
    );


    $receiptRow =
        $receiptStmt->fetch();


    if (
        $receiptRow
    ) {

        $receipt = [

            'id' =>
                (int)
                $receiptRow['id'],

            'receipt_number' =>
                (string)
                $receiptRow['receipt_number'],

            'receipt_path' =>
                $receiptRow['receipt_path'],

            'issued_at' =>
                $receiptRow['issued_at']

        ];

    }

} catch (Throwable $e) {

    /*
     * Receipt lookup is optional.
     */

    error_log(
        '[LOVEMI PAYMENT RECEIPT STATUS] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   PREMIUM ACTIVE
============================================================ */

$premiumActive =
    (
        $payment['subscription_status'] ===
        'active'
        &&
        $payment['subscription_end'] !== null
        &&
        strtotime(
            (string)
            $payment['subscription_end']
        )
        >
        time()
    );


/* ============================================================
   RESPONSE
============================================================ */

paymentStatusResponse(
    true,
    'Payment status loaded successfully.',
    [

        'payment' => [

            'id' =>
                (int)
                $payment['id'],

            'payment_reference' =>
                (string)
                $payment['payment_reference'],

            'service_id' =>
                (int)
                $payment['service_id'],

            'service_name' =>
                (string)
                $payment['service_name'],

            'gateway' =>
                (string)
                $payment['gateway'],

            'payment_method' =>
                $payment['payment_method'],

            'gateway_transaction_id' =>
                $payment['gateway_transaction_id'],

            'checkout_reference' =>
                $payment['checkout_reference'],

            'status' =>
                (string)
                $payment['status'],

            'base_amount_usd' =>
                number_format(
                    (float)
                    $payment['base_amount_usd'],
                    2,
                    '.',
                    ''
                ),

            'exchange_rate' =>
                $payment['exchange_rate'] !== null
                    ?
                    number_format(
                        (float)
                        $payment['exchange_rate'],
                        10,
                        '.',
                        ''
                    )
                    :
                    null,

            'amount_expected' =>
                number_format(
                    (float)
                    $payment['amount_expected'],
                    (int)
                    $payment['decimal_places'],
                    '.',
                    ''
                ),

            'amount_paid' =>
                number_format(
                    (float)
                    $payment['amount_paid'],
                    (int)
                    $payment['decimal_places'],
                    '.',
                    ''
                ),

            'currency' => [

                'code' =>
                    (string)
                    $payment['currency_code'],

                'name' =>
                    (string)
                    $payment['currency_name'],

                'symbol' =>
                    (string)
                    $payment['currency_symbol'],

                'decimal_places' =>
                    (int)
                    $payment['decimal_places']

            ],

            'paid_at' =>
                $payment['paid_at'],

            'created_at' =>
                $payment['created_at'],

            'updated_at' =>
                $payment['updated_at']

        ],


        'subscription' => [

            'id' =>
                $payment['subscription_id'] !== null
                    ?
                    (int)
                    $payment['subscription_id']
                    :
                    null,

            'status' =>
                $payment['subscription_status'],

            'start_at' =>
                $payment['subscription_start'],

            'end_at' =>
                $payment['subscription_end'],

            'duration_days' =>
                (int)
                $payment['duration_days'],

            'usage_limit' =>
                $payment['usage_limit'] !== null
                    ?
                    (int)
                    $payment['usage_limit']
                    :
                    null,

            'usage_used' =>
                (int)
                $payment['usage_used']

        ],


        'premium_active' =>
            $premiumActive,


        'receipt' =>
            $receipt


    ]
);