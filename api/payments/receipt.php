<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function receiptResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    receiptResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTH
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

    receiptResponse(
        false,
        'Please log in first.',
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
    (int)
    (
        $_GET['payment_id']
        ??
        0
    );


if (
    $paymentId <= 0
) {

    receiptResponse(
        false,
        'Payment ID is required.',
        [
            'code' =>
                'PAYMENT_ID_REQUIRED'
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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI RECEIPT DB] '
        .
        $e->getMessage()
    );


    receiptResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   LOAD PAYMENT
============================================================ */

try {

    $paymentStmt =
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
                p.gateway_fee,
                p.paid_at,
                p.created_at,

                u.username,
                u.full_names,
                u.email,

                s.name AS service_name,
                s.slug AS service_slug,

                c.code AS currency_code,
                c.name AS currency_name,
                c.symbol AS currency_symbol,
                c.decimal_places

            FROM payments p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN services s
                ON s.id = p.service_id

            LEFT JOIN currencies c
                ON c.id = p.currency_id

            WHERE p.id =
                  :payment_id

              AND p.user_id =
                  :user_id

            LIMIT 1
            "
        );


    $paymentStmt->execute(
        [

            ':payment_id' =>
                $paymentId,

            ':user_id' =>
                $userId

        ]
    );


    $payment =
        $paymentStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI RECEIPT PAYMENT QUERY] '
        .
        $e->getMessage()
    );


    receiptResponse(
        false,
        'Unable to load the payment.',
        [
            'code' =>
                'PAYMENT_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$payment
) {

    receiptResponse(
        false,
        'Payment not found.',
        [
            'code' =>
                'PAYMENT_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   PAYMENT STATUS
============================================================ */

if (
    strtolower(
        (string)
        $payment['status']
    )
    !==
    'paid'
) {

    receiptResponse(
        false,
        'A receipt is only available for a completed payment.',
        [

            'code' =>
                'PAYMENT_NOT_PAID',

            'payment_status' =>
                $payment['status']

        ],
        409
    );
}


/* ============================================================
   FIND EXISTING RECEIPT
============================================================ */

try {

    $existingStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                payment_id,
                receipt_number,
                receipt_path,
                issued_at

            FROM payment_receipts

            WHERE payment_id =
                :payment_id

            LIMIT 1
            "
        );


    $existingStmt->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    $receipt =
        $existingStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI RECEIPT EXISTING QUERY] '
        .
        $e->getMessage()
    );


    $receipt =
        false;

}


/* ============================================================
   CREATE RECEIPT IF NEEDED
============================================================ */

if (
    !$receipt
) {

    try {

        /*
         * Use random bytes so receipt numbers are not predictable.
         */

        $receiptNumber =
            'LM-'
            .
            date('Ym')
            .
            '-'
            .
            strtoupper(
                bin2hex(
                    random_bytes(
                        5
                    )
                )
            );


    } catch (
        Throwable $e
    ) {

        receiptResponse(
            false,
            'Unable to generate a receipt number.',
            [
                'code' =>
                    'RECEIPT_NUMBER_FAILED'
            ],
            500
        );
    }


    try {

        $insertReceipt =
            $pdo->prepare(
                "
                INSERT INTO payment_receipts
                (
                    payment_id,
                    receipt_number,
                    receipt_path
                )
                VALUES
                (
                    :payment_id,
                    :receipt_number,
                    NULL
                )
                "
            );


        $insertReceipt->execute(
            [

                ':payment_id' =>
                    $paymentId,

                ':receipt_number' =>
                    $receiptNumber

            ]
        );


        $receiptId =
            (int)
            $pdo->lastInsertId();


        $receipt = [

            'id' =>
                $receiptId,

            'payment_id' =>
                $paymentId,

            'receipt_number' =>
                $receiptNumber,

            'receipt_path' =>
                null,

            'issued_at' =>
                date(
                    'Y-m-d H:i:s'
                )

        ];

    } catch (
        PDOException $e
    ) {

        /*
         * Another simultaneous request may have created it.
         * Try once more.
         */

        try {

            $retryStmt =
                $pdo->prepare(
                    "
                    SELECT

                        id,
                        payment_id,
                        receipt_number,
                        receipt_path,
                        issued_at

                    FROM payment_receipts

                    WHERE payment_id =
                        :payment_id

                    LIMIT 1
                    "
                );


            $retryStmt->execute(
                [
                    ':payment_id' =>
                        $paymentId
                ]
            );


            $receipt =
                $retryStmt->fetch();

        } catch (
            Throwable $retryException
        ) {

            error_log(
                '[LOVEMI RECEIPT RETRY] '
                .
                $retryException->getMessage()
            );


            receiptResponse(
                false,
                'Unable to create the payment receipt.',
                [
                    'code' =>
                        'RECEIPT_CREATION_FAILED'
                ],
                500
            );
        }

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI RECEIPT CREATE] '
            .
            $e->getMessage()
        );


        receiptResponse(
            false,
            'Unable to create the payment receipt.',
            [
                'code' =>
                    'RECEIPT_CREATION_FAILED'
            ],
            500
        );
    }

}


/* ============================================================
   RECEIPT DOWNLOAD URL
============================================================ */

$receiptUrl =
    null;


if (
    !empty(
        $receipt['receipt_path']
    )
) {

    $receiptUrl =
        (string)
        $receipt['receipt_path'];

}


/* ============================================================
   RESPONSE
============================================================ */

receiptResponse(
    true,
    'Payment receipt loaded successfully.',
    [

        'receipt' => [

            'id' =>
                (int)
                $receipt['id'],

            'receipt_number' =>
                $receipt['receipt_number'],

            'receipt_path' =>
                $receiptUrl,

            'issued_at' =>
                $receipt['issued_at'],

            'payment' => [

                'id' =>
                    (int)
                    $payment['id'],

                'reference' =>
                    $payment['payment_reference'],

                'gateway' =>
                    $payment['gateway'],

                'gateway_transaction_id' =>
                    $payment['gateway_transaction_id'],

                'method' =>
                    $payment['payment_method'],

                'status' =>
                    $payment['status'],

                'base_amount_usd' =>
                    (float)
                    $payment['base_amount_usd'],

                'exchange_rate' =>
                    $payment['exchange_rate']
                    !==
                    null
                        ?
                        (float)
                        $payment['exchange_rate']
                        :
                        null,

                'amount_expected' =>
                    (float)
                    $payment['amount_expected'],

                'amount_paid' =>
                    (float)
                    $payment['amount_paid'],

                'gateway_fee' =>
                    (float)
                    $payment['gateway_fee'],

                'paid_at' =>
                    $payment['paid_at'],

                'created_at' =>
                    $payment['created_at']

            ],

            'customer' => [

                'username' =>
                    $payment['username'],

                'full_names' =>
                    $payment['full_names'],

                'email' =>
                    $payment['email']

            ],

            'service' => [

                'name' =>
                    $payment['service_name'],

                'slug' =>
                    $payment['service_slug']

            ],

            'currency' => [

                'code' =>
                    $payment['currency_code'],

                'name' =>
                    $payment['currency_name'],

                'symbol' =>
                    $payment['currency_symbol'],

                'decimal_places' =>
                    $payment['decimal_places']
                    !==
                    null
                        ?
                        (int)
                        $payment['decimal_places']
                        :
                        2

            ]

        ]

    ]
);