<?php
/**
 * ============================================================
 * LOVEMI - PAYMENT VERIFICATION API
 * ============================================================
 *
 * Verifies a pending M-Pesa STK payment.
 *
 * The user's browser cannot declare a payment successful.
 * This endpoint asks the payment provider / trusted backend
 * and then updates the LOVEMI database.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function paymentVerifyResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

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

    paymentVerifyResponse(
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

    paymentVerifyResponse(
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
   INPUT
============================================================ */

$paymentId =
    isset(
        $_REQUEST['payment_id']
    )
        ? (int)
          $_REQUEST['payment_id']
        : 0;


if (
    $paymentId <= 0
) {

    paymentVerifyResponse(
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFY DB] '
        .
        $e->getMessage()
    );

    paymentVerifyResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/* ============================================================
   LOAD PAYMENT
============================================================ */

try {

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

                s.duration_days,
                s.name AS service_name,

                sub.status AS subscription_status

            FROM payments p

            INNER JOIN services s
                ON s.id = p.service_id

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


    $payment =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFY PAYMENT QUERY] '
        .
        $e->getMessage()
    );

    paymentVerifyResponse(
        false,
        'Unable to load payment information.',
        [],
        500
    );
}


if (
    !$payment
) {

    paymentVerifyResponse(
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
   ALREADY PAID
============================================================ */

if (
    $payment['status'] === 'paid'
) {

    paymentVerifyResponse(
        true,
        'Payment is already confirmed.',
        [

            'payment_id' =>
                (int)
                $payment['id'],

            'status' =>
                'paid',

            'subscription_id' =>
                $payment['subscription_id'] !== null
                    ?
                    (int)
                    $payment['subscription_id']
                    :
                    null,

            'subscription_status' =>
                $payment['subscription_status'],

            'premium_active' =>
                $payment['subscription_status'] === 'active'

        ]
    );
}


/* ============================================================
   NON-MPESA
============================================================ */

if (
    strtolower(
        (string)
        $payment['gateway']
    )
    !==
    'mpesa'
) {

    paymentVerifyResponse(
        true,
        'This payment is still awaiting confirmation from its payment gateway.',
        [

            'payment_id' =>
                (int)
                $payment['id'],

            'status' =>
                (string)
                $payment['status'],

            'gateway' =>
                (string)
                $payment['gateway'],

            'subscription_status' =>
                $payment['subscription_status'],

            'premium_active' =>
                $payment['subscription_status'] === 'active'

        ]
    );
}


/* ============================================================
   CHECKOUT REFERENCE
============================================================ */

$checkoutRequestId =
    trim(
        (string)
        (
            $payment['checkout_reference']
            ??
            ''
        )
    );


if (
    $checkoutRequestId === ''
) {

    paymentVerifyResponse(
        true,
        'The payment request has not received a provider reference yet.',
        [
            'payment_id' =>
                $paymentId,

            'status' =>
                'pending',

            'code' =>
                'CHECKOUT_REFERENCE_PENDING'
        ]
    );
}


/* ============================================================
   MPESA CONFIGURATION
============================================================ */

$consumerKey =
    trim(
        (string)
        getenv('MPESA_CONSUMER_KEY')
    );


$consumerSecret =
    trim(
        (string)
        getenv('MPESA_CONSUMER_SECRET')
    );


$shortCode =
    trim(
        (string)
        getenv('MPESA_SHORTCODE')
    );


$passKey =
    trim(
        (string)
        getenv('MPESA_PASSKEY')
    );


$baseUrl =
    trim(
        (string)
        getenv('MPESA_BASE_URL')
    );


if (
    $baseUrl === ''
) {

    $baseUrl =
        'https://sandbox.safaricom.co.ke';

}


if (
    $consumerKey === ''
    ||
    $consumerSecret === ''
    ||
    $shortCode === ''
    ||
    $passKey === ''
) {

    paymentVerifyResponse(
        false,
        'M-Pesa verification is not configured on the server.',
        [
            'code' =>
                'MPESA_CONFIGURATION_REQUIRED'
        ],
        503
    );
}


/* ============================================================
   OAUTH
============================================================ */

$credentials =
    base64_encode(
        $consumerKey
        .
        ':'
        .
        $consumerSecret
    );


$oauth =
    curl_init(
        rtrim(
            $baseUrl,
            '/'
        )
        .
        '/oauth/v1/generate?grant_type=client_credentials'
    );


curl_setopt_array(
    $oauth,
    [

        CURLOPT_RETURNTRANSFER =>
            true,

        CURLOPT_POST =>
            true,

        CURLOPT_HTTPHEADER => [

            'Authorization: Basic '
            .
            $credentials,

            'Accept: application/json'

        ],

        CURLOPT_TIMEOUT =>
            30,

        CURLOPT_CONNECTTIMEOUT =>
            10

    ]
);


$oauthResponse =
    curl_exec(
        $oauth
    );


$oauthHttp =
    (int)
    curl_getinfo(
        $oauth,
        CURLINFO_HTTP_CODE
    );


$oauthError =
    curl_error(
        $oauth
    );


curl_close(
    $oauth
);


if (
    $oauthResponse === false
    ||
    $oauthError !== ''
) {

    error_log(
        '[LOVEMI VERIFY OAUTH] '
        .
        $oauthError
    );

    paymentVerifyResponse(
        false,
        'Unable to contact the payment authorization service.',
        [
            'code' =>
                'MPESA_AUTH_CONNECTION_FAILED'
        ],
        502
    );
}


$oauthData =
    json_decode(
        $oauthResponse,
        true
    );


$accessToken =
    is_array(
        $oauthData
    )
        ?
        (
            $oauthData['access_token']
            ??
            ''
        )
        :
        '';


if (
    $oauthHttp < 200
    ||
    $oauthHttp >= 300
    ||
    $accessToken === ''
) {

    paymentVerifyResponse(
        false,
        'M-Pesa authorization failed.',
        [
            'code' =>
                'MPESA_AUTH_FAILED'
        ],
        502
    );
}


/* ============================================================
   STK QUERY
============================================================ */

$timestamp =
    gmdate(
        'YmdHis'
    );


$password =
    base64_encode(
        $shortCode
        .
        $passKey
        .
        $timestamp
    );


$queryPayload = [

    'BusinessShortCode' =>
        $shortCode,

    'Password' =>
        $password,

    'Timestamp' =>
        $timestamp,

    'CheckoutRequestID' =>
        $checkoutRequestId

];


$query =
    curl_init(
        rtrim(
            $baseUrl,
            '/'
        )
        .
        '/mpesa/stkpushquery/v1/query'
    );


curl_setopt_array(
    $query,
    [

        CURLOPT_RETURNTRANSFER =>
            true,

        CURLOPT_POST =>
            true,

        CURLOPT_POSTFIELDS =>
            json_encode(
                $queryPayload
            ),

        CURLOPT_HTTPHEADER => [

            'Authorization: Bearer '
            .
            $accessToken,

            'Content-Type: application/json',

            'Accept: application/json'

        ],

        CURLOPT_TIMEOUT =>
            30,

        CURLOPT_CONNECTTIMEOUT =>
            10

    ]
);


$queryResponse =
    curl_exec(
        $query
    );


$queryHttp =
    (int)
    curl_getinfo(
        $query,
        CURLINFO_HTTP_CODE
    );


$queryError =
    curl_error(
        $query
    );


curl_close(
    $query
);


if (
    $queryResponse === false
    ||
    $queryError !== ''
) {

    error_log(
        '[LOVEMI STK QUERY CURL] '
        .
        $queryError
    );

    paymentVerifyResponse(
        false,
        'Unable to contact M-Pesa transaction verification.',
        [
            'code' =>
                'MPESA_QUERY_CONNECTION_FAILED'
        ],
        502
    );
}


$queryData =
    json_decode(
        $queryResponse,
        true
    );


if (
    !is_array(
        $queryData
    )
) {

    paymentVerifyResponse(
        false,
        'Invalid M-Pesa verification response.',
        [
            'code' =>
                'MPESA_QUERY_INVALID_RESPONSE'
        ],
        502
    );
}


/* ============================================================
   RESULT
============================================================ */

$resultCode =
    (string)
    (
        $queryData['ResultCode']
        ??
        ''
    );


$resultDescription =
    (string)
    (
        $queryData['ResultDesc']
        ??
        ''
    );


/*
 * 0 is successful.
 */

if (
    $queryHttp >= 200
    &&
    $queryHttp < 300
    &&
    $resultCode === '0'
) {

    /*
     * We have provider confirmation.
     *
     * Activate transaction safely.
     */

    try {

        $pdo->beginTransaction();


        /*
         * Lock payment row.
         */

        $lockStmt =
            $pdo->prepare(
                "
                SELECT

                    p.id,
                    p.user_id,
                    p.service_id,
                    p.subscription_id,
                    p.status,
                    p.amount_expected,

                    s.duration_days

                FROM payments p

                INNER JOIN services s
                    ON s.id = p.service_id

                WHERE p.id = :id

                FOR UPDATE
                "
            );


        $lockStmt->execute(
            [
                ':id' =>
                    $paymentId
            ]
        );


        $locked =
            $lockStmt->fetch();


        if (
            !$locked
        ) {

            throw new RuntimeException(
                'Payment not found while verifying.'
            );

        }


        if (
            $locked['status'] !== 'paid'
        ) {

            $updatePayment =
                $pdo->prepare(
                    "
                    UPDATE payments

                    SET

                        gateway = 'mpesa',

                        payment_method = 'mpesa',

                        status = 'paid',

                        gateway_transaction_id =
                            :transaction_id,

                        amount_paid =
                            amount_expected,

                        paid_at =
                            CURRENT_TIMESTAMP

                    WHERE id = :id

                    LIMIT 1
                    "
                );


            $updatePayment->execute(
                [
                    ':transaction_id' =>
                        $checkoutRequestId,

                    ':id' =>
                        $paymentId
                ]
            );


            if (
                empty(
                    $locked['subscription_id']
                )
            ) {

                throw new RuntimeException(
                    'Payment has no subscription.'
                );

            }


            $durationDays =
                max(
                    1,
                    (int)
                    $locked['duration_days']
                );


            $startAt =
                date(
                    'Y-m-d H:i:s'
                );


            $endAt =
                date(
                    'Y-m-d H:i:s',
                    strtotime(
                        '+'
                        .
                        $durationDays
                        .
                        ' days'
                    )
                );


            $activateSub =
                $pdo->prepare(
                    "
                    UPDATE subscriptions

                    SET

                        status = 'active',

                        start_at = :start_at,

                        end_at = :end_at,

                        amount_paid =
                            :amount_paid,

                        payment_id =
                            :payment_id

                    WHERE id = :id

                      AND status <> 'active'

                    LIMIT 1
                    "
                );


            $activateSub->execute(
                [

                    ':start_at' =>
                        $startAt,

                    ':end_at' =>
                        $endAt,

                    ':amount_paid' =>
                        $locked['amount_expected'],

                    ':payment_id' =>
                        $paymentId,

                    ':id' =>
                        (int)
                        $locked['subscription_id']

                ]
            );


            /*
             * Receipt.
             */

            try {

                $receiptNumber =
                    'LVM-'
                    .
                    date('YmdHis')
                    .
                    '-'
                    .
                    $paymentId;


                $receiptStmt =
                    $pdo->prepare(
                        "
                        INSERT INTO payment_receipts
                        (
                            payment_id,
                            receipt_number,
                            receipt_path,
                            issued_at
                        )
                        VALUES
                        (
                            :payment_id,
                            :receipt_number,
                            NULL,
                            CURRENT_TIMESTAMP
                        )
                        "
                    );


                $receiptStmt->execute(
                    [
                        ':payment_id' =>
                            $paymentId,

                        ':receipt_number' =>
                            $receiptNumber
                    ]
                );

            } catch (Throwable $receiptError) {

                error_log(
                    '[LOVEMI VERIFY RECEIPT] '
                    .
                    $receiptError->getMessage()
                );

            }

        }


        $pdo->commit();

    } catch (Throwable $e) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        error_log(
            '[LOVEMI VERIFY ACTIVATION] '
            .
            $e->getMessage()
        );


        paymentVerifyResponse(
            false,
            'Payment was confirmed but Premium activation failed.',
            [
                'code' =>
                    'PREMIUM_ACTIVATION_FAILED'
            ],
            500
        );
    }


    paymentVerifyResponse(
        true,
        'Payment verified successfully. Premium is now active.',
        [

            'payment_id' =>
                $paymentId,

            'status' =>
                'paid',

            'premium_active' =>
                true,

            'subscription_id' =>
                $payment['subscription_id'] !== null
                    ?
                    (int)
                    $payment['subscription_id']
                    :
                    null,

            'redirect' =>
                'premium.html'

        ]
    );
}


/* ============================================================
   PAYMENT STILL PENDING
============================================================ */

paymentVerifyResponse(
    true,
    $resultDescription !== ''
        ?
        $resultDescription
        :
        'Payment is still awaiting confirmation.',
    [

        'payment_id' =>
            $paymentId,

        'status' =>
            'pending',

        'premium_active' =>
            false,

        'code' =>
            'PAYMENT_PENDING'

    ]
);