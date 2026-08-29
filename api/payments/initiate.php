<?php
/**
 * ============================================================
 * LOVEMI - PAYMENT INITIATION API
 * ============================================================
 *
 * Creates/starts the actual external payment request for an
 * already-created pending payment.
 *
 * Supported:
 *   - M-Pesa STK Push
 *
 * Card / PayPal:
 *   - Payment order is preserved in the database.
 *   - Returns a clear "gateway not configured" response until
 *     credentials / gateway integration are provided.
 *
 * IMPORTANT:
 *   Browser input is never trusted for:
 *      - amount
 *      - currency
 *      - user identity
 *      - subscription price
 *
 * All monetary information comes from the database.
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

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function paymentInitiateResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    paymentInitiateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   SESSION USER
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    paymentInitiateResponse(
        false,
        'Please log in before making a payment.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' =>
                'login.html?return=premium.html'
        ],
        401
    );
}


/* ============================================================
   READ INPUT
============================================================ */

$rawInput =
    file_get_contents('php://input');


$input =
    json_decode(
        $rawInput ?: '{}',
        true
    );


if (!is_array($input)) {
    $input = [];
}


$paymentId =
    isset($input['payment_id'])
        ? (int) $input['payment_id']
        : 0;


$paymentMethod =
    strtolower(
        trim(
            (string) (
                $input['payment_method']
                ??
                ''
            )
        )
    );


$paymentReference =
    trim(
        (string) (
            $input['payment_reference']
            ??
            ''
        )
    );


/* ============================================================
   IDENTIFIER REQUIRED
============================================================ */

if (
    $paymentId <= 0
    &&
    $paymentReference === ''
) {

    paymentInitiateResponse(
        false,
        'A payment ID or payment reference is required.',
        [
            'code' => 'PAYMENT_IDENTIFIER_REQUIRED'
        ],
        422
    );
}


/* ============================================================
   PAYMENT METHOD
============================================================ */

$allowedMethods = [
    'mpesa',
    'card',
    'paypal'
];


if (
    !in_array(
        $paymentMethod,
        $allowedMethods,
        true
    )
) {

    paymentInitiateResponse(
        false,
        'Please select a valid payment method.',
        [
            'code' => 'INVALID_PAYMENT_METHOD'
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
        '[LOVEMI INITIATE DB] '
        .
        $e->getMessage()
    );

    paymentInitiateResponse(
        false,
        'Unable to connect to the database.',
        [],
        500
    );
}


/* ============================================================
   LOAD PAYMENT
============================================================ */

try {

    if ($paymentId > 0) {

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
                    p.phone_number,
                    p.checkout_reference,
                    p.paid_at,

                    s.name AS service_name,
                    s.duration_days,

                    sub.status AS subscription_status,

                    c.code AS currency_code,
                    c.symbol AS currency_symbol,
                    c.decimal_places

                FROM payments p

                INNER JOIN services s
                    ON s.id = p.service_id

                LEFT JOIN subscriptions sub
                    ON sub.id = p.subscription_id

                LEFT JOIN currencies c
                    ON c.id = p.currency_id

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
                    p.phone_number,
                    p.checkout_reference,
                    p.paid_at,

                    s.name AS service_name,
                    s.duration_days,

                    sub.status AS subscription_status,

                    c.code AS currency_code,
                    c.symbol AS currency_symbol,
                    c.decimal_places

                FROM payments p

                INNER JOIN services s
                    ON s.id = p.service_id

                LEFT JOIN subscriptions sub
                    ON sub.id = p.subscription_id

                LEFT JOIN currencies c
                    ON c.id = p.currency_id

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
        '[LOVEMI INITIATE PAYMENT QUERY] '
        .
        $e->getMessage()
    );

    paymentInitiateResponse(
        false,
        'Unable to load the payment order.',
        [],
        500
    );
}


/* ============================================================
   PAYMENT EXISTS
============================================================ */

if (!$payment) {

    paymentInitiateResponse(
        false,
        'Payment order not found.',
        [
            'code' => 'PAYMENT_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   CURRENT STATUS
============================================================ */

if (
    $payment['status'] === 'paid'
) {

    paymentInitiateResponse(
        true,
        'This payment has already been completed.',
        [
            'code' =>
                'PAYMENT_ALREADY_PAID',

            'payment_id' =>
                (int)
                $payment['id'],

            'subscription_id' =>
                $payment['subscription_id'] !== null
                    ?
                    (int)
                    $payment['subscription_id']
                    :
                    null,

            'status' =>
                'paid',

            'redirect' =>
                'premium.html'
        ]
    );
}


if (
    $payment['status'] === 'failed'
) {

    paymentInitiateResponse(
        false,
        'This payment has already failed. Please create a new Premium payment order.',
        [
            'code' =>
                'PAYMENT_ALREADY_FAILED'
        ],
        409
    );
}


/* ============================================================
   UPDATE PAYMENT METHOD
============================================================ */

try {

    $updateMethod =
        $pdo->prepare(
            "
            UPDATE payments

            SET

                payment_method = :payment_method,

                gateway =
                    CASE
                        WHEN :payment_method2 = 'mpesa'
                            THEN 'mpesa'
                        WHEN :payment_method3 = 'card'
                            THEN 'card'
                        WHEN :payment_method4 = 'paypal'
                            THEN 'paypal'
                        ELSE gateway
                    END

            WHERE id = :payment_id

              AND user_id = :user_id

              AND status = 'pending'

            LIMIT 1
            "
        );


    $updateMethod->execute(
        [
            ':payment_method' =>
                $paymentMethod,

            ':payment_method2' =>
                $paymentMethod,

            ':payment_method3' =>
                $paymentMethod,

            ':payment_method4' =>
                $paymentMethod,

            ':payment_id' =>
                (int)
                $payment['id'],

            ':user_id' =>
                $userId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI INITIATE METHOD UPDATE] '
        .
        $e->getMessage()
    );

    paymentInitiateResponse(
        false,
        'Unable to update the payment method.',
        [],
        500
    );
}


/* ============================================================
   M-PESA
============================================================ */

if (
    $paymentMethod === 'mpesa'
) {

    /*
     * M-Pesa is available only when credentials have been
     * configured on the server.
     *
     * NEVER place these values in JavaScript or HTML.
     */

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


    $callbackUrl =
        trim(
            (string)
            getenv('MPESA_CALLBACK_URL')
        );


    $baseUrl =
        trim(
            (string)
            getenv('MPESA_BASE_URL')
        );


    if ($baseUrl === '') {

        /*
         * Default sandbox URL.
         *
         * Production should be explicitly configured.
         */

        $baseUrl =
            'https://sandbox.safaricom.co.ke';

    }


    $callbackSecret =
        trim(
            (string)
            getenv('MPESA_CALLBACK_SECRET')
        );


    if (
        $consumerKey === ''
        ||
        $consumerSecret === ''
        ||
        $shortCode === ''
        ||
        $passKey === ''
        ||
        $callbackUrl === ''
        ||
        $callbackSecret === ''
    ) {

        paymentInitiateResponse(
            false,
            'M-Pesa is not configured on the server yet.',
            [
                'code' =>
                    'MPESA_CONFIGURATION_REQUIRED'
            ],
            503
        );
    }


    /*
     * The callback secret is appended to the callback URL.
     */

    $callbackUrlSeparator =
        str_contains(
            $callbackUrl,
            '?'
        )
            ? '&'
            : '?';


    $callbackUrl =
        $callbackUrl
        .
        $callbackUrlSeparator
        .
        'token='
        .
        rawurlencode(
            $callbackSecret
        );


    /* ========================================================
       PHONE
    ========================================================= */

    try {

        $phoneStmt =
            $pdo->prepare(
                "
                SELECT
                    phone_e164

                FROM users

                WHERE id = :user_id

                LIMIT 1
                "
            );


        $phoneStmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $phone =
            $phoneStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI MPESA PHONE QUERY] '
            .
            $e->getMessage()
        );

        paymentInitiateResponse(
            false,
            'Unable to load the payment phone number.',
            [],
            500
        );
    }


    if (
        !$phone
    ) {

        paymentInitiateResponse(
            false,
            'No verified phone number is available for M-Pesa payment.',
            [
                'code' =>
                    'PHONE_REQUIRED'
            ],
            422
        );
    }


    /*
     * Normalize to international format.
     */

    $phone =
        preg_replace(
            '/[^0-9+]/',
            '',
            (string)
            $phone
        );


    if (
        !str_starts_with(
            $phone,
            '+'
        )
    ) {

        if (
            str_starts_with(
                $phone,
                '0'
            )
        ) {

            $phone =
                '+254'
                .
                substr(
                    $phone,
                    1
                );

        } elseif (
            str_starts_with(
                $phone,
                '254'
            )
        ) {

            $phone =
                '+'
                .
                $phone;

        }

    }


    $phoneDigits =
        ltrim(
            $phone,
            '+'
        );


    if (
        !preg_match(
            '/^2547\d{8}$/',
            $phoneDigits
        )
    ) {

        paymentInitiateResponse(
            false,
            'The M-Pesa phone number is invalid.',
            [
                'code' =>
                    'INVALID_MPESA_PHONE'
            ],
            422
        );
    }


    /*
     * Save phone used for this payment.
     */

    try {

        $savePhone =
            $pdo->prepare(
                "
                UPDATE payments

                SET phone_number = :phone

                WHERE id = :payment_id

                LIMIT 1
                "
            );


        $savePhone->execute(
            [
                ':phone' =>
                    $phoneDigits,

                ':payment_id' =>
                    (int)
                    $payment['id']
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI MPESA PAYMENT PHONE] '
            .
            $e->getMessage()
        );
    }


    /* ========================================================
       TOKEN
    ========================================================= */

    $credentials =
        base64_encode(
            $consumerKey
            .
            ':'
            .
            $consumerSecret
        );


    $ch =
        curl_init(
            rtrim(
                $baseUrl,
                '/'
            )
            .
            '/oauth/v1/generate?grant_type=client_credentials'
        );


    curl_setopt_array(
        $ch,
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


    $tokenResponse =
        curl_exec(
            $ch
        );


    $tokenHttp =
        (int)
        curl_getinfo(
            $ch,
            CURLINFO_HTTP_CODE
        );


    $tokenCurlError =
        curl_error(
            $ch
        );


    curl_close(
        $ch
    );


    if (
        $tokenResponse === false
        ||
        $tokenCurlError !== ''
    ) {

        error_log(
            '[LOVEMI MPESA TOKEN CURL] '
            .
            $tokenCurlError
        );

        paymentInitiateResponse(
            false,
            'Unable to contact the M-Pesa authorization service.',
            [
                'code' =>
                    'MPESA_AUTH_CONNECTION_FAILED'
            ],
            502
        );
    }


    $tokenData =
        json_decode(
            $tokenResponse,
            true
        );


    $accessToken =
        is_array(
            $tokenData
        )
        ?
        (
            $tokenData['access_token']
            ??
            ''
        )
        :
        '';


    if (
        $tokenHttp < 200
        ||
        $tokenHttp >= 300
        ||
        $accessToken === ''
    ) {

        error_log(
            '[LOVEMI MPESA TOKEN RESPONSE] '
            .
            $tokenResponse
        );

        paymentInitiateResponse(
            false,
            'M-Pesa authorization failed.',
            [
                'code' =>
                    'MPESA_AUTH_FAILED'
            ],
            502
        );
    }


    /* ========================================================
       STK REQUEST
    ========================================================= */

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


    /*
     * The payment was created in USD/KES from the server.
     * M-Pesa is used for Kenyan payments, so expected currency
     * must be KES.
     */

    if (
        strtoupper(
            (string)
            $payment['currency_code']
        )
        !==
        'KES'
    ) {

        paymentInitiateResponse(
            false,
            'M-Pesa can only be used for a Kenyan KES payment.',
            [
                'code' =>
                    'MPESA_REQUIRES_KES'
            ],
            422
        );
    }


    $amount =
        (int)
        ceil(
            (float)
            $payment['amount_expected']
        );


    if (
        $amount <= 0
    ) {

        paymentInitiateResponse(
            false,
            'The payment amount is invalid.',
            [
                'code' =>
                    'INVALID_PAYMENT_AMOUNT'
            ],
            422
        );
    }


    $stkPayload = [

        'BusinessShortCode' =>
            $shortCode,

        'Password' =>
            $password,

        'Timestamp' =>
            $timestamp,

        'TransactionType' =>
            'CustomerPayBillOnline',

        'Amount' =>
            $amount,

        'PartyA' =>
            $phoneDigits,

        'PartyB' =>
            $shortCode,

        'PhoneNumber' =>
            $phoneDigits,

        'CallBackURL' =>
            $callbackUrl,

        'AccountReference' =>
            $payment['payment_reference'],

        'TransactionDesc' =>
            'LOVEMI Premium'

    ];


    $stkCh =
        curl_init(
            rtrim(
                $baseUrl,
                '/'
            )
            .
            '/mpesa/stkpush/v1/processrequest'
        );


    curl_setopt_array(
        $stkCh,
        [

            CURLOPT_RETURNTRANSFER =>
                true,

            CURLOPT_POST =>
                true,

            CURLOPT_POSTFIELDS =>
                json_encode(
                    $stkPayload
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


    $stkResponse =
        curl_exec(
            $stkCh
        );


    $stkHttp =
        (int)
        curl_getinfo(
            $stkCh,
            CURLINFO_HTTP_CODE
        );


    $stkCurlError =
        curl_error(
            $stkCh
        );


    curl_close(
        $stkCh
    );


    if (
        $stkResponse === false
        ||
        $stkCurlError !== ''
    ) {

        error_log(
            '[LOVEMI MPESA STK CURL] '
            .
            $stkCurlError
        );

        paymentInitiateResponse(
            false,
            'Unable to contact the M-Pesa payment service.',
            [
                'code' =>
                    'MPESA_STK_CONNECTION_FAILED'
            ],
            502
        );
    }


    $stkData =
        json_decode(
            $stkResponse,
            true
        );


    if (
        !is_array(
            $stkData
        )
    ) {

        error_log(
            '[LOVEMI MPESA STK INVALID] '
            .
            $stkResponse
        );

        paymentInitiateResponse(
            false,
            'The M-Pesa service returned an invalid response.',
            [
                'code' =>
                    'MPESA_INVALID_RESPONSE'
            ],
            502
        );
    }


    $responseCode =
        (string)
        (
            $stkData['ResponseCode']
            ??
            ''
        );


    if (
        $stkHttp < 200
        ||
        $stkHttp >= 300
        ||
        $responseCode !== '0'
    ) {

        error_log(
            '[LOVEMI MPESA STK ERROR] '
            .
            $stkResponse
        );

        paymentInitiateResponse(
            false,
            (
                $stkData['ResponseDescription']
                ??
                'M-Pesa payment request could not be started.'
            ),
            [
                'code' =>
                    'MPESA_STK_FAILED'
            ],
            502
        );
    }


    $checkoutRequestId =
        (string)
        (
            $stkData['CheckoutRequestID']
            ??
            ''
        );


    $merchantRequestId =
        (string)
        (
            $stkData['MerchantRequestID']
            ??
            ''
        );


    if (
        $checkoutRequestId === ''
    ) {

        paymentInitiateResponse(
            false,
            'M-Pesa did not return a checkout request ID.',
            [
                'code' =>
                    'MPESA_CHECKOUT_REFERENCE_MISSING'
            ],
            502
        );
    }


    /* ========================================================
       SAVE GATEWAY REFERENCES
    ========================================================= */

    try {

        $saveGateway =
            $pdo->prepare(
                "
                UPDATE payments

                SET

                    gateway = 'mpesa',

                    payment_method = 'mpesa',

                    checkout_reference = :checkout_reference

                WHERE id = :payment_id

                  AND user_id = :user_id

                  AND status = 'pending'

                LIMIT 1
                "
            );


        $saveGateway->execute(
            [
                ':checkout_reference' =>
                    $checkoutRequestId,

                ':payment_id' =>
                    (int)
                    $payment['id'],

                ':user_id' =>
                    $userId
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI MPESA SAVE REFERENCE] '
            .
            $e->getMessage()
        );

        paymentInitiateResponse(
            false,
            'The payment request started, but the reference could not be saved.',
            [
                'code' =>
                    'PAYMENT_REFERENCE_SAVE_FAILED'
            ],
            500
        );
    }


    paymentInitiateResponse(
        true,
        'M-Pesa payment request sent. Complete the payment on your phone.',
        [

            'code' =>
                'MPESA_STK_SENT',

            'payment_id' =>
                (int)
                $payment['id'],

            'payment_reference' =>
                (string)
                $payment['payment_reference'],

            'checkout_request_id' =>
                $checkoutRequestId,

            'merchant_request_id' =>
                $merchantRequestId,

            'currency' =>
                (string)
                $payment['currency_code'],

            'amount' =>
                $amount,

            'status' =>
                'pending'

        ]
    );
}


/* ============================================================
   CARD
============================================================ */

if (
    $paymentMethod === 'card'
) {

    /*
     * We deliberately do not collect or store raw card numbers
     * in LOVEMI. Card processing must be handled by a PCI-compliant
     * hosted payment provider.
     *
     * Gateway credentials/integration will be configured in:
     * services/payment/card.php
     */

    paymentInitiateResponse(
        false,
        'Card payments are not configured yet. The payment order is safely stored as pending.',
        [
            'code' =>
                'CARD_GATEWAY_NOT_CONFIGURED'
        ],
        503
    );
}


/* ============================================================
   PAYPAL
============================================================ */

if (
    $paymentMethod === 'paypal'
) {

    paymentInitiateResponse(
        false,
        'PayPal payments are not configured yet. The payment order is safely stored as pending.',
        [
            'code' =>
                'PAYPAL_GATEWAY_NOT_CONFIGURED'
        ],
        503
    );
}


/* ============================================================
   FALLBACK
============================================================ */

paymentInitiateResponse(
    false,
    'Unable to determine the payment gateway.',
    [
        'code' =>
            'GATEWAY_NOT_DETERMINED'
    ],
    500
);