<?php
/**
 * ============================================================
 * LOVEMI - M-PESA CALLBACK API
 * ============================================================
 *
 * Receives M-Pesa STK callback information.
 *
 * SECURITY:
 *   A callback secret is required.
 *
 * IMPORTANT:
 *   Never trust a front-end request to mark payment as paid.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');


/* ============================================================
   RESPONSE
============================================================ */

function callbackResponse(
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'ResultCode' => 0,
                'ResultDesc' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   CALLBACK SECRET
============================================================ */

$configuredSecret =
    trim(
        (string)
        getenv('MPESA_CALLBACK_SECRET')
    );


$providedSecret =
    trim(
        (string)
        (
            $_GET['token']
            ??
            ''
        )
    );


if (
    $configuredSecret === ''
    ||
    $providedSecret === ''
    ||
    !hash_equals(
        $configuredSecret,
        $providedSecret
    )
) {

    http_response_code(403);

    echo json_encode(
        [
            'ResultCode' =>
                1,

            'ResultDesc' =>
                'Unauthorized callback.'
        ]
    );

    exit;
}


/* ============================================================
   POST BODY
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


if (
    trim(
        (string)
        $rawBody
    ) === ''
) {

    callbackResponse(
        'Empty callback received.',
        [],
        400
    );
}


$payload =
    json_decode(
        (string)
        $rawBody,
        true
    );


if (
    !is_array(
        $payload
    )
) {

    callbackResponse(
        'Invalid JSON callback.',
        [],
        400
    );
}


/* ============================================================
   EXTRACT STK CALLBACK
============================================================ */

$stkCallback =
    $payload['Body']['stkCallback']
    ??
    null;


if (
    !is_array(
        $stkCallback
    )
) {

    callbackResponse(
        'Invalid STK callback payload.',
        [],
        400
    );
}


$merchantRequestId =
    (string)
    (
        $stkCallback['MerchantRequestID']
        ??
        ''
    );


$checkoutRequestId =
    (string)
    (
        $stkCallback['CheckoutRequestID']
        ??
        ''
    );


$resultCode =
    (int)
    (
        $stkCallback['ResultCode']
        ??
        -1
    );


$resultDescription =
    (string)
    (
        $stkCallback['ResultDesc']
        ??
        ''
    );


if (
    $checkoutRequestId === ''
) {

    callbackResponse(
        'Checkout request reference missing.',
        [],
        400
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
        '[LOVEMI CALLBACK DB] '
        .
        $e->getMessage()
    );

    callbackResponse(
        'Database unavailable.',
        [],
        500
    );
}


/* ============================================================
   FIND PAYMENT
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
                p.status,
                p.currency_id,
                p.base_amount_usd,
                p.exchange_rate,
                p.amount_expected,
                p.amount_paid,
                p.checkout_reference,

                s.name AS service_name,
                s.duration_days,

                sub.status AS subscription_status

            FROM payments p

            INNER JOIN services s
                ON s.id = p.service_id

            LEFT JOIN subscriptions sub
                ON sub.id = p.subscription_id

            WHERE p.checkout_reference = :checkout_reference

            LIMIT 1
            "
        );


    $paymentStmt->execute(
        [
            ':checkout_reference' =>
                $checkoutRequestId
        ]
    );


    $payment =
        $paymentStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CALLBACK PAYMENT QUERY] '
        .
        $e->getMessage()
    );

    callbackResponse(
        'Payment could not be located.',
        [],
        500
    );
}


if (
    !$payment
) {

    error_log(
        '[LOVEMI CALLBACK UNKNOWN CHECKOUT] '
        .
        $checkoutRequestId
    );

    callbackResponse(
        'Payment not found.',
        [],
        404
    );
}


/* ============================================================
   ALREADY PAID
============================================================ */

if (
    $payment['status'] === 'paid'
) {

    callbackResponse(
        'Payment was already processed.'
    );
}


/* ============================================================
   FAILED / CANCELLED
============================================================ */

if (
    $resultCode !== 0
) {

    try {

        $failedStmt =
            $pdo->prepare(
                "
                UPDATE payments

                SET

                    status = 'failed',

                    gateway = 'mpesa',

                    payment_method = 'mpesa',

                    checkout_reference =
                        :checkout_reference

                WHERE id = :payment_id

                  AND status <> 'paid'

                LIMIT 1
                "
            );


        $failedStmt->execute(
            [
                ':checkout_reference' =>
                    $checkoutRequestId,

                ':payment_id' =>
                    (int)
                    $payment['id']
            ]
        );


        /*
         * Keep pending subscription from becoming active.
         */

        if (
            !empty(
                $payment['subscription_id']
            )
        ) {

            $subFailed =
                $pdo->prepare(
                    "
                    UPDATE subscriptions

                    SET status = 'failed'

                    WHERE id = :subscription_id

                      AND status = 'pending'

                    LIMIT 1
                    "
                );


            $subFailed->execute(
                [
                    ':subscription_id' =>
                        (int)
                        $payment['subscription_id']
                ]
            );

        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CALLBACK FAILED UPDATE] '
            .
            $e->getMessage()
        );

    }


    callbackResponse(
        'Payment was not completed. ' .
        $resultDescription
    );
}


/* ============================================================
   CALLBACK METADATA
============================================================ */

$metadataItems =
    $stkCallback['CallbackMetadata']['Item']
    ??
    [];


if (
    !is_array(
        $metadataItems
    )
) {

    $metadataItems = [];

}


$metadata = [];


foreach (
    $metadataItems
    as $item
) {

    if (
        !is_array($item)
    ) {

        continue;

    }


    $name =
        (string)
        (
            $item['Name']
            ??
            ''
        );


    if (
        $name === ''
    ) {

        continue;

    }


    $metadata[$name] =
        $item['Value']
        ??
        null;

}


/* ============================================================
   PAYMENT DATA
============================================================ */

$mpesaAmount =
    isset(
        $metadata['Amount']
    )
        ? (float)
          $metadata['Amount']
        : 0.0;


$mpesaReceipt =
    trim(
        (string)
        (
            $metadata['MpesaReceiptNumber']
            ??
            ''
        )
    );


$transactionDate =
    isset(
        $metadata['TransactionDate']
    )
        ?
        (string)
        $metadata['TransactionDate']
        :
        null;


$phoneNumber =
    isset(
        $metadata['PhoneNumber']
    )
        ?
        (string)
        $metadata['PhoneNumber']
        :
        null;


/* ============================================================
   TRANSACTION ID
============================================================ */

$gatewayTransactionId =
    $mpesaReceipt !== ''
        ?
        $mpesaReceipt
        :
        $checkoutRequestId;


/* ============================================================
   RECEIPT NUMBER
============================================================ */

$receiptNumber =
    $mpesaReceipt;


if (
    $receiptNumber === ''
) {

    $receiptNumber =
        'LVM-'
        .
        date('YmdHis')
        .
        '-'
        .
        (int)
        $payment['id'];

}


/* ============================================================
   ACTIVATE PAYMENT
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Lock payment while processing callback.
     */

    $lockStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                service_id,
                subscription_id,
                status,
                amount_expected,
                amount_paid

            FROM payments

            WHERE id = :id

            FOR UPDATE
            "
        );


    $lockStmt->execute(
        [
            ':id' =>
                (int)
                $payment['id']
        ]
    );


    $lockedPayment =
        $lockStmt->fetch();


    if (
        !$lockedPayment
    ) {

        throw new RuntimeException(
            'Payment disappeared during callback processing.'
        );

    }


    if (
        $lockedPayment['status'] === 'paid'
    ) {

        $pdo->commit();

        callbackResponse(
            'Payment was already processed.'
        );

    }


    /*
     * Amount validation.
     *
     * For KES payments compare the callback amount with the
     * amount expected by LOVEMI.
     */

    $expectedAmount =
        (float)
        $lockedPayment['amount_expected'];


    if (
        $mpesaAmount > 0
        &&
        abs(
            $mpesaAmount
            -
            $expectedAmount
        ) > 1.0
    ) {

        throw new RuntimeException(
            'Payment amount does not match the expected amount.'
        );

    }


    /* ========================================================
       UPDATE PAYMENT
    ====================================================== */

    $paymentUpdate =
        $pdo->prepare(
            "
            UPDATE payments

            SET

                gateway = 'mpesa',

                payment_method = 'mpesa',

                status = 'paid',

                gateway_transaction_id =
                    :gateway_transaction_id,

                amount_paid =
                    :amount_paid,

                phone_number =
                    COALESCE(
                        :phone_number,
                        phone_number
                    ),

                paid_at =
                    CURRENT_TIMESTAMP

            WHERE id = :payment_id

              AND status <> 'paid'

            LIMIT 1
            "
        );


    $paymentUpdate->execute(
        [
            ':gateway_transaction_id' =>
                $gatewayTransactionId,

            ':amount_paid' =>
                $mpesaAmount > 0
                    ?
                    $mpesaAmount
                    :
                    $expectedAmount,

            ':phone_number' =>
                $phoneNumber,

            ':payment_id' =>
                (int)
                $payment['id']
        ]
    );


    /* ========================================================
       SUBSCRIPTION
    ====================================================== */

    if (
        empty(
            $lockedPayment['subscription_id']
        )
    ) {

        throw new RuntimeException(
            'Paid payment does not have a linked subscription.'
        );

    }


    /*
     * Fetch service duration.
     */

    $durationStmt =
        $pdo->prepare(
            "
            SELECT

                duration_days,
                max_usage

            FROM services

            WHERE id = :service_id

            LIMIT 1
            "
        );


    $durationStmt->execute(
        [
            ':service_id' =>
                (int)
                $lockedPayment['service_id']
        ]
    );


    $service =
        $durationStmt->fetch();


    if (
        !$service
    ) {

        throw new RuntimeException(
            'Premium service not found.'
        );

    }


    $durationDays =
        max(
            1,
            (int)
            $service['duration_days']
        );


    /*
     * Start immediately after confirmed payment.
     */

    $startSql =
        date(
            'Y-m-d H:i:s'
        );


    $endSql =
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


    $subscriptionUpdate =
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

            WHERE id = :subscription_id

              AND status IN
                ('pending','failed')

            LIMIT 1
            "
        );


    $subscriptionUpdate->execute(
        [

            ':start_at' =>
                $startSql,

            ':end_at' =>
                $endSql,

            ':amount_paid' =>
                $mpesaAmount > 0
                    ?
                    $mpesaAmount
                    :
                    $expectedAmount,

            ':payment_id' =>
                (int)
                $lockedPayment['id'],

            ':subscription_id' =>
                (int)
                $lockedPayment['subscription_id']

        ]
    );


    if (
        $subscriptionUpdate->rowCount() < 1
    ) {

        /*
         * It may already be active.
         */

        $checkSubscription =
            $pdo->prepare(
                "
                SELECT status

                FROM subscriptions

                WHERE id = :id

                LIMIT 1
                "
            );


        $checkSubscription->execute(
            [
                ':id' =>
                    (int)
                    $lockedPayment['subscription_id']
            ]
        );


        $subStatus =
            $checkSubscription->fetchColumn();


        if (
            $subStatus !== 'active'
        ) {

            throw new RuntimeException(
                'Premium subscription could not be activated.'
            );

        }

    }


    /* ========================================================
       RECEIPT RECORD
    ====================================================== */

    try {

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
                    (int)
                    $lockedPayment['id'],

                ':receipt_number' =>
                    $receiptNumber
            ]
        );

    } catch (Throwable $receiptError) {

        /*
         * Receipt record should not make a successfully confirmed
         * payment disappear. Log and continue.
         */

        error_log(
            '[LOVEMI RECEIPT RECORD] '
            .
            $receiptError->getMessage()
        );

    }


    /* ========================================================
       AUDIT
    ====================================================== */

    try {

        $auditStmt =
            $pdo->prepare(
                "
                INSERT INTO audit_logs
                (
                    user_id,
                    action,
                    entity_type,
                    entity_id,
                    new_values,
                    ip_address,
                    user_agent
                )
                VALUES
                (
                    :user_id,
                    'payment_confirmed',
                    'payment',
                    :entity_id,
                    :new_values,
                    NULL,
                    'M-Pesa callback'
                )
                "
            );


        $auditStmt->execute(
            [

                ':user_id' =>
                    (int)
                    $lockedPayment['user_id'],

                ':entity_id' =>
                    (int)
                    $lockedPayment['id'],

                ':new_values' =>
                    json_encode(
                        [
                            'gateway' =>
                                'mpesa',

                            'transaction_id' =>
                                $gatewayTransactionId,

                            'receipt_number' =>
                                $receiptNumber,

                            'status' =>
                                'paid'

                        ],
                        JSON_UNESCAPED_UNICODE
                    )

            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI PAYMENT AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CALLBACK ERROR] '
        .
        $e->getMessage()
    );


    callbackResponse(
        'Payment processing failed.',
        [],
        500
    );
}


/* ============================================================
   SUCCESS
============================================================ */

callbackResponse(
    'Payment successfully confirmed and Premium activated.'
);