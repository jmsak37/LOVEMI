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

function premiumRenewResponse(
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

    premiumRenewResponse(
        false,
        'Only POST requests are allowed.',
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

    premiumRenewResponse(
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

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $raw,
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$currencyId =
    isset(
        $input['currency_id']
    )
        ?
        (int)
        $input['currency_id']
        :
        0;


$paymentMethod =
    trim(
        (string)
        (
            $input['payment_method']
            ??
            ''
        )
    );


$phoneNumber =
    trim(
        (string)
        (
            $input['phone_number']
            ??
            ''
        )
    );


if (
    $currencyId <= 0
) {

    premiumRenewResponse(
        false,
        'Currency ID is required.',
        [
            'code' =>
                'CURRENCY_ID_REQUIRED'
        ],
        422
    );
}


if (
    $paymentMethod === ''
) {

    premiumRenewResponse(
        false,
        'Payment method is required.',
        [
            'code' =>
                'PAYMENT_METHOD_REQUIRED'
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
        '[LOVEMI PREMIUM RENEW DB] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
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
   LOAD USER
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                country_id,
                email_verified,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM RENEW USER] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
        false,
        'Unable to verify your account.',
        [
            'code' =>
                'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$user
) {

    premiumRenewResponse(
        false,
        'Account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    premiumRenewResponse(
        false,
        'Your account has been deleted.',
        [
            'code' =>
                'ACCOUNT_DELETED'
        ],
        403
    );
}


if (
    (int)
    $user['is_suspended']
    ===
    1
) {

    premiumRenewResponse(
        false,
        'Your account is suspended.',
        [
            'code' =>
                'ACCOUNT_SUSPENDED'
        ],
        403
    );
}


if (
    (int)
    $user['is_active']
    !==
    1
) {

    premiumRenewResponse(
        false,
        'Your account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );
}


if (
    (int)
    $user['email_verified']
    !==
    1
) {

    premiumRenewResponse(
        false,
        'Please verify your email before purchasing Premium.',
        [
            'code' =>
                'EMAIL_VERIFICATION_REQUIRED',

            'redirect' =>
                'verify-account.html'
        ],
        403
    );
}


/* ============================================================
   PREMIUM SERVICE
============================================================ */

try {

    $serviceStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                name,
                slug,
                description,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium,
                is_active

            FROM services

            WHERE slug =
                  'lovemi-premium'

              AND is_premium = 1

              AND is_active = 1

            LIMIT 1
            "
        );


    $serviceStmt->execute();


    $service =
        $serviceStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM SERVICE] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
        false,
        'Unable to load the Premium service.',
        [
            'code' =>
                'PREMIUM_SERVICE_FAILED'
        ],
        500
    );
}


if (
    !$service
) {

    premiumRenewResponse(
        false,
        'LOVEMI Premium is currently unavailable.',
        [
            'code' =>
                'PREMIUM_SERVICE_NOT_FOUND'
        ],
        503
    );
}


/* ============================================================
   CURRENCY
============================================================ */

try {

    $currencyStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                code,
                name,
                symbol,
                decimal_places,
                is_base,
                is_active

            FROM currencies

            WHERE id =
                  :currency_id

              AND is_active = 1

            LIMIT 1
            "
        );


    $currencyStmt->execute(
        [
            ':currency_id' =>
                $currencyId
        ]
    );


    $currency =
        $currencyStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM CURRENCY] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
        false,
        'Unable to load the selected currency.',
        [
            'code' =>
                'CURRENCY_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$currency
) {

    premiumRenewResponse(
        false,
        'The selected currency is not available.',
        [
            'code' =>
                'INVALID_CURRENCY'
        ],
        422
    );
}


/* ============================================================
   USD BASE
============================================================ */

$baseAmountUsd =
    round(
        (float)
        $service['base_price_usd'],
        2
    );


/* ============================================================
   EXCHANGE RATE
============================================================ */

$exchangeRate =
    null;


$amountExpected =
    $baseAmountUsd;


/*
|--------------------------------------------------------------------------
| USD does not need conversion.
|--------------------------------------------------------------------------
*/

if (
    strtoupper(
        $currency['code']
    )
    !==
    'USD'
) {

    /*
     * Find the most recent active USD → selected currency rate.
     */

    try {

        $rateStmt =
            $pdo->prepare(
                "
                SELECT

                    rate,
                    effective_at

                FROM exchange_rates er

                INNER JOIN currencies base
                    ON base.id =
                       er.base_currency_id

                INNER JOIN currencies target
                    ON target.id =
                       er.target_currency_id

                WHERE base.code =
                      'USD'

                  AND target.id =
                      :currency_id

                  AND er.is_active =
                      1

                ORDER BY

                    er.effective_at DESC,
                    er.id DESC

                LIMIT 1
                "
            );


        $rateStmt->execute(
            [
                ':currency_id' =>
                    $currencyId
            ]
        );


        $rateRow =
            $rateStmt->fetch();

    } catch (
        Throwable $e
    ) {

        $rateRow =
            false;

    }


    if (
        !$rateRow
    ) {

        premiumRenewResponse(
            false,
            'No current exchange rate is available for the selected currency.',
            [
                'code' =>
                    'EXCHANGE_RATE_NOT_FOUND'
            ],
            503
        );
    }


    $exchangeRate =
        (float)
        $rateRow['rate'];


    if (
        $exchangeRate <= 0
    ) {

        premiumRenewResponse(
            false,
            'The current exchange rate is invalid.',
            [
                'code' =>
                    'INVALID_EXCHANGE_RATE'
            ],
            503
        );
    }


    $amountExpected =
        $baseAmountUsd *
        $exchangeRate;

}


/* ============================================================
   ROUND CURRENCY
============================================================ */

$decimalPlaces =
    max(
        0,
        min(
            6,
            (int)
            $currency['decimal_places']
        )
    );


$amountExpected =
    round(
        $amountExpected,
        $decimalPlaces
    );


/* ============================================================
   CHECK EXISTING ACTIVE SUBSCRIPTION
============================================================ */

try {

    $activeStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                start_at,
                end_at

            FROM subscriptions

            WHERE user_id =
                  :user_id

              AND service_id =
                  :service_id

              AND status =
                  'active'

              AND end_at >
                  CURRENT_TIMESTAMP

            ORDER BY
                end_at DESC,
                id DESC

            LIMIT 1
            "
        );


    $activeStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':service_id' =>
                (int)
                $service['id']

        ]
    );


    $active =
        $activeStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM ACTIVE CHECK] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
        false,
        'Unable to check your current Premium subscription.',
        [
            'code' =>
                'ACTIVE_CHECK_FAILED'
        ],
        500
    );
}


/* ============================================================
   RENEWAL POLICY
============================================================ */

if (
    $active
) {

    premiumRenewResponse(
        false,
        'You already have an active Premium subscription.',
        [

            'code' =>
                'PREMIUM_ALREADY_ACTIVE',

            'subscription_id' =>
                (int)
                $active['id'],

            'start_at' =>
                $active['start_at'],

            'end_at' =>
                $active['end_at']

        ],
        409
    );
}


/* ============================================================
   AVOID DUPLICATE PENDING PAYMENTS
============================================================ */

try {

    $pendingStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                payment_reference,
                amount_expected,
                currency_id,
                created_at

            FROM payments

            WHERE user_id =
                  :user_id

              AND service_id =
                  :service_id

              AND status =
                  'pending'

              AND created_at >=
                  DATE_SUB(
                      CURRENT_TIMESTAMP,
                      INTERVAL 30 MINUTE
                  )

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $pendingStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':service_id' =>
                (int)
                $service['id']

        ]
    );


    $existingPending =
        $pendingStmt->fetch();

} catch (
    Throwable $e
) {

    $existingPending =
        false;

}


/*
|--------------------------------------------------------------------------
| Return an existing recent checkout instead of creating duplicates.
|--------------------------------------------------------------------------
*/

if (
    $existingPending
) {

    premiumRenewResponse(
        true,
        'A recent Premium payment is already waiting for completion.',
        [

            'checkout' => [

                'payment_id' =>
                    (int)
                    $existingPending['id'],

                'payment_reference' =>
                    $existingPending[
                        'payment_reference'
                    ],

                'amount_expected' =>
                    (float)
                    $existingPending[
                        'amount_expected'
                    ],

                'currency_id' =>
                    (int)
                    $existingPending[
                        'currency_id'
                    ],

                'created_at' =>
                    $existingPending[
                        'created_at'
                    ]

            ]

        ]
    );
}


/* ============================================================
   GENERATE REFERENCE
============================================================ */

try {

    $token =
        strtoupper(
            bin2hex(
                random_bytes(
                    7
                )
            )
        );

} catch (
    Throwable $e
) {

    premiumRenewResponse(
        false,
        'Unable to create a secure payment reference.',
        [
            'code' =>
                'REFERENCE_GENERATION_FAILED'
        ],
        500
    );
}


$paymentReference =
    'LM-PREM-' .
    date('YmdHis') .
    '-' .
    $token;


/* ============================================================
   CREATE PENDING PAYMENT + SUBSCRIPTION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | Payment
    |--------------------------------------------------------------------------
    */

    $paymentStmt =
        $pdo->prepare(
            "
            INSERT INTO payments
            (
                user_id,
                service_id,
                subscription_id,
                payment_reference,
                gateway,
                payment_method,
                status,
                currency_id,
                base_amount_usd,
                exchange_rate,
                amount_expected,
                amount_paid,
                gateway_fee,
                phone_number
            )
            VALUES
            (
                :user_id,
                :service_id,
                NULL,
                :payment_reference,
                'pending',
                :payment_method,
                'pending',
                :currency_id,
                :base_amount_usd,
                :exchange_rate,
                :amount_expected,
                0.0000,
                0.0000,
                :phone_number
            )
            "
        );


    $paymentStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':service_id' =>
                (int)
                $service['id'],

            ':payment_reference' =>
                $paymentReference,

            ':payment_method' =>
                $paymentMethod,

            ':currency_id' =>
                $currencyId,

            ':base_amount_usd' =>
                $baseAmountUsd,

            ':exchange_rate' =>
                $exchangeRate,

            ':amount_expected' =>
                $amountExpected,

            ':phone_number' =>
                $phoneNumber !== ''
                    ?
                    $phoneNumber
                    :
                    null

        ]
    );


    $paymentId =
        (int)
        $pdo->lastInsertId();


    /*
    |--------------------------------------------------------------------------
    | Pending subscription
    |--------------------------------------------------------------------------
    */

    $subscriptionStmt =
        $pdo->prepare(
            "
            INSERT INTO subscriptions
            (
                user_id,
                service_id,
                status,
                start_at,
                end_at,
                base_amount_usd,
                amount_paid,
                currency_id,
                exchange_rate,
                payment_id,
                usage_limit,
                usage_used
            )
            VALUES
            (
                :user_id,
                :service_id,
                'pending',
                NULL,
                NULL,
                :base_amount_usd,
                0.0000,
                :currency_id,
                :exchange_rate,
                :payment_id,
                :usage_limit,
                0
            )
            "
        );


    $usageLimit =
        $service['max_usage']
        !==
        null
            ?
            (int)
            $service['max_usage']
            :
            null;


    $subscriptionStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':service_id' =>
                (int)
                $service['id'],

            ':base_amount_usd' =>
                $baseAmountUsd,

            ':currency_id' =>
                $currencyId,

            ':exchange_rate' =>
                $exchangeRate,

            ':payment_id' =>
                $paymentId,

            ':usage_limit' =>
                $usageLimit

        ]
    );


    $subscriptionId =
        (int)
        $pdo->lastInsertId();


    /*
    |--------------------------------------------------------------------------
    | Link payment to subscription.
    |--------------------------------------------------------------------------
    */

    $linkStmt =
        $pdo->prepare(
            "
            UPDATE payments

            SET
                subscription_id =
                    :subscription_id

            WHERE id =
                :payment_id

            LIMIT 1
            "
        );


    $linkStmt->execute(
        [

            ':subscription_id' =>
                $subscriptionId,

            ':payment_id' =>
                $paymentId

        ]
    );


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI PREMIUM RENEW TRANSACTION] '
        .
        $e->getMessage()
    );


    premiumRenewResponse(
        false,
        'Unable to start Premium renewal.',
        [
            'code' =>
                'PREMIUM_RENEW_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

premiumRenewResponse(
    true,
    'Premium renewal checkout has been created.',
    [

        'checkout' => [

            'payment_id' =>
                $paymentId,

            'subscription_id' =>
                $subscriptionId,

            'payment_reference' =>
                $paymentReference,

            'service' => [

                'id' =>
                    (int)
                    $service['id'],

                'name' =>
                    $service['name'],

                'slug' =>
                    $service['slug'],

                'duration_days' =>
                    (int)
                    $service['duration_days']

            ],

            'amount' => [

                'base_usd' =>
                    $baseAmountUsd,

                'expected' =>
                    $amountExpected,

                'currency' =>
                    $currency['code'],

                'symbol' =>
                    $currency['symbol'],

                'exchange_rate' =>
                    $exchangeRate

            ],

            'payment_method' =>
                $paymentMethod,

            'status' =>
                'pending'

        ]

    ],
    201
);