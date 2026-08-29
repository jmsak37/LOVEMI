<?php
/**
 * ============================================================
 * LOVEMI - PREMIUM SUBSCRIBE API
 * ============================================================
 *
 * Creates a pending Premium subscription + pending payment.
 *
 * IMPORTANT:
 *
 * This endpoint NEVER marks the subscription as paid/active.
 * The payment gateway callback/verification endpoint must do
 * that after the payment provider confirms payment.
 *
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

function subscribeResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    subscribeResponse(
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
   AUTHENTICATION
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

    subscribeResponse(
        false,
        'Please log in before subscribing to Premium.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=premium.html'
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
        $raw ?: '{}',
        true
    );


if (
    !is_array($input)
) {

    $input = [];

}


$serviceId =
    isset(
        $input['service_id']
    )
        ? (int)
          $input['service_id']
        : 0;


$requestedPaymentMethod =
    strtolower(
        trim(
            (string)(
                $input['payment_method']
                ?? ''
            )
        )
    );


/*
 * We do not trust the client's amount or currency.
 */

if (
    $serviceId <= 0
) {

    subscribeResponse(
        false,
        'Please select a valid Premium service.',
        [
            'code' =>
                'INVALID_SERVICE'
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
        '[LOVEMI SUBSCRIBE DB] ' .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to connect to the database.',
        [],
        500
    );
}


/* ============================================================
   USER + COUNTRY
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted,

                c.id AS country_id,
                c.iso2 AS country_iso2,
                c.name AS country_name

            FROM users u

            LEFT JOIN countries c
                ON c.id = u.country_id

            WHERE u.id = :user_id

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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUBSCRIBE USER QUERY] ' .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to load your account.',
        [],
        500
    );
}


if (
    !$user
) {

    subscribeResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    !(bool)
    $user['email_verified']
) {

    subscribeResponse(
        false,
        'Please complete your email verification first.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED',

            'redirect' =>
                'verify-account.html?user=' .
                rawurlencode(
                    (string)
                    $userId
                )
        ],
        403
    );
}


if (
    !(bool)$user['is_active']
    ||
    (bool)$user['is_suspended']
    ||
    (bool)$user['is_deleted']
) {

    subscribeResponse(
        false,
        'Your account is currently unavailable.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   SERVICE
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
                service_type,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium,
                is_active

            FROM services

            WHERE id = :service_id

              AND is_active = TRUE

              AND is_premium = TRUE

            LIMIT 1
            "
        );


    $serviceStmt->execute(
        [
            ':service_id' =>
                $serviceId
        ]
    );


    $service =
        $serviceStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICE QUERY] '
        .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to load the selected Premium service.',
        [],
        500
    );
}


if (
    !$service
) {

    subscribeResponse(
        false,
        'The selected Premium service is unavailable.',
        [
            'code' =>
                'SERVICE_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   CHECK ACTIVE PREMIUM
============================================================ */

try {

    $activeStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                end_at

            FROM subscriptions

            WHERE user_id = :user_id

              AND status = 'active'

              AND start_at <= CURRENT_TIMESTAMP

              AND end_at > CURRENT_TIMESTAMP

            ORDER BY end_at DESC

            LIMIT 1
            "
        );


    $activeStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $active =
        $activeStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ACTIVE SUBSCRIPTION QUERY] '
        .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to check your existing Premium status.',
        [],
        500
    );
}


if (
    $active
) {

    subscribeResponse(
        false,
        'You already have an active Premium subscription.',
        [
            'code' =>
                'PREMIUM_ALREADY_ACTIVE',

            'subscription_id' =>
                (int)
                $active['id'],

            'end_at' =>
                $active['end_at'],

            'redirect' =>
                'premium.html'
        ],
        409
    );
}


/* ============================================================
   CHECK PENDING PAYMENT/SUBSCRIPTION
============================================================ */

try {

    $pendingStmt =
        $pdo->prepare(
            "
            SELECT

                s.id AS subscription_id,
                s.status AS subscription_status,

                p.id AS payment_id,
                p.payment_reference,
                p.status AS payment_status

            FROM subscriptions s

            LEFT JOIN payments p
                ON p.id = s.payment_id

            WHERE s.user_id = :user_id

              AND s.service_id = :service_id

              AND s.status = 'pending'

            ORDER BY s.created_at DESC

            LIMIT 1
            "
        );


    $pendingStmt->execute(
        [
            ':user_id' =>
                $userId,

            ':service_id' =>
                $serviceId
        ]
    );


    $pending =
        $pendingStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PENDING SUBSCRIPTION QUERY] '
        .
        $e->getMessage()
    );

    $pending =
        false;
}


if (
    $pending
) {

    subscribeResponse(
        true,
        'A Premium payment is already awaiting completion.',
        [
            'code' =>
                'PENDING_PAYMENT_EXISTS',

            'subscription_id' =>
                (int)
                $pending['subscription_id'],

            'payment_id' =>
                $pending['payment_id'] !== null
                    ?
                    (int)
                    $pending['payment_id']
                    :
                    null,

            'payment_reference' =>
                $pending['payment_reference'],

            'payment_status' =>
                $pending['payment_status'],

            'redirect' =>
                'payments.html?payment_id='
                .
                rawurlencode(
                    (string)
                    (
                        $pending['payment_id']
                        ?? ''
                    )
                )
        ],
        200
    );
}


/* ============================================================
   CURRENCY
============================================================ */

$countryIso =
    strtoupper(
        trim(
            (string)
            (
                $user['country_iso2']
                ??
                ''
            )
        )
    );


$targetCurrency =
    $countryIso === 'KE'
        ?
        'KES'
        :
        'USD';


try {

    $currencyStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                code,
                name,
                symbol,
                decimal_places

            FROM currencies

            WHERE code = :code

              AND is_active = TRUE

            LIMIT 1
            "
        );


    $currencyStmt->execute(
        [
            ':code' =>
                $targetCurrency
        ]
    );


    $currency =
        $currencyStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUBSCRIBE CURRENCY QUERY] '
        .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to determine your payment currency.',
        [],
        500
    );
}


if (
    !$currency
) {

    subscribeResponse(
        false,
        'The payment currency is not configured.',
        [
            'code' =>
                'CURRENCY_NOT_FOUND'
        ],
        500
    );
}


/* ============================================================
   EXCHANGE RATE
============================================================ */

$baseAmountUsd =
    (float)
    $service['base_price_usd'];


$exchangeRate =
    1.0;


if (
    $targetCurrency !== 'USD'
) {

    try {

        $rateStmt =
            $pdo->prepare(
                "
                SELECT

                    er.rate,
                    er.effective_at,
                    er.source

                FROM exchange_rates er

                INNER JOIN currencies base
                    ON base.id =
                       er.base_currency_id

                INNER JOIN currencies target
                    ON target.id =
                       er.target_currency_id

                WHERE base.code = 'USD'

                  AND target.code = :target

                  AND er.is_active = TRUE

                ORDER BY
                    er.effective_at DESC,
                    er.id DESC

                LIMIT 1
                "
            );


        $rateStmt->execute(
            [
                ':target' =>
                    $targetCurrency
            ]
        );


        $rate =
            $rateStmt->fetch();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI SUBSCRIBE RATE QUERY] '
            .
            $e->getMessage()
        );

        $rate =
            false;
    }


    if (
        !$rate
        ||
        (float)$rate['rate'] <= 0
    ) {

        subscribeResponse(
            false,
            'The current exchange rate is unavailable.',
            [
                'code' =>
                    'EXCHANGE_RATE_UNAVAILABLE'
            ],
            503
        );
    }


    $exchangeRate =
        (float)
        $rate['rate'];

}


$amountExpected =
    $baseAmountUsd
    *
    $exchangeRate;


$decimalPlaces =
    (int)
    $currency['decimal_places'];


if (
    $decimalPlaces < 0
    ||
    $decimalPlaces > 6
) {

    $decimalPlaces =
        2;

}


/* ============================================================
   PAYMENT REFERENCE
============================================================ */

try {

    $randomPart =
        strtoupper(
            bin2hex(
                random_bytes(
                    5
                )
            )
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PAYMENT RANDOM] '
        .
        $e->getMessage()
    );

    subscribeResponse(
        false,
        'Unable to create a payment reference.',
        [],
        500
    );
}


$paymentReference =
    'LVM-'
    .
    date('YmdHis')
    .
    '-'
    .
    $userId
    .
    '-'
    .
    $randomPart;


/* ============================================================
   SELECT DEFAULT PAYMENT GATEWAY
============================================================ */

$gateway =
    'pending';


$paymentMethod =
    $requestedPaymentMethod !== ''
        ?
        $requestedPaymentMethod
        :
        'pending';


$allowedMethods = [

    'mpesa',
    'card',
    'paypal',
    'pending'

];


if (
    !in_array(
        $paymentMethod,
        $allowedMethods,
        true
    )
) {

    subscribeResponse(
        false,
        'Unsupported payment method.',
        [
            'code' =>
                'INVALID_PAYMENT_METHOD'
        ],
        422
    );
}


/* ============================================================
   CREATE PAYMENT + SUBSCRIPTION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Create payment first.
     */

    $paymentStmt =
        $pdo->prepare(
            "
            INSERT INTO payments
            (
                user_id,
                service_id,
                payment_reference,
                gateway,
                payment_method,
                status,
                currency_id,
                base_amount_usd,
                exchange_rate,
                amount_expected,
                amount_paid
            )
            VALUES
            (
                :user_id,
                :service_id,
                :payment_reference,
                :gateway,
                :payment_method,
                'pending',
                :currency_id,
                :base_amount_usd,
                :exchange_rate,
                :amount_expected,
                0.0000
            )
            "
        );


    $paymentStmt->execute(
        [
            ':user_id' =>
                $userId,

            ':service_id' =>
                $serviceId,

            ':payment_reference' =>
                $paymentReference,

            ':gateway' =>
                $gateway,

            ':payment_method' =>
                $paymentMethod,

            ':currency_id' =>
                (int)
                $currency['id'],

            ':base_amount_usd' =>
                $baseAmountUsd,

            ':exchange_rate' =>
                $exchangeRate,

            ':amount_expected' =>
                $amountExpected
        ]
    );


    $paymentId =
        (int)
        $pdo->lastInsertId();


    /*
     * Create pending subscription.
     *
     * No start/end dates yet because payment has not been
     * confirmed.
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
        $service['max_usage'] !== null
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
                $serviceId,

            ':base_amount_usd' =>
                $baseAmountUsd,

            ':currency_id' =>
                (int)
                $currency['id'],

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
     * Link subscription back to payment.
     */

    $linkStmt =
        $pdo->prepare(
            "
            UPDATE payments

            SET subscription_id = :subscription_id

            WHERE id = :payment_id

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


    /*
     * Audit.
     */

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
                    'premium_subscription_created',
                    'subscription',
                    :entity_id,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $auditStmt->execute(
            [
                ':user_id' =>
                    $userId,

                ':entity_id' =>
                    $subscriptionId,

                ':new_values' =>
                    json_encode(
                        [
                            'service_id' =>
                                $serviceId,

                            'payment_id' =>
                                $paymentId,

                            'status' =>
                                'pending'
                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null
            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI PREMIUM AUDIT] '
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
        '[LOVEMI PREMIUM SUBSCRIBE] '
        .
        $e->getMessage()
    );


    subscribeResponse(
        false,
        'The Premium subscription request could not be created.',
        [
            'code' =>
                'SUBSCRIPTION_CREATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

subscribeResponse(
    true,
    'Your Premium order has been created. Continue to payment.',
    [

        'status' =>
            'pending',

        'service_id' =>
            $serviceId,

        'service_name' =>
            (string)
            $service['name'],

        'subscription_id' =>
            $subscriptionId,

        'payment_id' =>
            $paymentId,

        'payment_reference' =>
            $paymentReference,

        'currency' =>
            (string)
            $currency['code'],

        'currency_symbol' =>
            (string)
            $currency['symbol'],

        'base_amount_usd' =>
            number_format(
                $baseAmountUsd,
                2,
                '.',
                ''
            ),

        'exchange_rate' =>
            number_format(
                $exchangeRate,
                10,
                '.',
                ''
            ),

        'amount_expected' =>
            number_format(
                $amountExpected,
                $decimalPlaces,
                '.',
                ''
            ),

        'duration_days' =>
            (int)
            $service['duration_days'],

        'redirect' =>
            'payments.html?payment_id='
            .
            $paymentId

    ],
    201
);