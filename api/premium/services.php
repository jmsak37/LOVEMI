<?php
/**
 * ============================================================
 * LOVEMI - PREMIUM SERVICES API
 * ============================================================
 *
 * Returns active premium services and the current user's
 * calculated payment currency.
 *
 * Source of truth:
 *   services
 *   users
 *   countries
 *   currencies
 *   exchange_rates
 *   subscriptions
 *   system_settings
 *
 * No browser cache.
 * No hardcoded country list.
 * No hardcoded exchange rate.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   RESPONSE HEADERS
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
   RESPONSE FUNCTION
============================================================ */

function premiumServicesResponse(
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

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') {

    premiumServicesResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    premiumServicesResponse(
        false,
        'Please log in before viewing Premium services.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html?return=premium.html'
        ],
        401
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SERVICES DB] ' .
        $e->getMessage()
    );

    premiumServicesResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER + COUNTRY + CURRENCY
============================================================ */

try {

    $userStmt = $pdo->prepare(
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
            c.name AS country_name,
            c.iso2 AS country_iso2,
            c.phone_code,

            cur.id AS currency_id,
            cur.code AS currency_code,
            cur.name AS currency_name,
            cur.symbol AS currency_symbol,
            cur.decimal_places AS decimal_places

        FROM users u

        LEFT JOIN countries c
            ON c.id = u.country_id

        LEFT JOIN currencies cur
            ON cur.id = c.currency_id

        WHERE u.id = :user_id

        LIMIT 1
        "
    );


    $userStmt->execute(
        [
            ':user_id' => $userId
        ]
    );


    $user = $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM USER QUERY] ' .
        $e->getMessage()
    );

    premiumServicesResponse(
        false,
        'Unable to load your account information.',
        [
            'code' => 'USER_QUERY_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER VALIDATION
============================================================ */

if (!$user) {

    premiumServicesResponse(
        false,
        'Your account could not be found.',
        [
            'code' => 'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    !(bool) $user['email_verified']
) {

    premiumServicesResponse(
        false,
        'Please complete email verification before purchasing Premium.',
        [
            'code' => 'EMAIL_NOT_VERIFIED',
            'redirect' =>
                'verify-account.html?user=' .
                rawurlencode((string) $userId)
        ],
        403
    );
}


if (
    !(bool) $user['is_active']
    ||
    (bool) $user['is_suspended']
    ||
    (bool) $user['is_deleted']
) {

    premiumServicesResponse(
        false,
        'Your account is currently unavailable.',
        [
            'code' => 'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   DETERMINE CURRENCY
============================================================ */

/*
 * Requirement:
 *
 * Kenya       -> KES
 * Other       -> USD
 *
 * We determine this from the country record and its currency.
 */

$countryIso =
    strtoupper(
        trim(
            (string) (
                $user['country_iso2'] ?? ''
            )
        )
    );


$currencyCode =
    strtoupper(
        trim(
            (string) (
                $user['currency_code'] ?? ''
            )
        )
    );


$isKenya =
    (
        $countryIso === 'KE'
        ||
        $currencyCode === 'KES'
    );


if ($isKenya) {

    $displayCurrencyCode = 'KES';

} else {

    $displayCurrencyCode = 'USD';

}


/* ============================================================
   GET CURRENCY
============================================================ */

try {

    $currencyStmt = $pdo->prepare(
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
            ':code' => $displayCurrencyCode
        ]
    );


    $displayCurrency = $currencyStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM CURRENCY QUERY] ' .
        $e->getMessage()
    );

    premiumServicesResponse(
        false,
        'Unable to determine the payment currency.',
        [
            'code' => 'CURRENCY_QUERY_ERROR'
        ],
        500
    );
}


if (!$displayCurrency) {

    premiumServicesResponse(
        false,
        'The required payment currency is not configured.',
        [
            'code' => 'CURRENCY_NOT_CONFIGURED'
        ],
        500
    );
}


/* ============================================================
   PREMIUM SERVICES
============================================================ */

try {

    $serviceStmt = $pdo->prepare(
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
            is_active,
            sort_order

        FROM services

        WHERE is_active = TRUE

          AND is_premium = TRUE

        ORDER BY
            sort_order ASC,
            id ASC
        "
    );


    $serviceStmt->execute();


    $services = $serviceStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SERVICE QUERY] ' .
        $e->getMessage()
    );

    premiumServicesResponse(
        false,
        'Premium services could not be loaded.',
        [
            'code' => 'SERVICE_QUERY_ERROR'
        ],
        500
    );
}


/* ============================================================
   EXISTING PREMIUM
============================================================ */

try {

    $subscriptionStmt = $pdo->prepare(
        "
        SELECT

            s.id,
            s.service_id,
            s.status,
            s.start_at,
            s.end_at,
            s.base_amount_usd,
            s.amount_paid,
            s.currency_id,
            s.exchange_rate,
            s.usage_limit,
            s.usage_used,

            sv.name AS service_name

        FROM subscriptions s

        INNER JOIN services sv
            ON sv.id = s.service_id

        WHERE s.user_id = :user_id

          AND s.status = 'active'

          AND s.start_at <= CURRENT_TIMESTAMP

          AND s.end_at > CURRENT_TIMESTAMP

        ORDER BY
            s.end_at DESC

        LIMIT 1
        "
    );


    $subscriptionStmt->execute(
        [
            ':user_id' => $userId
        ]
    );


    $activeSubscription =
        $subscriptionStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI ACTIVE PREMIUM QUERY] ' .
        $e->getMessage()
    );

    $activeSubscription = false;
}


/* ============================================================
   LATEST USD -> LOCAL RATE
============================================================ */

$exchangeRate =
    1.0;


if (
    $displayCurrencyCode !== 'USD'
) {

    try {

        $rateStmt = $pdo->prepare(
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

              AND target.code = :target_code

              AND er.is_active = TRUE

            ORDER BY
                er.effective_at DESC,
                er.id DESC

            LIMIT 1
            "
        );


        $rateStmt->execute(
            [
                ':target_code' =>
                    $displayCurrencyCode
            ]
        );


        $rateRow =
            $rateStmt->fetch();


        if ($rateRow) {

            $exchangeRate =
                (float)
                $rateRow['rate'];

        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PREMIUM RATE QUERY] ' .
            $e->getMessage()
        );

        $rateRow = false;

    }


    if (
        !$rateRow
        ||
        $exchangeRate <= 0
    ) {

        premiumServicesResponse(
            false,
            'The current exchange rate for ' .
            $displayCurrencyCode .
            ' is not available.',
            [
                'code' => 'EXCHANGE_RATE_UNAVAILABLE'
            ],
            503
        );

    }

}


/* ============================================================
   FORMAT SERVICES
============================================================ */

$formattedServices = [];


foreach ($services as $service) {

    $baseUsd =
        (float)
        $service['base_price_usd'];


    $localAmount =
        $baseUsd
        *
        $exchangeRate;


    $decimalPlaces =
        (int)
        $displayCurrency['decimal_places'];


    if (
        $decimalPlaces < 0
        ||
        $decimalPlaces > 6
    ) {

        $decimalPlaces = 2;

    }


    $formattedServices[] = [

        'id' =>
            (int)
            $service['id'],

        'name' =>
            (string)
            $service['name'],

        'slug' =>
            (string)
            $service['slug'],

        'description' =>
            (string)
            (
                $service['description']
                ?? ''
            ),

        'service_type' =>
            (string)
            $service['service_type'],

        'base_price_usd' =>
            number_format(
                $baseUsd,
                2,
                '.',
                ''
            ),

        'price_usd_display' =>
            '$' .
            number_format(
                $baseUsd,
                2
            ),

        'duration_days' =>
            (int)
            $service['duration_days'],

        'max_usage' =>
            $service['max_usage'] !== null
                ?
                (int)
                $service['max_usage']
                :
                null,

        'is_premium' =>
            (bool)
            $service['is_premium'],

        'currency' => [

            'id' =>
                (int)
                $displayCurrency['id'],

            'code' =>
                $displayCurrencyCode,

            'name' =>
                (string)
                $displayCurrency['name'],

            'symbol' =>
                (string)
                $displayCurrency['symbol'],

            'decimal_places' =>
                $decimalPlaces

        ],

        'exchange_rate' =>
            number_format(
                $exchangeRate,
                10,
                '.',
                ''
            ),

        'local_amount' =>
            number_format(
                $localAmount,
                $decimalPlaces,
                '.',
                ''
            ),

        'local_amount_display' =>
            (string)
            $displayCurrency['symbol']
            .
            number_format(
                $localAmount,
                $decimalPlaces
            )

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

premiumServicesResponse(
    true,
    'Premium services loaded successfully.',
    [

        'user' => [

            'id' =>
                (int)
                $user['id'],

            'username' =>
                (string)
                $user['username'],

            'full_name' =>
                (string)
                $user['full_names'],

            'country' => [

                'id' =>
                    $user['country_id'] !== null
                        ?
                        (int)
                        $user['country_id']
                        :
                        null,

                'name' =>
                    $user['country_name'],

                'iso2' =>
                    $countryIso

            ]

        ],

        'payment_currency' => [

            'id' =>
                (int)
                $displayCurrency['id'],

            'code' =>
                $displayCurrencyCode,

            'name' =>
                (string)
                $displayCurrency['name'],

            'symbol' =>
                (string)
                $displayCurrency['symbol'],

            'decimal_places' =>
                (int)
                $displayCurrency['decimal_places']

        ],

        'exchange_rate' =>
            number_format(
                $exchangeRate,
                10,
                '.',
                ''
            ),

        'active_subscription' =>
            $activeSubscription
                ?
                [
                    'id' =>
                        (int)
                        $activeSubscription['id'],

                    'service_id' =>
                        (int)
                        $activeSubscription['service_id'],

                    'service_name' =>
                        (string)
                        $activeSubscription['service_name'],

                    'status' =>
                        (string)
                        $activeSubscription['status'],

                    'start_at' =>
                        $activeSubscription['start_at'],

                    'end_at' =>
                        $activeSubscription['end_at'],

                    'base_amount_usd' =>
                        $activeSubscription['base_amount_usd'],

                    'amount_paid' =>
                        $activeSubscription['amount_paid'],

                    'usage_limit' =>
                        $activeSubscription['usage_limit'] !== null
                            ?
                            (int)
                            $activeSubscription['usage_limit']
                            :
                            null,

                    'usage_used' =>
                        (int)
                        $activeSubscription['usage_used']

                ]
                :
                null,

        'has_active_premium' =>
            (bool)
            $activeSubscription,

        'services' =>
            $formattedServices

    ]
);