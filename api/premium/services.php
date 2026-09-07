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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    premiumServicesResponse(
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

    premiumServicesResponse(
        false,
        'Please log in before viewing Premium.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',
            'redirect' =>
                'login.html?return=premium.html'
        ],
        401
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

    $userQuery =
        $pdo->prepare(
            "SELECT
                u.id,
                u.username,
                u.full_names,
                u.email,
                u.email_verified,
                u.is_active,
                u.is_suspended,
                u.is_deleted,
                c.name AS country_name,
                c.iso2,
                curr.id AS currency_id,
                curr.code AS currency_code,
                curr.name AS currency_name,
                curr.symbol AS currency_symbol,
                curr.decimal_places
             FROM users u
             LEFT JOIN countries c
                ON c.id = u.country_id
             LEFT JOIN currencies curr
                ON curr.id = c.currency_id
             WHERE u.id = :id
             LIMIT 1"
        );

    $userQuery->execute(
        [
            ':id' => $userId
        ]
    );

    $user =
        $userQuery->fetch();

    if (!$user) {

        premiumServicesResponse(
            false,
            'Your account could not be found.',
            [
                'code' =>
                    'USER_NOT_FOUND'
            ],
            404
        );
    }

    if (!(bool) $user['email_verified']) {

        premiumServicesResponse(
            false,
            'Please complete email verification before purchasing Premium.',
            [
                'code' =>
                    'EMAIL_NOT_VERIFIED'
            ],
            403
        );
    }

    if (
        !(bool) $user['is_active'] ||
        (bool) $user['is_suspended'] ||
        (bool) $user['is_deleted']
    ) {

        premiumServicesResponse(
            false,
            'Your account is currently unavailable.',
            [
                'code' =>
                    'ACCOUNT_UNAVAILABLE'
            ],
            403
        );
    }

    $targetCurrency =
        strtoupper(
            (string) (
                $user['iso2'] ?? ''
            )
        ) === 'KE'
            ? 'KES'
            : 'USD';

    $currencyQuery =
        $pdo->prepare(
            "SELECT
                id,
                code,
                name,
                symbol,
                decimal_places
             FROM currencies
             WHERE code = :code
               AND is_active = 1
             LIMIT 1"
        );

    $currencyQuery->execute(
        [
            ':code' =>
                $targetCurrency
        ]
    );

    $currency =
        $currencyQuery->fetch();

    if (!$currency) {

        premiumServicesResponse(
            false,
            'The payment currency is not configured.',
            [
                'code' =>
                    'CURRENCY_NOT_CONFIGURED'
            ],
            500
        );
    }

    $rate =
        1.0;

    $rateSource =
        'internal';

    if ($targetCurrency !== 'USD') {

        $rateQuery =
            $pdo->prepare(
                "SELECT
                    er.rate,
                    er.effective_at,
                    er.source
                 FROM exchange_rates er
                 JOIN currencies b
                    ON b.id =
                        er.base_currency_id
                 JOIN currencies t
                    ON t.id =
                        er.target_currency_id
                 WHERE b.code = 'USD'
                   AND t.code = :currency
                   AND er.is_active = 1
                 ORDER BY
                    er.effective_at DESC,
                    er.id DESC
                 LIMIT 1"
            );

        $rateQuery->execute(
            [
                ':currency' =>
                    $targetCurrency
            ]
        );

        $latestRate =
            $rateQuery->fetch();

        if (
            !$latestRate ||
            (float) $latestRate['rate'] <= 0
        ) {

            premiumServicesResponse(
                false,
                'The current exchange rate is unavailable. Run the administrator exchange-rate refresh first.',
                [
                    'code' =>
                        'EXCHANGE_RATE_UNAVAILABLE'
                ],
                503
            );
        }

        $rate =
            (float) $latestRate['rate'];

        $rateSource =
            (string) $latestRate['source'];
    }

    $services =
        $pdo->query(
            "SELECT
                id,
                name,
                slug,
                description,
                service_type,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium
             FROM services
             WHERE is_active = 1
               AND is_premium = 1
             ORDER BY
                sort_order ASC,
                id ASC"
        )->fetchAll();

    $activeQuery =
        $pdo->prepare(
            "SELECT
                s.id,
                s.service_id,
                s.status,
                s.start_at,
                s.end_at,
                s.base_amount_usd,
                s.amount_paid,
                cu.code AS currency_code,
                cu.symbol AS currency_symbol,
                sv.name AS service_name
             FROM subscriptions s
             JOIN services sv
                ON sv.id = s.service_id
             LEFT JOIN currencies cu
                ON cu.id = s.currency_id
             WHERE s.user_id = :user_id
               AND s.status = 'active'
               AND s.start_at <= CURRENT_TIMESTAMP
               AND s.end_at > CURRENT_TIMESTAMP
             ORDER BY
                s.end_at ASC"
        );

    $activeQuery->execute(
        [
            ':user_id' =>
                $userId
        ]
    );

    $activeRows =
        $activeQuery->fetchAll();

    $now =
        time();

    $active =
        [];

    foreach ($activeRows as $row) {

        $start =
            strtotime(
                (string) $row['start_at']
            ) ?: $now;

        $end =
            strtotime(
                (string) $row['end_at']
            ) ?: $now;

        $total =
            max(
                1,
                $end - $start
            );

        $remaining =
            max(
                0,
                $end - $now
            );

        $active[] = [
            'id' =>
                (int) $row['id'],

            'service_id' =>
                (int) $row['service_id'],

            'service_name' =>
                $row['service_name'],

            'status' =>
                $row['status'],

            'start_at' =>
                $row['start_at'],

            'end_at' =>
                $row['end_at'],

            'base_amount_usd' =>
                (string) $row['base_amount_usd'],

            'amount_paid' =>
                (string) $row['amount_paid'],

            'amount_paid_display' =>
                (string) (
                    $row['currency_symbol'] ??
                    $targetCurrency
                ) .
                ' ' .
                number_format(
                    (float) $row['amount_paid'],
                    (int) $currency['decimal_places']
                ),

            'total_seconds' =>
                $total,

            'remaining_seconds' =>
                $remaining,

            'percent_remaining' =>
                round(
                    (
                        $remaining /
                        $total
                    ) * 100,
                    2
                ),

            'percent_used' =>
                round(
                    (
                        1 -
                        (
                            $remaining /
                            $total
                        )
                    ) * 100,
                    2
                ),

            'end_at_display' =>
                date(
                    'M j, Y g:i A',
                    $end
                )
        ];
    }

    $formattedServices =
        [];

    $decimalPlaces =
        max(
            0,
            min(
                6,
                (int)
                    $currency[
                        'decimal_places'
                    ]
            )
        );

    foreach ($services as $service) {

        $base =
            (float)
                $service[
                    'base_price_usd'
                ];

        $localAmount =
            $base *
            $rate;

        $formattedServices[] = [
            'id' =>
                (int) $service['id'],

            'name' =>
                $service['name'],

            'slug' =>
                $service['slug'],

            'description' =>
                $service['description'] ?? '',

            'service_type' =>
                $service['service_type'],

            'base_price_usd' =>
                number_format(
                    $base,
                    2,
                    '.',
                    ''
                ),

            'duration_days' =>
                (int)
                    $service['duration_days'],

            'duration_label' =>
                (int)
                    $service['duration_days'] === 1
                    ? '1 day'
                    : (
                        (int)
                            $service['duration_days']
                    ) . ' days',

            'max_usage' =>
                $service['max_usage'] !== null
                    ? (int)
                        $service['max_usage']
                    : null,

            'currency' => [
                'id' =>
                    (int) $currency['id'],

                'code' =>
                    $targetCurrency,

                'name' =>
                    $currency['name'],

                'symbol' =>
                    $currency['symbol'],

                'decimal_places' =>
                    $decimalPlaces
            ],

            'exchange_rate' =>
                number_format(
                    $rate,
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
                    $currency['symbol'] .
                number_format(
                    $localAmount,
                    $decimalPlaces
                ),

            'price_usd_display' =>
                '$' .
                number_format(
                    $base,
                    2
                )
        ];
    }

    premiumServicesResponse(
        true,
        'Premium services loaded successfully.',
        [
            'user' => [
                'id' =>
                    (int) $user['id'],

                'username' =>
                    $user['username'],

                'full_name' =>
                    $user['full_names'],

                'email' =>
                    $user['email'],

                'country' =>
                    $user['country_name'],

                'iso2' =>
                    $user['iso2']
            ],

            'payment_currency' => [
                'id' =>
                    (int) $currency['id'],

                'code' =>
                    $targetCurrency,

                'name' =>
                    $currency['name'],

                'symbol' =>
                    $currency['symbol'],

                'decimal_places' =>
                    $decimalPlaces
            ],

            'exchange_rate' =>
                number_format(
                    $rate,
                    10,
                    '.',
                    ''
                ),

            'exchange_rate_source' =>
                $rateSource,

            'active_count' =>
                count($active),

            'active_subscriptions' =>
                $active,

            'services' =>
                $formattedServices
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SERVICES] ' .
        $e->getMessage()
    );

    premiumServicesResponse(
        false,
        'Premium information could not be loaded.',
        [
            'code' =>
                'PREMIUM_SERVICES_ERROR'
        ],
        500
    );
}