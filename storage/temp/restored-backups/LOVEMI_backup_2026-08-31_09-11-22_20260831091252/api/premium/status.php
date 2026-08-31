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

function premiumStatusResponse(
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

    premiumStatusResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTH
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    premiumStatusResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
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
        '[LOVEMI PREMIUM STATUS DB] ' .
        $e->getMessage()
    );

    premiumStatusResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   EXPIRE OLD SUBSCRIPTIONS FIRST
============================================================ */

try {

    $expireStmt =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET status = 'expired'

            WHERE user_id = :user_id

              AND status = 'active'

              AND end_at IS NOT NULL

              AND end_at <= CURRENT_TIMESTAMP
            "
        );

    $expireStmt->execute(
        [
            ':user_id' => $userId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM STATUS EXPIRY] ' .
        $e->getMessage()
    );

}


/* ============================================================
   LOAD ACTIVE PREMIUM
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                s.id,
                s.user_id,
                s.service_id,
                s.status,
                s.start_at,
                s.end_at,
                s.base_amount_usd,
                s.amount_paid,
                s.currency_id,
                s.exchange_rate,
                s.payment_id,
                s.usage_limit,
                s.usage_used,
                s.created_at,
                s.updated_at,

                sv.name AS service_name,
                sv.slug AS service_slug,
                sv.description AS service_description,
                sv.duration_days,
                sv.max_usage,
                sv.is_premium,
                sv.is_active,

                c.code AS currency_code,
                c.name AS currency_name,
                c.symbol AS currency_symbol,
                c.decimal_places

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id = s.service_id

            LEFT JOIN currencies c
                ON c.id = s.currency_id

            WHERE s.user_id = :user_id

              AND sv.slug = 'lovemi-premium'

            ORDER BY

                CASE
                    WHEN s.status = 'active'
                         AND s.end_at > CURRENT_TIMESTAMP
                    THEN 0

                    WHEN s.status = 'pending'
                    THEN 1

                    ELSE 2
                END,

                s.end_at DESC,
                s.id DESC

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':user_id' => $userId
        ]
    );


    $subscription =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM STATUS QUERY] ' .
        $e->getMessage()
    );

    premiumStatusResponse(
        false,
        'Unable to load Premium status.',
        [
            'code' => 'PREMIUM_STATUS_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   NO SUBSCRIPTION
============================================================ */

if (!$subscription) {

    premiumStatusResponse(
        true,
        'No Premium subscription found.',
        [

            'premium' => [

                'active' => false,

                'status' => 'none',

                'subscription_id' => null,

                'start_at' => null,

                'end_at' => null,

                'remaining_seconds' => 0,

                'remaining_days' => 0,

                'usage_limit' => null,

                'usage_used' => 0,

                'usage_remaining' => null

            ]

        ]
    );
}


/* ============================================================
   DETERMINE ACTIVITY
============================================================ */

$isActive =
    $subscription['status'] === 'active'
    &&
    !empty($subscription['end_at'])
    &&
    strtotime(
        (string)
        $subscription['end_at']
    ) >
    time();


/* ============================================================
   REMAINING TIME
============================================================ */

$remainingSeconds =
    0;


$remainingDays =
    0;


if (
    $isActive
) {

    $endTimestamp =
        strtotime(
            (string)
            $subscription['end_at']
        );


    if (
        $endTimestamp !== false
    ) {

        $remainingSeconds =
            max(
                0,
                $endTimestamp -
                time()
            );


        $remainingDays =
            (int)
            ceil(
                $remainingSeconds /
                86400
            );

    }

}


/* ============================================================
   USAGE
============================================================ */

$usageLimit =
    $subscription['usage_limit'];


if (
    $usageLimit === null
    &&
    $subscription['max_usage'] !== null
) {

    $usageLimit =
        $subscription['max_usage'];

}


$usageLimitValue =
    $usageLimit !== null
        ?
        (int)
        $usageLimit
        :
        null;


$usageUsed =
    (int)
    $subscription['usage_used'];


$usageRemaining =
    $usageLimitValue !== null
        ?
        max(
            0,
            $usageLimitValue -
            $usageUsed
        )
        :
        null;


/* ============================================================
   NORMALIZED STATUS
============================================================ */

$normalizedStatus =
    $isActive
        ?
        'active'
        :
        (
            $subscription['status']
            ??
            'unknown'
        );


/*
|--------------------------------------------------------------------------
| If an old subscription says active but is already expired,
| report it as expired.
|--------------------------------------------------------------------------
*/

if (
    !$isActive
    &&
    $subscription['status'] === 'active'
) {

    $normalizedStatus =
        'expired';

}


/* ============================================================
   RESPONSE
============================================================ */

premiumStatusResponse(
    true,
    $isActive
        ? 'Premium is active.'
        : 'Premium is not active.',
    [

        'premium' => [

            'active' =>
                $isActive,

            'status' =>
                $normalizedStatus,

            'subscription_id' =>
                (int)
                $subscription['id'],

            'service' => [

                'id' =>
                    (int)
                    $subscription['service_id'],

                'name' =>
                    $subscription['service_name'],

                'slug' =>
                    $subscription['service_slug'],

                'description' =>
                    $subscription['service_description'],

                'duration_days' =>
                    (int)
                    $subscription['duration_days']

            ],

            'start_at' =>
                $subscription['start_at'],

            'end_at' =>
                $subscription['end_at'],

            'remaining_seconds' =>
                $remainingSeconds,

            'remaining_days' =>
                $remainingDays,

            'base_amount_usd' =>
                (float)
                $subscription['base_amount_usd'],

            'amount_paid' =>
                (float)
                $subscription['amount_paid'],

            'currency' => [

                'id' =>
                    $subscription['currency_id']
                    !== null
                        ?
                        (int)
                        $subscription['currency_id']
                        :
                        null,

                'code' =>
                    $subscription['currency_code'],

                'name' =>
                    $subscription['currency_name'],

                'symbol' =>
                    $subscription['currency_symbol'],

                'decimal_places' =>
                    $subscription['decimal_places']
                    !== null
                        ?
                        (int)
                        $subscription['decimal_places']
                        :
                        2

            ],

            'exchange_rate' =>
                $subscription['exchange_rate']
                !== null
                    ?
                    (float)
                    $subscription['exchange_rate']
                    :
                    null,

            'payment_id' =>
                $subscription['payment_id']
                !== null
                    ?
                    (int)
                    $subscription['payment_id']
                    :
                    null,

            'usage' => [

                'limit' =>
                    $usageLimitValue,

                'used' =>
                    $usageUsed,

                'remaining' =>
                    $usageRemaining

            ],

            'created_at' =>
                $subscription['created_at'],

            'updated_at' =>
                $subscription['updated_at']

        ]

    ]
);