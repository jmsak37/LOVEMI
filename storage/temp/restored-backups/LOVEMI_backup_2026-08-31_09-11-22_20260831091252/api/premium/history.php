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

function premiumHistoryResponse(
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

    premiumHistoryResponse(
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

    premiumHistoryResponse(
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
   PAGINATION
============================================================ */

$page =
    max(
        1,
        (int)
        (
            $_GET['page']
            ??
            1
        )
    );


$requestedLimit =
    (int)
    (
        $_GET['limit']
        ??
        20
    );


$limit =
    min(
        50,
        max(
            1,
            $requestedLimit
        )
    );


$offset =
    (
        $page -
        1
    )
    *
    $limit;


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
        '[LOVEMI PREMIUM HISTORY DB] '
        .
        $e->getMessage()
    );


    premiumHistoryResponse(
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
   MARK EXPIRED SUBSCRIPTIONS
============================================================ */

try {

    $expireStmt =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET status = 'expired'

            WHERE user_id =
                  :user_id

              AND status =
                  'active'

              AND end_at IS NOT NULL

              AND end_at <= CURRENT_TIMESTAMP
            "
        );


    $expireStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM HISTORY EXPIRE] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   COUNT
============================================================ */

try {

    $countStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id =
                   s.service_id

            WHERE s.user_id =
                  :user_id

              AND sv.slug =
                  'lovemi-premium'
            "
        );


    $countStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $total =
        (int)
        $countStmt->fetchColumn();

} catch (
    Throwable $e
) {

    premiumHistoryResponse(
        false,
        'Unable to count Premium history.',
        [
            'code' =>
                'HISTORY_COUNT_FAILED'
        ],
        500
    );
}


/* ============================================================
   HISTORY
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                s.id,
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

                sv.id AS service_id,
                sv.name AS service_name,
                sv.slug AS service_slug,
                sv.duration_days,
                sv.max_usage,

                c.code AS currency_code,
                c.name AS currency_name,
                c.symbol AS currency_symbol,
                c.decimal_places,

                p.payment_reference,
                p.gateway,
                p.gateway_transaction_id,
                p.payment_method,
                p.status AS payment_status,
                p.amount_expected,
                p.amount_paid AS payment_amount_paid,
                p.paid_at

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id =
                   s.service_id

            LEFT JOIN currencies c
                ON c.id =
                   s.currency_id

            LEFT JOIN payments p
                ON p.id =
                   s.payment_id

            WHERE s.user_id =
                  :user_id

              AND sv.slug =
                  'lovemi-premium'

            ORDER BY

                s.created_at DESC,
                s.id DESC

            LIMIT :limit

            OFFSET :offset
            "
        );


    $stmt->bindValue(
        ':user_id',
        $userId,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':limit',
        $limit,
        PDO::PARAM_INT
    );


    $stmt->bindValue(
        ':offset',
        $offset,
        PDO::PARAM_INT
    );


    $stmt->execute();


    $rows =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM HISTORY QUERY] '
        .
        $e->getMessage()
    );


    premiumHistoryResponse(
        false,
        'Unable to load Premium history.',
        [
            'code' =>
                'HISTORY_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   FORMAT
============================================================ */

$history =
    [];


foreach (
    $rows
    as $row
) {

    $usageLimit =
        $row['usage_limit'];


    if (
        $usageLimit ===
        null
        &&
        $row['max_usage'] !== null
    ) {

        $usageLimit =
            $row['max_usage'];

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
        $row['usage_used'];


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


    $status =
        $row['status'];


    /*
     * Correct a stale active record whose end date has passed.
     */

    if (
        $status === 'active'
        &&
        !empty($row['end_at'])
        &&
        strtotime(
            (string)
            $row['end_at']
        ) <= time()
    ) {

        $status =
            'expired';

    }


    $history[] = [

        'subscription_id' =>
            (int)
            $row['id'],

        'status' =>
            $status,

        'service' => [

            'id' =>
                (int)
                $row['service_id'],

            'name' =>
                $row['service_name'],

            'slug' =>
                $row['service_slug'],

            'duration_days' =>
                (int)
                $row['duration_days']

        ],

        'dates' => [

            'start_at' =>
                $row['start_at'],

            'end_at' =>
                $row['end_at']

        ],

        'amount' => [

            'base_usd' =>
                (float)
                $row['base_amount_usd'],

            'subscription_paid' =>
                (float)
                $row['amount_paid'],

            'exchange_rate' =>
                $row['exchange_rate']
                !== null
                    ?
                    (float)
                    $row['exchange_rate']
                    :
                    null,

            'currency' => [

                'id' =>
                    $row['currency_id']
                    !== null
                        ?
                        (int)
                        $row['currency_id']
                        :
                        null,

                'code' =>
                    $row['currency_code'],

                'name' =>
                    $row['currency_name'],

                'symbol' =>
                    $row['currency_symbol'],

                'decimal_places' =>
                    $row['decimal_places']
                    !== null
                        ?
                        (int)
                        $row['decimal_places']
                        :
                        2

            ]

        ],

        'usage' => [

            'limit' =>
                $usageLimitValue,

            'used' =>
                $usageUsed,

            'remaining' =>
                $usageRemaining

        ],

        'payment' => $row['payment_id'] !== null
            ?

            [

                'id' =>
                    (int)
                    $row['payment_id'],

                'reference' =>
                    $row['payment_reference'],

                'gateway' =>
                    $row['gateway'],

                'gateway_transaction_id' =>
                    $row['gateway_transaction_id'],

                'method' =>
                    $row['payment_method'],

                'status' =>
                    $row['payment_status'],

                'amount_expected' =>
                    (float)
                    $row['amount_expected'],

                'amount_paid' =>
                    (float)
                    $row['payment_amount_paid'],

                'paid_at' =>
                    $row['paid_at']

            ]

            :
            null,

        'created_at' =>
            $row['created_at'],

        'updated_at' =>
            $row['updated_at']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

$totalPages =
    $limit > 0
        ?
        (int)
        ceil(
            $total /
            $limit
        )
        :
        0;


premiumHistoryResponse(
    true,
    'Premium history loaded successfully.',
    [

        'pagination' => [

            'page' =>
                $page,

            'limit' =>
                $limit,

            'total' =>
                $total,

            'total_pages' =>
                $totalPages

        ],

        'count' =>
            count(
                $history
            ),

        'history' =>
            $history

    ]
);