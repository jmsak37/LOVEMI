<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - CURRENCY RATE API
|--------------------------------------------------------------------------
|
| GET:
|
|   /api/currencies/rate.php?from=USD&to=KES
|
|--------------------------------------------------------------------------
*/


header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   RESPONSE
============================================================ */

function currencyRateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


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
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    currencyRateResponse(
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
   INPUT
============================================================ */

$fromCode =
    strtoupper(
        trim(
            (string)
            (
                $_GET['from']
                ??
                $_GET['base']
                ??
                ''
            )
        )
    );


$toCode =
    strtoupper(
        trim(
            (string)
            (
                $_GET['to']
                ??
                $_GET['target']
                ??
                ''
            )
        )
    );


if (
    $fromCode === ''
    ||
    $toCode === ''
) {

    currencyRateResponse(
        false,
        'Both from and to currency codes are required.',
        [
            'code' =>
                'CURRENCY_CODES_REQUIRED'
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
        '[LOVEMI CURRENCY RATE DB] '
        .
        $e->getMessage()
    );


    currencyRateResponse(
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
   CURRENCY LOOKUP
============================================================ */

try {

    $stmt =
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

            WHERE code =
                  :code

              AND is_active =
                  1

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':code' =>
                $fromCode
        ]
    );


    $from =
        $stmt->fetch();


    $stmt->execute(
        [
            ':code' =>
                $toCode
        ]
    );


    $to =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CURRENCY LOOKUP] '
        .
        $e->getMessage()
    );


    currencyRateResponse(
        false,
        'Unable to load the requested currencies.',
        [
            'code' =>
                'CURRENCY_LOOKUP_FAILED'
        ],
        500
    );

}


if (
    !$from
) {

    currencyRateResponse(
        false,
        "Currency '{$fromCode}' was not found.",
        [
            'code' =>
                'FROM_CURRENCY_NOT_FOUND'
        ],
        404
    );

}


if (
    !$to
) {

    currencyRateResponse(
        false,
        "Currency '{$toCode}' was not found.",
        [
            'code' =>
                'TO_CURRENCY_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   SAME CURRENCY
============================================================ */

if (
    (int)
    $from['id']
    ===
    (int)
    $to['id']
) {

    currencyRateResponse(
        true,
        'Currency rate loaded successfully.',
        [

            'rate' =>
                1.0,

            'rate_source' =>
                'same_currency',

            'from' => [

                'id' =>
                    (int)
                    $from['id'],

                'code' =>
                    $from['code'],

                'name' =>
                    $from['name'],

                'symbol' =>
                    $from['symbol']

            ],

            'to' => [

                'id' =>
                    (int)
                    $to['id'],

                'code' =>
                    $to['code'],

                'name' =>
                    $to['name'],

                'symbol' =>
                    $to['symbol']

            ],

            'effective_at' =>
                date(
                    'Y-m-d H:i:s'
                )

        ]
    );

}


/* ============================================================
   DIRECT RATE
============================================================ */

try {

    $directStmt =
        $pdo->prepare(
            "
            SELECT

                er.id,
                er.rate,
                er.source,
                er.effective_at

            FROM exchange_rates er

            WHERE er.base_currency_id =
                  :base_currency_id

              AND er.target_currency_id =
                  :target_currency_id

              AND er.is_active =
                  1

            ORDER BY

                er.effective_at DESC,
                er.id DESC

            LIMIT 1
            "
        );


    $directStmt->execute(
        [

            ':base_currency_id' =>
                (int)
                $from['id'],

            ':target_currency_id' =>
                (int)
                $to['id']

        ]
    );


    $directRate =
        $directStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DIRECT RATE] '
        .
        $e->getMessage()
    );


    $directRate =
        false;

}


/* ============================================================
   INVERSE RATE
============================================================ */

if (
    $directRate
) {

    $rate =
        (float)
        $directRate['rate'];


    $source =
        $directRate['source'];


    $effectiveAt =
        $directRate['effective_at'];


    $rateId =
        (int)
        $directRate['id'];


    $rateDirection =
        'direct';

} else {

    try {

        $inverseStmt =
            $pdo->prepare(
                "
                SELECT

                    er.id,
                    er.rate,
                    er.source,
                    er.effective_at

                FROM exchange_rates er

                WHERE er.base_currency_id =
                      :base_currency_id

                  AND er.target_currency_id =
                      :target_currency_id

                  AND er.is_active =
                      1

                ORDER BY

                    er.effective_at DESC,
                    er.id DESC

                LIMIT 1
                "
            );


        $inverseStmt->execute(
            [

                ':base_currency_id' =>
                    (int)
                    $to['id'],

                ':target_currency_id' =>
                    (int)
                    $from['id']

            ]
        );


        $inverse =
            $inverseStmt->fetch();

    } catch (
        Throwable $e
    ) {

        $inverse =
            false;

    }


    if (
        !$inverse
    ) {

        currencyRateResponse(
            false,
            "No exchange rate is available for {$fromCode} to {$toCode}.",
            [

                'code' =>
                    'EXCHANGE_RATE_NOT_FOUND',

                'from' =>
                    $fromCode,

                'to' =>
                    $toCode

            ],
            404
        );
    }


    $inverseRate =
        (float)
        $inverse['rate'];


    if (
        $inverseRate <=
        0
    ) {

        currencyRateResponse(
            false,
            'The stored exchange rate is invalid.',
            [
                'code' =>
                    'INVALID_EXCHANGE_RATE'
            ],
            500
        );
    }


    $rate =
        1 /
        $inverseRate;


    $source =
        $inverse['source'];


    $effectiveAt =
        $inverse['effective_at'];


    $rateId =
        (int)
        $inverse['id'];


    $rateDirection =
        'inverse';

}


/* ============================================================
   VALIDATE
============================================================ */

if (
    $rate <=
    0
) {

    currencyRateResponse(
        false,
        'The exchange rate is invalid.',
        [
            'code' =>
                'INVALID_EXCHANGE_RATE'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

currencyRateResponse(
    true,
    'Currency rate loaded successfully.',
    [

        'rate' =>
            (float)
            $rate,

        'rate_rounded' =>
            round(
                $rate,
                10
            ),

        'rate_direction' =>
            $rateDirection,

        'rate_id' =>
            $rateId,

        'source' =>
            $source,

        'effective_at' =>
            $effectiveAt,

        'from' => [

            'id' =>
                (int)
                $from['id'],

            'code' =>
                $from['code'],

            'name' =>
                $from['name'],

            'symbol' =>
                $from['symbol'],

            'decimal_places' =>
                (int)
                $from['decimal_places']

        ],

        'to' => [

            'id' =>
                (int)
                $to['id'],

            'code' =>
                $to['code'],

            'name' =>
                $to['name'],

            'symbol' =>
                $to['symbol'],

            'decimal_places' =>
                (int)
                $to['decimal_places']

        ]

    ]
);