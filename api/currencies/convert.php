<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - CURRENCY CONVERSION API
|--------------------------------------------------------------------------
|
| GET:
|
|   /api/currencies/convert.php
|
| Required:
|
|   amount
|   from
|   to
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

function currencyConvertResponse(
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
    (
        $_SERVER['REQUEST_METHOD']
        ??
        ''
    )
    !==
    'GET'
) {

    currencyConvertResponse(
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

$amountInput =
    trim(
        (string)
        (
            $_GET['amount']
            ??
            ''
        )
    );


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
    $amountInput === ''
) {

    currencyConvertResponse(
        false,
        'Amount is required.',
        [
            'code' =>
                'AMOUNT_REQUIRED'
        ],
        422
    );
}


/*
|--------------------------------------------------------------------------
| Strict numeric validation.
|--------------------------------------------------------------------------
*/

if (
    !is_numeric(
        $amountInput
    )
) {

    currencyConvertResponse(
        false,
        'Amount must be a valid number.',
        [
            'code' =>
                'INVALID_AMOUNT'
        ],
        422
    );
}


$amount =
    (float)
    $amountInput;


if (
    !is_finite(
        $amount
    )
    ||
    $amount < 0
) {

    currencyConvertResponse(
        false,
        'Amount must be zero or greater.',
        [
            'code' =>
                'INVALID_AMOUNT'
        ],
        422
    );
}


if (
    $fromCode === ''
    ||
    $toCode === ''
) {

    currencyConvertResponse(
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
        '[LOVEMI CURRENCY CONVERT DB] '
        .
        $e->getMessage()
    );


    currencyConvertResponse(
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
   LOAD CURRENCIES
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
                is_active

            FROM currencies

            WHERE code =
                  :code

              AND is_active =
                  1

            LIMIT 1
            "
        );


    $currencyStmt->execute(
        [
            ':code' =>
                $fromCode
        ]
    );


    $from =
        $currencyStmt->fetch();


    $currencyStmt->execute(
        [
            ':code' =>
                $toCode
        ]
    );


    $to =
        $currencyStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CURRENCY CONVERT LOOKUP] '
        .
        $e->getMessage()
    );


    currencyConvertResponse(
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

    currencyConvertResponse(
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

    currencyConvertResponse(
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

    $rate =
        1.0;

    $converted =
        round(
            $amount,
            (int)
            $to['decimal_places']
        );


    currencyConvertResponse(
        true,
        'Currency converted successfully.',
        [

            'amount' =>
                $amount,

            'converted_amount' =>
                $converted,

            'rate' =>
                $rate,

            'rate_direction' =>
                'same_currency',

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

    $rateStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                rate,
                source,
                effective_at

            FROM exchange_rates

            WHERE base_currency_id =
                  :base_id

              AND target_currency_id =
                  :target_id

              AND is_active =
                  1

            ORDER BY

                effective_at DESC,
                id DESC

            LIMIT 1
            "
        );


    $rateStmt->execute(
        [

            ':base_id' =>
                (int)
                $from['id'],

            ':target_id' =>
                (int)
                $to['id']

        ]
    );


    $direct =
        $rateStmt->fetch();

} catch (
    Throwable $e
) {

    $direct =
        false;

}


/* ============================================================
   DETERMINE RATE
============================================================ */

if (
    $direct
) {

    $rate =
        (float)
        $direct['rate'];


    $source =
        $direct['source'];


    $effectiveAt =
        $direct['effective_at'];


    $rateId =
        (int)
        $direct['id'];


    $direction =
        'direct';

} else {

    /*
     * Try inverse pair.
     */

    try {

        $inverseStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    rate,
                    source,
                    effective_at

                FROM exchange_rates

                WHERE base_currency_id =
                      :base_id

                  AND target_currency_id =
                      :target_id

                  AND is_active =
                      1

                ORDER BY

                    effective_at DESC,
                    id DESC

                LIMIT 1
                "
            );


        $inverseStmt->execute(
            [

                ':base_id' =>
                    (int)
                    $to['id'],

                ':target_id' =>
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

        currencyConvertResponse(
            false,
            "No current exchange rate is available for {$fromCode} to {$toCode}.",
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

        currencyConvertResponse(
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


    $direction =
        'inverse';

}


/* ============================================================
   VALIDATE RATE
============================================================ */

if (
    !is_finite(
        $rate
    )
    ||
    $rate <=
    0
) {

    currencyConvertResponse(
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
   CALCULATE
============================================================ */

$convertedAmount =
    $amount *
    $rate;


$targetDecimals =
    max(
        0,
        min(
            10,
            (int)
            $to['decimal_places']
        )
    );


$convertedAmount =
    round(
        $convertedAmount,
        $targetDecimals
    );


/* ============================================================
   RESPONSE
============================================================ */

currencyConvertResponse(
    true,
    'Currency converted successfully.',
    [

        'amount' =>
            $amount,

        'converted_amount' =>
            $convertedAmount,

        'rate' =>
            $rate,

        'rate_rounded' =>
            round(
                $rate,
                10
            ),

        'rate_direction' =>
            $direction,

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