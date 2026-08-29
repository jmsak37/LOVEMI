<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/*
|--------------------------------------------------------------------------
| LOVEMI - CURRENCIES LIST API
|--------------------------------------------------------------------------
|
| GET:
|
|   /api/currencies/list.php
|
| Optional:
|
|   ?search=ken
|   ?search=KES
|   ?active=1
|
| Returns currencies directly from MySQL.
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

function currenciesListResponse(
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

    currenciesListResponse(
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

$search =
    trim(
        (string)
        (
            $_GET['search']
            ??
            $_GET['q']
            ??
            ''
        )
    );


$active =
    isset(
        $_GET['active']
    )
        ?
        (int)
        $_GET['active']
        :
        1;


if (
    !in_array(
        $active,
        [
            0,
            1
        ],
        true
    )
) {

    $active =
        1;

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
        '[LOVEMI CURRENCIES LIST DB] '
        .
        $e->getMessage()
    );


    currenciesListResponse(
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
   BUILD QUERY
============================================================ */

$where = [

    'is_active = :is_active'

];


$params = [

    ':is_active' =>
        $active

];


if (
    $search !==
    ''
) {

    $where[] =
        "
        (
            code LIKE :search_code

            OR

            name LIKE :search_name

            OR

            symbol LIKE :search_symbol
        )
        ";


    $like =
        '%' .
        $search .
        '%';


    $params[
        ':search_code'
    ] =
        $like;


    $params[
        ':search_name'
    ] =
        $like;


    $params[
        ':search_symbol'
    ] =
        $like;

}


/* ============================================================
   QUERY
============================================================ */

$sql =
    "
    SELECT

        id,
        code,
        name,
        symbol,
        decimal_places,
        is_base,
        is_active,
        created_at,
        updated_at

    FROM currencies

    WHERE
        "
    .
    implode(
        ' AND ',
        $where
    )
    .
    "

    ORDER BY

        is_base DESC,
        name ASC,
        id ASC
    ";


try {

    $stmt =
        $pdo->prepare(
            $sql
        );


    $stmt->execute(
        $params
    );


    $rows =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CURRENCIES LIST QUERY] '
        .
        $e->getMessage()
    );


    currenciesListResponse(
        false,
        'Unable to load currencies.',
        [
            'code' =>
                'CURRENCY_QUERY_FAILED'
        ],
        500
    );

}


/* ============================================================
   FORMAT RESULT
============================================================ */

$currencies =
    [];


foreach (
    $rows
    as $row
) {

    $currencies[] = [

        'id' =>
            (int)
            $row['id'],

        'code' =>
            $row['code'],

        'name' =>
            $row['name'],

        'symbol' =>
            $row['symbol'],

        'decimal_places' =>
            (int)
            $row['decimal_places'],

        'is_base' =>
            (bool)
            $row['is_base'],

        'is_active' =>
            (bool)
            $row['is_active'],

        'created_at' =>
            $row['created_at'],

        'updated_at' =>
            $row['updated_at']

    ];

}


/* ============================================================
   BASE CURRENCY
============================================================ */

$baseCurrency =
    null;


foreach (
    $currencies
    as $currency
) {

    if (
        $currency['is_base']
    ) {

        $baseCurrency =
            $currency;

        break;

    }

}


/* ============================================================
   RESPONSE
============================================================ */

currenciesListResponse(
    true,
    'Currencies loaded successfully.',
    [

        'count' =>
            count(
                $currencies
            ),

        'base_currency' =>
            $baseCurrency,

        'search' =>
            $search,

        'currencies' =>
            $currencies

    ]
);