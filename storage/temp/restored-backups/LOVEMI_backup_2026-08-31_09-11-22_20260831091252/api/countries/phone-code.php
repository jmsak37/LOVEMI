<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function phoneCodeResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    phoneCodeResponse(
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

$countryId =
    (int)
    (
        $_GET['country_id']
        ??
        0
    );


$iso2 =
    strtoupper(
        trim(
            (string)
            (
                $_GET['iso2']
                ??
                ''
            )
        )
    );


$iso3 =
    strtoupper(
        trim(
            (string)
            (
                $_GET['iso3']
                ??
                ''
            )
        )
    );


$name =
    trim(
        (string)
        (
            $_GET['name']
            ??
            ''
        )
    );


$phoneCode =
    trim(
        (string)
        (
            $_GET['phone_code']
            ??
            ''
        )
    );


if (
    $countryId <= 0
    &&
    $iso2 === ''
    &&
    $iso3 === ''
    &&
    $name === ''
    &&
    $phoneCode === ''
) {

    phoneCodeResponse(
        false,
        'Provide country_id, iso2, iso3, name or phone_code.',
        [
            'code' =>
                'COUNTRY_IDENTIFIER_REQUIRED'
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
        '[LOVEMI PHONE CODE DB] '
        .
        $e->getMessage()
    );


    phoneCodeResponse(
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

$where =
    [];


$params =
    [];


/* Country ID */

if (
    $countryId > 0
) {

    $where[] =
        'id = :country_id';

    $params[
        ':country_id'
    ] =
        $countryId;

}


/* ISO2 */

if (
    $iso2 !== ''
) {

    $where[] =
        'iso2 = :iso2';

    $params[
        ':iso2'
    ] =
        $iso2;

}


/* ISO3 */

if (
    $iso3 !== ''
) {

    $where[] =
        'iso3 = :iso3';

    $params[
        ':iso3'
    ] =
        $iso3;

}


/* Name */

if (
    $name !== ''
) {

    $where[] =
        '
        name LIKE :country_name
        ';

    $params[
        ':country_name'
    ] =
        '%' .
        $name .
        '%';

}


/* Phone code */

if (
    $phoneCode !== ''
) {

    /*
     * Accept either +254 or 254.
     */

    $normalizedPhoneCode =
        $phoneCode;

    if (
        $normalizedPhoneCode[0]
        ===
        '+'
    ) {

        $normalizedPhoneCode =
            substr(
                $normalizedPhoneCode,
                1
            );

    }


    $where[] =
        "
        REPLACE(
            phone_code,
            '+',
            ''
        ) =
        :phone_code
        ";

    $params[
        ':phone_code'
    ] =
        $normalizedPhoneCode;

}


/* ============================================================
   QUERY
============================================================ */

$sql =
    "
    SELECT

        id,
        name,
        iso2,
        iso3,
        phone_code,
        currency_id,
        flag_code

    FROM countries

    WHERE is_active = 1

      AND
        "
    .
    implode(
        ' AND ',
        $where
    )
    .
    "

    ORDER BY name ASC

    LIMIT 20
    ";


try {

    $stmt =
        $pdo->prepare(
            $sql
        );


    foreach (
        $params
        as $key =>
        $value
    ) {

        $stmt->bindValue(
            $key,
            $value
        );

    }


    $stmt->execute();


    $countries =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PHONE CODE QUERY] '
        .
        $e->getMessage()
    );


    phoneCodeResponse(
        false,
        'Unable to retrieve country information.',
        [
            'code' =>
                'COUNTRY_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   NOT FOUND
============================================================ */

if (
    count(
        $countries
    )
    ===
    0
) {

    phoneCodeResponse(
        false,
        'Country could not be found.',
        [
            'code' =>
                'COUNTRY_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   FORMAT
============================================================ */

$result =
    [];


foreach (
    $countries
    as $country
) {

    $result[] = [

        'id' =>
            (int)
            $country['id'],

        'name' =>
            $country['name'],

        'iso2' =>
            $country['iso2'],

        'iso3' =>
            $country['iso3'],

        'phone_code' =>
            $country['phone_code'],

        'currency_id' =>
            $country['currency_id']
            !==
            null
                ?
                (int)
                $country['currency_id']
                :
                null,

        'flag_code' =>
            $country['flag_code']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

phoneCodeResponse(
    true,
    'Country information loaded successfully.',
    [

        'count' =>
            count(
                $result
            ),

        /*
         * convenient single-result field
         */
        'country' =>
            count(
                $result
            )
            ===
            1
                ?
                $result[0]
                :
                null,

        'countries' =>
            $result

    ]
);