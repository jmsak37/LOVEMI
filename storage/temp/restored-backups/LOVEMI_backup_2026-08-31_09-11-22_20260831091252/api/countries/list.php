<?php
/**
 * ============================================================
 * LOVEMI - COUNTRIES LIST API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\countries\list.php
 *
 * Purpose:
 * - Load countries directly from MySQL.
 * - Return country name.
 * - Return ISO2 / ISO3 code.
 * - Return international phone code.
 * - Return currency information.
 *
 * IMPORTANT:
 * Countries are NOT hardcoded in registration.html.
 * They come directly from the countries database table.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
   ============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
   ============================================================ */

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-cache, no-store, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   METHOD
   ============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'GET'
) {

    http_response_code(405);

    echo json_encode(
        [
            'success' => false,
            'message' => 'Only GET requests are allowed.',
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    exit;
}


/* ============================================================
   DATABASE QUERY
   ============================================================ */

try {

    $pdo = db();


    /*
     * Pull countries directly from MySQL.
     *
     * No hardcoded country names.
     */

    $stmt = $pdo->query(
        "
        SELECT

            c.id,

            c.name,

            c.iso2,

            c.iso3,

            c.phone_code,

            c.currency_id,

            cu.code AS currency_code,

            cu.name AS currency_name,

            cu.symbol AS currency_symbol

        FROM countries c

        LEFT JOIN currencies cu
            ON cu.id = c.currency_id

        WHERE c.is_active = TRUE

        ORDER BY c.name ASC
        "
    );


    $countries = $stmt->fetchAll();


    /*
     * Convert database values to clean JSON types.
     */

    $cleanCountries = [];


    foreach (
        $countries as $country
    ) {

        $cleanCountries[] = [

            'id' =>
                (int) $country['id'],

            'name' =>
                (string) $country['name'],

            'iso2' =>
                $country['iso2'] !== null
                    ? strtoupper(
                        (string) $country['iso2']
                    )
                    : null,

            'iso3' =>
                $country['iso3'] !== null
                    ? strtoupper(
                        (string) $country['iso3']
                    )
                    : null,

            'phone_code' =>
                (string) $country['phone_code'],

            'currency_id' =>
                $country['currency_id'] !== null
                    ? (int) $country['currency_id']
                    : null,

            'currency_code' =>
                $country['currency_code'] !== null
                    ? strtoupper(
                        (string) $country['currency_code']
                    )
                    : null,

            'currency_name' =>
                $country['currency_name'] !== null
                    ? (string) $country['currency_name']
                    : null,

            'currency_symbol' =>
                $country['currency_symbol'] !== null
                    ? (string) $country['currency_symbol']
                    : null

        ];

    }


    /* ========================================================
       RESPONSE
       ======================================================== */

    echo json_encode(
        [
            'success' => true,

            'message' => 'Countries loaded successfully.',

            'count' =>
                count($cleanCountries),

            'countries' =>
                $cleanCountries,

            'data' =>
                $cleanCountries
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI COUNTRIES ERROR] '
        . $e->getMessage()
    );


    http_response_code(500);


    echo json_encode(
        [
            'success' => false,

            'message' =>
                'Unable to load countries from the database.',

            'code' =>
                'COUNTRIES_DATABASE_ERROR',

            'countries' =>
                [],

            'data' =>
                []
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

}


exit;