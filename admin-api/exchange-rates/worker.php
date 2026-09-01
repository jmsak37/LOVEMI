<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - EXCHANGE RATE AUTOMATIC WORKER
|--------------------------------------------------------------------------
|
| This is the central exchange-rate engine.
|
| Responsibilities:
|
| 1. Load active currencies from LOVEMI database.
| 2. Obtain current USD-base market/reference rates.
| 3. Use multiple free public sources.
| 4. Compare incoming values with the latest stored values.
| 5. Store only genuine rate changes.
| 6. Keep only the newest row active for each pair.
| 7. Append every genuine change to:
|
|    storage/exchange-rates/exchange-rate-history.xlsx
|
| 8. Work when the browser is NOT open when executed by
|    Windows Task Scheduler / cron.
|
|--------------------------------------------------------------------------
|
| Sources:
|
| Primary:
|   https://open.er-api.com/v6/latest/USD
|
| Secondary:
|   https://api.frankfurter.dev/v2/rates?base=USD
|
|--------------------------------------------------------------------------
*/

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . '/../../config/database.php';


/* =========================================================================
   HEADERS
========================================================================= */

if (
    PHP_SAPI !== 'cli'
) {

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

}


/* =========================================================================
   RESPONSE
========================================================================= */

function fx_worker_response(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    if (
        PHP_SAPI !== 'cli'
    ) {

        while (
            ob_get_level() > 0
        ) {

            @ob_end_clean();

        }

        http_response_code(
            $status
        );

        echo json_encode(
            [
                'success' =>
                    $success,

                'message' =>
                    $message,

                'data' =>
                    $data
            ],
            JSON_UNESCAPED_UNICODE
            |
            JSON_UNESCAPED_SLASHES
            |
            JSON_INVALID_UTF8_SUBSTITUTE
        );

    } else {

        echo json_encode(
            [
                'success' =>
                    $success,

                'message' =>
                    $message,

                'data' =>
                    $data
            ],
            JSON_UNESCAPED_UNICODE
            |
            JSON_UNESCAPED_SLASHES
            |
            JSON_INVALID_UTF8_SUBSTITUTE
        )
        .
        PHP_EOL;

    }

    exit(
        $success
            ? 0
            : 1
    );

}


/* =========================================================================
   DATABASE
========================================================================= */

function fx_get_pdo(): PDO
{

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


    return $pdo;

}


/* =========================================================================
   SESSION / ADMIN AUTH
========================================================================= */

function fx_start_session(): void
{

    if (
        PHP_SAPI === 'cli'
    ) {

        return;

    }


    $isHttps =
        !empty(
            $_SERVER['HTTPS']
        )
        &&
        $_SERVER['HTTPS'] !== 'off';


    if (
        session_status()
        !==
        PHP_SESSION_ACTIVE
    ) {

        session_set_cookie_params(
            [
                'lifetime' =>
                    0,

                'path' =>
                    '/',

                'secure' =>
                    $isHttps,

                'httponly' =>
                    true,

                'samesite' =>
                    'Lax'
            ]
        );


        session_start();

    }

}


/* =========================================================================
   CHECK ADMIN PERMISSION
========================================================================= */

function fx_require_admin(
    PDO $pdo
): int
{

    /*
     * CLI is intended for Windows Task Scheduler / cron.
     */

    if (
        PHP_SAPI === 'cli'
    ) {

        return 0;

    }


    fx_start_session();


    $adminId =
        (int)(
            $_SESSION[
                'lovemi_user_id'
            ]
            ??
            0
        );


    $sessionId =
        (int)(
            $_SESSION[
                'lovemi_database_session_id'
            ]
            ??
            0
        );


    $sessionToken =
        trim(
            (string)(
                $_SESSION[
                    'lovemi_session_token'
                ]
                ??
                ''
            )
        );


    if (
        $adminId <= 0
        ||
        $sessionId <= 0
        ||
        $sessionToken === ''
    ) {

        fx_worker_response(
            false,
            'Administrator session expired.',
            [
                'code' =>
                    'NOT_AUTHENTICATED'
            ],
            401
        );

    }


    $tokenHash =
        hash(
            'sha256',
            $sessionToken
        );


    $stmt =
        $pdo->prepare(
            "
            SELECT
                u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND p.slug =
                    'exchange_rates.manage'

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$stmt->fetch()
    ) {

        fx_worker_response(
            false,
            'You do not have permission to manage exchange rates.',
            [
                'code' =>
                    'PERMISSION_DENIED'
            ],
            403
        );

    }


    return $adminId;

}


/* =========================================================================
   HTTP JSON REQUEST
========================================================================= */

function fx_http_json(
    string $url,
    int $timeout = 20
): array
{

    $ch =
        curl_init(
            $url
        );


    if (
        $ch === false
    ) {

        return [

            'ok' =>
                false,

            'status' =>
                0,

            'data' =>
                null,

            'error' =>
                'Unable to initialize HTTP client.'

        ];

    }


    curl_setopt_array(
        $ch,
        [

            CURLOPT_RETURNTRANSFER =>
                true,

            CURLOPT_FOLLOWLOCATION =>
                true,

            CURLOPT_MAXREDIRS =>
                5,

            CURLOPT_CONNECTTIMEOUT =>
                8,

            CURLOPT_TIMEOUT =>
                $timeout,

            CURLOPT_SSL_VERIFYPEER =>
                true,

            CURLOPT_SSL_VERIFYHOST =>
                2,

            CURLOPT_HTTPHEADER =>
                [
                    'Accept: application/json'
                ],

            CURLOPT_USERAGENT =>
                'LOVEMI-Exchange-Worker/1.0'

        ]
    );


    $body =
        curl_exec(
            $ch
        );


    $error =
        curl_error(
            $ch
        );


    $status =
        (int)
        curl_getinfo(
            $ch,
            CURLINFO_HTTP_CODE
        );


    curl_close(
        $ch
    );


    if (
        $body === false
        ||
        $status < 200
        ||
        $status >= 300
    ) {

        return [

            'ok' =>
                false,

            'status' =>
                $status,

            'data' =>
                null,

            'error' =>
                $error
                !==
                ''
                    ?
                    $error
                    :
                    'HTTP ' .
                    $status

        ];

    }


    $data =
        json_decode(
            $body,
            true
        );


    if (
        !is_array(
            $data
        )
    ) {

        return [

            'ok' =>
                false,

            'status' =>
                $status,

            'data' =>
                null,

            'error' =>
                'Invalid JSON response.'

        ];

    }


    return [

        'ok' =>
            true,

        'status' =>
            $status,

        'data' =>
            $data,

        'error' =>
            null

    ];

}


/* =========================================================================
   NORMALIZE MARKET DATA
========================================================================= */

function fx_clean_rates(
    array $rates
): array
{

    $clean =
        [];


    foreach (
        $rates
        as $code =>
        $value
    ) {

        $currencyCode =
            strtoupper(
                trim(
                    (string)
                    $code
                )
            );


        if (
            !preg_match(
                '/^[A-Z]{3,10}$/',
                $currencyCode
            )
        ) {

            continue;

        }


        if (
            !is_numeric(
                (string)
                $value
            )
        ) {

            continue;

        }


        $numeric =
            (float)
            $value;


        if (
            !is_finite(
                $numeric
            )
            ||
            $numeric <= 0
        ) {

            continue;

        }


        $clean[
            $currencyCode
        ] =
            $numeric;

    }


    return $clean;

}


/* =========================================================================
   READ MARKET DATA
========================================================================= */

function fx_get_market_rates(): array
{

    $combined =
        [];


    $sources =
        [];


    /*
     * --------------------------------------------------------------
     * SOURCE 1
     * --------------------------------------------------------------
     */

    $exchangeApi =
        fx_http_json(
            'https://open.er-api.com/v6/latest/USD',
            15
        );


    if (
        $exchangeApi['ok']
        &&
        isset(
            $exchangeApi['data']['rates']
        )
        &&
        is_array(
            $exchangeApi['data']['rates']
        )
    ) {

        $first =
            fx_clean_rates(
                $exchangeApi[
                    'data'
                ][
                    'rates'
                ]
            );


        if (
            count(
                $first
            ) > 10
        ) {

            foreach (
                $first
                as $code =>
                $rate
            ) {

                $combined[
                    $code
                ] =
                    [

                        'rate' =>
                            $rate,

                        'source' =>
                            'open.er-api.com'

                    ];

            }


            $sources[] =
                'open.er-api.com';

        }

    }


    /*
     * --------------------------------------------------------------
     * SOURCE 2
     * --------------------------------------------------------------
     *
     * Frankfurter returns rows such as:
     *
     * [
     *   {
     *      date: "...",
     *      base: "USD",
     *      quote: "EUR",
     *      rate: 0.85
     *   }
     * ]
     *
     * We overlay it when available.
     */

    $frankfurter =
        fx_http_json(
            'https://api.frankfurter.dev/v2/rates?base=USD',
            20
        );


    if (
        $frankfurter['ok']
        &&
        is_array(
            $frankfurter['data']
        )
    ) {

        $frankfurterCount =
            0;


        foreach (
            $frankfurter['data']
            as $row
        ) {

            if (
                !is_array(
                    $row
                )
            ) {

                continue;

            }


            $code =
                strtoupper(
                    trim(
                        (string)(
                            $row['quote']
                            ??
                            ''
                        )
                    )
                );


            $rate =
                $row['rate']
                ??
                null;


            if (
                $code === ''
                ||
                !is_numeric(
                    (string)
                    $rate
                )
            ) {

                continue;

            }


            $numeric =
                (float)
                $rate;


            if (
                !is_finite(
                    $numeric
                )
                ||
                $numeric <= 0
            ) {

                continue;

            }


            /*
             * Frankfurter is a useful reference source.
             * Prefer it when it has the requested currency.
             */

            $combined[
                $code
            ] =
                [

                    'rate' =>
                        $numeric,

                    'source' =>
                        'api.frankfurter.dev'

                ];


            $frankfurterCount++;

        }


        if (
            $frankfurterCount > 0
        ) {

            $sources[] =
                'api.frankfurter.dev';

        }

    }


    /*
     * USD is always exactly 1 against itself.
     */

    $combined['USD'] =
        [

            'rate' =>
                1.0,

            'source' =>
                'internal-usd-base'

        ];


    if (
        count(
            $combined
        )
        <
        2
    ) {

        throw new RuntimeException(
            'All live market-rate sources are unavailable.'
        );

    }


    return [

        'rates' =>
            $combined,

        'sources' =>
            array_values(
                array_unique(
                    $sources
                )
            )

    ];

}


/* =========================================================================
   XLSX HELPERS
========================================================================= */

function fx_xlsx_path(): string
{

    $root =
        dirname(
            __DIR__,
            2
        );


    return
        $root
        .
        DIRECTORY_SEPARATOR
        .
        'storage'
        .
        DIRECTORY_SEPARATOR
        .
        'exchange-rates'
        .
        DIRECTORY_SEPARATOR
        .
        'exchange-rate-history.xlsx';

}


/* =========================================================================
   XML ESCAPE
========================================================================= */

function fx_xml(
    string $value
): string
{

    return htmlspecialchars(
        $value,
        ENT_XML1
        |
        ENT_QUOTES,
        'UTF-8'
    );

}


/* =========================================================================
   CREATE XLSX
========================================================================= */

function fx_create_xlsx(
    string $path
): void
{

    $directory =
        dirname(
            $path
        );


    if (
        !is_dir(
            $directory
        )
        &&
        !mkdir(
            $directory,
            0775,
            true
        )
    ) {

        throw new RuntimeException(
            'Unable to create exchange-rate storage directory.'
        );

    }


    if (
        !class_exists(
            'ZipArchive'
        )
    ) {

        throw new RuntimeException(
            'PHP ZipArchive extension is required to create the Excel history file.'
        );

    }


    $zip =
        new ZipArchive();


    if (
        $zip->open(
            $path,
            ZipArchive::CREATE
            |
            ZipArchive::OVERWRITE
        )
        !==
        true
    ) {

        throw new RuntimeException(
            'Unable to create Excel history workbook.'
        );

    }


    $now =
        date(
            'Y-m-d H:i:s'
        );


    $sheet =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        .
        '<sheetData>'
        .
        '<row r="1">'
        .
        fx_xlsx_inline_string_cell(
            'A1',
            'Timestamp'
        )
        .
        fx_xlsx_inline_string_cell(
            'B1',
            'Base Currency'
        )
        .
        fx_xlsx_inline_string_cell(
            'C1',
            'Target Currency'
        )
        .
        fx_xlsx_numeric_cell(
            'D1',
            'Rate'
        )
        .
        fx_xlsx_inline_string_cell(
            'E1',
            'Source'
        )
        .
        fx_xlsx_inline_string_cell(
            'F1',
            'Change Type'
        )
        .
        '</row>'
        .
        '</sheetData>'
        .
        '</worksheet>';


    $contentTypes =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        .
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        .
        '<Default Extension="xml" ContentType="application/xml"/>'
        .
        '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        .
        '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        .
        '</Types>';


    $rels =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>'
        .
        '</Relationships>';


    $workbook =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        .
        '<sheets>'
        .
        '<sheet name="RateHistory" sheetId="1" r:id="rId1"/>'
        .
        '</sheets>'
        .
        '</workbook>';


    $workbookRels =
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        .
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        .
        '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>'
        .
        '</Relationships>';


    $zip->addFromString(
        '[Content_Types].xml',
        $contentTypes
    );


    $zip->addFromString(
        '_rels/.rels',
        $rels
    );


    $zip->addFromString(
        'xl/workbook.xml',
        $workbook
    );


    $zip->addFromString(
        'xl/_rels/workbook.xml.rels',
        $workbookRels
    );


    $zip->addFromString(
        'xl/worksheets/sheet1.xml',
        $sheet
    );


    $zip->close();

}


/* =========================================================================
   XLSX CELLS
========================================================================= */

function fx_xlsx_inline_string_cell(
    string $ref,
    string $value
): string
{

    return
        '<c r="'
        .
        fx_xml(
            $ref
        )
        .
        '" t="inlineStr">'
        .
        '<is><t xml:space="preserve">'
        .
        fx_xml(
            $value
        )
        .
        '</t></is>'
        .
        '</c>';

}


function fx_xlsx_numeric_cell(
    string $ref,
    string $value
): string
{

    return
        '<c r="'
        .
        fx_xml(
            $ref
        )
        .
        '">'
        .
        '<v>'
        .
        fx_xml(
            $value
        )
        .
        '</v>'
        .
        '</c>';

}


/* =========================================================================
   APPEND XLSX ROW
========================================================================= */

function fx_append_xlsx(
    array $changes
): void
{

    $path =
        fx_xlsx_path();


    if (
        !is_file(
            $path
        )
    ) {

        fx_create_xlsx(
            $path
        );

    }


    if (
        !class_exists(
            'ZipArchive'
        )
    ) {

        throw new RuntimeException(
            'PHP ZipArchive extension is required for Excel history.'
        );

    }


    $zip =
        new ZipArchive();


    if (
        $zip->open(
            $path
        )
        !==
        true
    ) {

        throw new RuntimeException(
            'Unable to open Excel history workbook.'
        );

    }


    $sheetIndex =
        $zip->locateName(
            'xl/worksheets/sheet1.xml'
        );


    if (
        $sheetIndex === false
    ) {

        $zip->close();

        throw new RuntimeException(
            'Excel worksheet is missing.'
        );

    }


    $xml =
        $zip->getFromIndex(
            $sheetIndex
        );


    if (
        $xml === false
    ) {

        $zip->close();

        throw new RuntimeException(
            'Unable to read Excel worksheet.'
        );

    }


    /*
     * Determine the highest existing row.
     */

    $lastRow =
        1;


    if (
        preg_match_all(
            '/<row[^>]*\br="(\d+)"/i',
            $xml,
            $matches
        )
    ) {

        foreach (
            $matches[1]
            as $rowNumber
        ) {

            $lastRow =
                max(
                    $lastRow,
                    (int)
                    $rowNumber
                );

        }

    }


    $newRows =
        '';


    foreach (
        $changes
        as $change
    ) {

        $lastRow++;


        $timestamp =
            (string)
            (
                $change['timestamp']
                ??
                date(
                    'Y-m-d H:i:s'
                )
            );


        $base =
            strtoupper(
                (string)
                (
                    $change['base']
                    ??
                    ''
                )
            );


        $target =
            strtoupper(
                (string)
                (
                    $change['target']
                    ??
                    ''
                )
            );


        $rate =
            (string)
            (
                $change['rate']
                ??
                '0'
            );


        $source =
            (string)
            (
                $change['source']
                ??
                ''
            );


        $type =
            (string)
            (
                $change['change_type']
                ??
                'rate_change'
            );


        $newRows .=
            '<row r="'
            .
            $lastRow
            .
            '">'
            .
            fx_xlsx_inline_string_cell(
                'A' . $lastRow,
                $timestamp
            )
            .
            fx_xlsx_inline_string_cell(
                'B' . $lastRow,
                $base
            )
            .
            fx_xlsx_inline_string_cell(
                'C' . $lastRow,
                $target
            )
            .
            fx_xlsx_numeric_cell(
                'D' . $lastRow,
                $rate
            )
            .
            fx_xlsx_inline_string_cell(
                'E' . $lastRow,
                $source
            )
            .
            fx_xlsx_inline_string_cell(
                'F' . $lastRow,
                $type
            )
            .
            '</row>';

    }


    if (
        $newRows !== ''
    ) {

        /*
         * Insert before </sheetData>.
         */

        $replacement =
            $newRows
            .
            '</sheetData>';


        $xml =
            preg_replace(
                '/<\/sheetData>/i',
                $replacement,
                $xml,
                1
            );


        if (
            $xml === null
        ) {

            $zip->close();

            throw new RuntimeException(
                'Unable to append Excel history rows.'
            );

        }


        $zip->addFromString(
            'xl/worksheets/sheet1.xml',
            $xml
        );

    }


    $zip->close();

}


/* =========================================================================
   GET LATEST STORED RATES
========================================================================= */

function fx_latest_database_rates(
    PDO $pdo
): array
{

    $stmt =
        $pdo->query(
            "
            SELECT

                er.id,
                er.base_currency_id,
                er.target_currency_id,
                er.rate,
                er.source,
                er.effective_at,
                er.is_active,
                er.created_at,

                bc.code AS base_code,
                tc.code AS target_code

            FROM exchange_rates er

            INNER JOIN currencies bc
                ON bc.id =
                    er.base_currency_id

            INNER JOIN currencies tc
                ON tc.id =
                    er.target_currency_id

            INNER JOIN
            (
                SELECT

                    base_currency_id,
                    target_currency_id,
                    MAX(
                        id
                    ) AS latest_id

                FROM exchange_rates

                WHERE
                    is_active = 1

                GROUP BY
                    base_currency_id,
                    target_currency_id

            ) latest

                ON latest.latest_id =
                    er.id

            ORDER BY
                bc.code ASC,
                tc.code ASC
            "
        );


    $rows =
        $stmt->fetchAll();


    $map =
        [];


    foreach (
        $rows
        as $row
    ) {

        $key =
            strtoupper(
                $row['base_code']
            )
            .
            ':'
            .
            strtoupper(
                $row['target_code']
            );


        $map[
            $key
        ] =
            $row;

    }


    return $map;

}


/* =========================================================================
   CURRENCIES
========================================================================= */

function fx_active_currencies(
    PDO $pdo
): array
{

    $stmt =
        $pdo->query(
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

            WHERE
                is_active = 1

            ORDER BY
                code ASC
            "
        );


    return
        $stmt->fetchAll();

}


/* =========================================================================
   RATE DECIMAL REPRESENTATION
========================================================================= */

function fx_decimal(
    float $value
): string
{

    return number_format(
        $value,
        10,
        '.',
        ''
    );

}


/* =========================================================================
   WORKER
========================================================================= */

function lovemi_run_exchange_worker(
    bool $returnResponse = true
): array
{

    $pdo =
        fx_get_pdo();


    $adminId =
        fx_require_admin(
            $pdo
        );


    /*
     * Single-process lock.
     *
     * This prevents multiple page requests/tasks from writing
     * the Excel file simultaneously.
     */

    $root =
        dirname(
            __DIR__,
            2
        );


    $lockDirectory =
        $root
        .
        DIRECTORY_SEPARATOR
        .
        'storage'
        .
        DIRECTORY_SEPARATOR
        .
        'temp';


    if (
        !is_dir(
            $lockDirectory
        )
    ) {

        @mkdir(
            $lockDirectory,
            0775,
            true
        );

    }


    $lockFile =
        $lockDirectory
        .
        DIRECTORY_SEPARATOR
        .
        'exchange-rate-worker.lock';


    $lockHandle =
        @fopen(
            $lockFile,
            'c'
        );


    if (
        $lockHandle === false
    ) {

        throw new RuntimeException(
            'Unable to create worker lock.'
        );

    }


    if (
        !flock(
            $lockHandle,
            LOCK_EX
            |
            LOCK_NB
        )
    ) {

        fclose(
            $lockHandle
        );


        return [

            'updated' =>
                0,

            'unchanged' =>
                0,

            'source' =>
                'worker_locked',

            'message' =>
                'Another exchange-rate worker is already running.'

        ];

    }


    try {

        /*
         * ----------------------------------------------------------
         * Load currencies
         * ----------------------------------------------------------
         */

        $currencies =
            fx_active_currencies(
                $pdo
            );


        if (
            !$currencies
        ) {

            throw new RuntimeException(
                'No active currencies are configured.'
            );

        }


        /*
         * ----------------------------------------------------------
         * Load live market data
         * ----------------------------------------------------------
         */

        $market =
            fx_get_market_rates();


        $marketRates =
            $market[
                'rates'
            ];


        $sourceList =
            $market[
                'sources'
            ];


        /*
         * ----------------------------------------------------------
         * Latest database state
         * ----------------------------------------------------------
         */

        $existing =
            fx_latest_database_rates(
                $pdo
            );


        /*
         * ----------------------------------------------------------
         * Find USD ID
         * ----------------------------------------------------------
         */

        $usdId =
            0;


        foreach (
            $currencies
            as $currency
        ) {

            if (
                strtoupper(
                    (string)
                    $currency['code']
                )
                ===
                'USD'
            ) {

                $usdId =
                    (int)
                    $currency['id'];

                break;

            }

        }


        if (
            $usdId <= 0
        ) {

            throw new RuntimeException(
                'USD is not configured as an active currency.'
            );

        }


        /*
         * ----------------------------------------------------------
         * Process rates
         * ----------------------------------------------------------
         */

        $changes =
            [];


        $inserted =
            0;


        $unchanged =
            0;


        $now =
            date(
                'Y-m-d H:i:s'
            );


        $pdo->beginTransaction();


        /*
         * IMPORTANT:
         *
         * LOVEMI stores USD -> target as the primary live market
         * rate. Other currency pairs are calculated from these
         * values by the application.
         */

        $insert =
            $pdo->prepare(
                "
                INSERT INTO exchange_rates
                (
                    base_currency_id,
                    target_currency_id,
                    rate,
                    source,
                    effective_at,
                    is_active
                )
                VALUES
                (
                    :base_id,
                    :target_id,
                    :rate,
                    :source,
                    :effective_at,
                    1
                )
                "
            );


        $deactivate =
            $pdo->prepare(
                "
                UPDATE exchange_rates

                SET
                    is_active = 0

                WHERE

                    base_currency_id =
                        :base_id

                    AND target_currency_id =
                        :target_id

                    AND is_active = 1
                "
            );


        foreach (
            $currencies
            as $currency
        ) {

            $targetId =
                (int)
                $currency['id'];


            $targetCode =
                strtoupper(
                    (string)
                    $currency['code']
                );


            if (
                $targetCode ===
                'USD'
            ) {

                continue;

            }


            /*
             * The market source must provide this currency.
             *
             * Never manufacture a missing currency price.
             */

            if (
                !isset(
                    $marketRates[
                        $targetCode
                    ]
                )
            ) {

                continue;

            }


            $incoming =
                (float)
                $marketRates[
                    $targetCode
                ][
                    'rate'
                ];


            $source =
                (string)
                $marketRates[
                    $targetCode
                ][
                    'source'
                ];


            if (
                !is_finite(
                    $incoming
                )
                ||
                $incoming <= 0
            ) {

                continue;

            }


            $key =
                'USD'
                .
                ':'
                .
                $targetCode;


            $previous =
                $existing[
                    $key
                ]
                ??
                null;


            $previousRate =
                $previous
                ?
                (float)
                $previous['rate']
                :
                null;


            /*
             * Only write to database when:
             *
             * - there was no previous rate
             * OR
             * - the actual numeric rate changed
             *
             * This means Excel records genuine rate changes,
             * not empty polling activity.
             */

            $changed =
                $previousRate === null
                ||
                abs(
                    $incoming
                    -
                    $previousRate
                )
                >
                0.00000000005;


            if (
                !$changed
            ) {

                $unchanged++;

                continue;

            }


            /*
             * Deactivate previous active row.
             */

            $deactivate->execute(
                [

                    ':base_id' =>
                        $usdId,

                    ':target_id' =>
                        $targetId

                ]
            );


            /*
             * Insert new active row.
             */

            $insert->execute(
                [

                    ':base_id' =>
                        $usdId,

                    ':target_id' =>
                        $targetId,

                    ':rate' =>
                        fx_decimal(
                            $incoming
                        ),

                    ':source' =>
                        $source,

                    ':effective_at' =>
                        $now

                ]
            );


            $changeType =
                $previousRate === null
                    ?
                    'initial_live_rate'
                    :
                    'rate_change';


            $changes[] = [

                'timestamp' =>
                    $now,

                'base' =>
                    'USD',

                'target' =>
                    $targetCode,

                'rate' =>
                    fx_decimal(
                        $incoming
                    ),

                'source' =>
                    $source,

                'change_type' =>
                    $changeType

            ];


            $inserted++;

        }


        /*
         * ----------------------------------------------------------
         * AUDIT LOG
         * ----------------------------------------------------------
         */

        if (
            $inserted > 0
        ) {

            try {

                $audit =
                    $pdo->prepare(
                        "
                        INSERT INTO audit_logs
                        (
                            user_id,
                            action,
                            entity_type,
                            entity_id,
                            old_values,
                            new_values,
                            ip_address,
                            user_agent
                        )
                        VALUES
                        (
                            :user_id,
                            'exchange_rate_worker_update',
                            'exchange_rate',
                            NULL,
                            NULL,
                            :new_values,
                            :ip,
                            :agent
                        )
                        "
                    );


                $audit->execute(
                    [

                        ':user_id' =>
                            $adminId > 0
                                ?
                                $adminId
                                :
                                null,

                        ':new_values' =>
                            json_encode(
                                [

                                    'updated' =>
                                        $inserted,

                                    'source' =>
                                        $sourceList,

                                    'changes' =>
                                        $changes,

                                    'timestamp' =>
                                        $now

                                ],
                                JSON_UNESCAPED_UNICODE
                            ),

                        ':ip' =>
                            PHP_SAPI === 'cli'
                                ?
                                null
                                :
                                (
                                    $_SERVER[
                                        'REMOTE_ADDR'
                                    ]
                                    ??
                                    null
                                ),

                        ':agent' =>
                            PHP_SAPI === 'cli'
                                ?
                                'CLI worker'
                                :
                                (
                                    $_SERVER[
                                        'HTTP_USER_AGENT'
                                    ]
                                    ??
                                    null
                                )

                    ]
                );

            } catch (
                Throwable $auditException
            ) {

                error_log(
                    '[LOVEMI FX AUDIT] '
                    .
                    $auditException->getMessage()
                );

            }

        }


        /*
         * Commit database first.
         */

        $pdo->commit();


        /*
         * ----------------------------------------------------------
         * Excel
         * ----------------------------------------------------------
         *
         * Excel is system history. It is not the primary database.
         */

        $excelWritten =
            false;


        $excelError =
            null;


        if (
            $inserted > 0
        ) {

            try {

                fx_append_xlsx(
                    $changes
                );


                $excelWritten =
                    true;

            } catch (
                Throwable $excelException
            ) {

                $excelError =
                    $excelException->getMessage();


                error_log(
                    '[LOVEMI FX EXCEL] '
                    .
                    $excelError
                );

            }

        } else {

            /*
             * Ensure workbook exists even before the first change.
             */

            try {

                $xlsxPath =
                    fx_xlsx_path();


                if (
                    !is_file(
                        $xlsxPath
                    )
                ) {

                    fx_create_xlsx(
                        $xlsxPath
                    );

                }


                $excelWritten =
                    true;

            } catch (
                Throwable $excelException
            ) {

                $excelError =
                    $excelException->getMessage();

            }

        }


        /*
         * ----------------------------------------------------------
         * Result
         * ----------------------------------------------------------
         */

        $result = [

            'updated' =>
                $inserted,

            'unchanged' =>
                $unchanged,

            'source' =>
                implode(
                    ', ',
                    $sourceList
                ),

            'sources' =>
                $sourceList,

            'updated_at' =>
                $inserted > 0
                    ?
                    $now
                    :
                    null,

            'excel_path' =>
                fx_xlsx_path(),

            'excel_updated' =>
                $excelWritten,

            'excel_error' =>
                $excelError,

            'changes' =>
                $changes

        ];


        return $result;

    } catch (
        Throwable $e
    ) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        throw $e;

    } finally {

        flock(
            $lockHandle,
            LOCK_UN
        );


        fclose(
            $lockHandle
        );

    }

}


/* =========================================================================
   DIRECT EXECUTION
========================================================================= */

if (
    basename(
        __FILE__
    )
    ===
    basename(
        $_SERVER['SCRIPT_FILENAME']
        ??
        ''
    )
) {

    try {

        $result =
            lovemi_run_exchange_worker(
                true
            );


        fx_worker_response(
            true,
            $result['updated'] > 0
                ?
                'Live exchange rates updated successfully.'
                :
                'Live exchange check completed. No rate changes were detected.',
            $result
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI EXCHANGE WORKER ERROR] '
            .
            $e->getMessage()
        );


        fx_worker_response(
            false,
            'Live market-rate services are unavailable or the worker could not complete.',
            [
                'code' =>
                    'WORKER_ERROR',

                'error' =>
                    $e->getMessage()
            ],
            502
        );

    }

}