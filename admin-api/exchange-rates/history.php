<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . '/../../config/database.php';


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


/* =========================================================================
   RESPONSE
========================================================================= */

function fx_history_response(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

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


    exit;

}


/* =========================================================================
   DATABASE
========================================================================= */

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

} catch (
    Throwable $e
) {

    fx_history_response(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================================
   SESSION
========================================================================= */

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


/* =========================================================================
   ADMIN AUTH
========================================================================= */

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

    fx_history_response(
        false,
        'Your administrator session has expired.',
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


try {

    $auth =
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

                u.id =
                    :user_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
                    'exchange_rates.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':user_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        fx_history_response(
            false,
            'You do not have permission to view exchange-rate history.',
            [
                'code' =>
                    'PERMISSION_DENIED'
            ],
            403
        );

    }

} catch (
    Throwable $e
) {

    fx_history_response(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* =========================================================================
   INPUT
========================================================================= */

$base =
    strtoupper(
        trim(
            (string)(
                $_GET['base']
                ??
                'USD'
            )
        )
    );


$target =
    strtoupper(
        trim(
            (string)(
                $_GET['target']
                ??
                'KES'
            )
        )
    );


$limit =
    (int)(
        $_GET['limit']
        ??
        50
    );


$limit =
    max(
        1,
        min(
            5000,
            $limit
        )
    );


if (
    !preg_match(
        '/^[A-Z]{3,10}$/',
        $base
    )
    ||
    !preg_match(
        '/^[A-Z]{3,10}$/',
        $target
    )
) {

    fx_history_response(
        false,
        'Invalid currency code.',
        [],
        422
    );

}


/* =========================================================================
   XLSX PATH
========================================================================= */

$root =
    dirname(
        __DIR__,
        2
    );


$xlsx =
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


/* =========================================================================
   CHECK WORKBOOK
========================================================================= */

if (
    !is_file(
        $xlsx
    )
) {

    fx_history_response(
        true,
        'Exchange-rate history is waiting for the first live rate update.',
        [

            'base' =>
                $base,

            'target' =>
                $target,

            'history' =>
                [],

            'source' =>
                'exchange-rate-history.xlsx',

            'waiting' =>
                true

        ]
    );

}


if (
    !class_exists(
        'ZipArchive'
    )
) {

    fx_history_response(
        false,
        'PHP ZipArchive extension is required to read the exchange-rate history workbook.',
        [
            'code' =>
                'ZIP_EXTENSION_REQUIRED'
        ],
        500
    );

}


/* =========================================================================
   OPEN XLSX
========================================================================= */

$zip =
    new ZipArchive();


if (
    $zip->open(
        $xlsx
    )
    !==
    true
) {

    fx_history_response(
        false,
        'Unable to open exchange-rate history workbook.',
        [],
        500
    );

}


$sheetLocation =
    $zip->locateName(
        'xl/worksheets/sheet1.xml'
    );


if (
    $sheetLocation === false
) {

    $zip->close();


    fx_history_response(
        false,
        'Exchange-rate history worksheet is missing.',
        [],
        500
    );

}


$sheetXml =
    $zip->getFromIndex(
        $sheetLocation
    );


if (
    $sheetXml === false
) {

    $zip->close();


    fx_history_response(
        false,
        'Unable to read exchange-rate history worksheet.',
        [],
        500
    );

}


/* =========================================================================
   SHARED STRINGS
========================================================================= */

$sharedStrings =
    [];


$sharedLocation =
    $zip->locateName(
        'xl/sharedStrings.xml'
    );


if (
    $sharedLocation !== false
) {

    $sharedXml =
        $zip->getFromIndex(
            $sharedLocation
        );


    if (
        $sharedXml !== false
    ) {

        $sharedDom =
            @simplexml_load_string(
                $sharedXml
            );


        if (
            $sharedDom !== false
        ) {

            $sharedDom->registerXPathNamespace(
                'x',
                'http://schemas.openxmlformats.org/spreadsheetml/2006/main'
            );


            $items =
                $sharedDom->xpath(
                    '//x:si'
                );


            foreach (
                $items
                as $item
            ) {

                $textNodes =
                    $item->xpath(
                        './/x:t'
                    );


                $text =
                    '';


                foreach (
                    $textNodes
                    as $textNode
                ) {

                    $text .=
                        (string)
                        $textNode;

                }


                $sharedStrings[] =
                    $text;

            }

        }

    }

}


$zip->close();


/* =========================================================================
   PARSE SHEET
========================================================================= */

$dom =
    @simplexml_load_string(
        $sheetXml
    );


if (
    $dom === false
) {

    fx_history_response(
        false,
        'The exchange-rate history workbook contains invalid worksheet XML.',
        [],
        500
    );

}


$namespace =
    'http://schemas.openxmlformats.org/spreadsheetml/2006/main';


$dom->registerXPathNamespace(
    'x',
    $namespace
);


$rowNodes =
    $dom->xpath(
        '//x:sheetData/x:row'
    );


$records =
    [];


/* =========================================================================
   CELL VALUE
========================================================================= */

function fx_cell_value(
    SimpleXMLElement $cell,
    array $sharedStrings
): string
{

    $type =
        (string)
        (
            $cell['t']
            ??
            ''
        );


    if (
        $type ===
        'inlineStr'
    ) {

        $nodes =
            $cell->xpath(
                './/x:is/x:t'
            );


        if (
            $nodes
            &&
            isset(
                $nodes[0]
            )
        ) {

            return
                (string)
                $nodes[0];

        }


        return '';

    }


    $v =
        $cell->xpath(
            './x:v'
        );


    if (
        !$v
        ||
        !isset(
            $v[0]
        )
    ) {

        return '';

    }


    $raw =
        (string)
        $v[0];


    if (
        $type ===
        's'
    ) {

        $index =
            (int)
            $raw;


        return
            $sharedStrings[
                $index
            ]
            ??
            '';

    }


    return $raw;

}


/* =========================================================================
   PARSE EACH DATA ROW
========================================================================= */

foreach (
    $rowNodes
    as $index =>
    $row
) {

    /*
     * First row is the header.
     */

    if (
        $index === 0
    ) {

        continue;

    }


    $cells =
        $row->xpath(
            './x:c'
        );


    $values =
        [];


    foreach (
        $cells
        as $cell
    ) {

        $ref =
            (string)
            $cell['r'];


        $column =
            preg_replace(
                '/\d+/',
                '',
                $ref
            );


        $values[
            $column
        ] =
            fx_cell_value(
                $cell,
                $sharedStrings
            );

    }


    $recordBase =
        strtoupper(
            trim(
                $values['B']
                ??
                ''
            )
        );


    $recordTarget =
        strtoupper(
            trim(
                $values['C']
                ??
                ''
            )
        );


    if (
        $recordBase === ''
        ||
        $recordTarget === ''
    ) {

        continue;

    }


    /*
     * The workbook stores primary market history as USD -> target.
     */

    if (
        $recordBase !==
        'USD'
    ) {

        continue;

    }


    $rate =
        (float)
        (
            $values['D']
            ??
            0
        );


    if (
        $rate <= 0
    ) {

        continue;

    }


    $records[] = [

        'effective_at' =>
            $values['A']
            ??
            '',

        'base' =>
            $recordBase,

        'target' =>
            $recordTarget,

        'rate' =>
            $rate,

        'source' =>
            $values['E']
            ??
            '',

        'change_type' =>
            $values['F']
            ??
            'rate_change'

    ];

}


/* =========================================================================
   FILTER TARGET
========================================================================= */

$targetRecords =
    array_values(
        array_filter(
            $records,
            static function (
                array $record
            ) use (
                $target
            ): bool {

                return
                    strtoupper(
                        $record['target']
                    )
                    ===
                    $target;

            }
        )
    );


/* =========================================================================
   DERIVE NON-USD PAIRS
========================================================================= */

if (
    $base !==
    'USD'
) {

    $baseRecords =
        [];


    foreach (
        $records
        as $record
    ) {

        if (
            strtoupper(
                $record['target']
            )
            ===
            $base
        ) {

            $baseRecords[
                $record['effective_at']
            ] =
                (float)
                $record['rate'];

        }

    }


    $targetMap =
        [];


    foreach (
        $records
        as $record
    ) {

        if (
            strtoupper(
                $record['target']
            )
            ===
            $target
        ) {

            $targetMap[
                $record['effective_at']
            ] =
                [

                    'rate' =>
                        (float)
                        $record['rate'],

                    'source' =>
                        $record['source']

                ];

        }

    }


    $derived =
        [];


    foreach (
        $targetMap
        as $time =>
        $item
    ) {

        if (
            !isset(
                $baseRecords[
                    $time
                ]
            )
        ) {

            continue;

        }


        $baseRate =
            $baseRecords[
                $time
            ];


        if (
            $baseRate <= 0
        ) {

            continue;

        }


        $derived[] = [

            'effective_at' =>
                $time,

            'base' =>
                $base,

            'target' =>
                $target,

            'rate' =>
                $item['rate']
                /
                $baseRate,

            'source' =>
                $item['source'],

            'change_type' =>
                'derived_from_usd'

        ];

    }


    $targetRecords =
        $derived;

}


/* =========================================================================
   SORT CHRONOLOGICALLY
========================================================================= */

usort(
    $targetRecords,
    static function (
        array $a,
        array $b
    ): int {

        return
            strcmp(
                (string)
                $a['effective_at'],
                (string)
                $b['effective_at']
            );

    }
);


/* =========================================================================
   LIMIT
========================================================================= */

if (
    count(
        $targetRecords
    )
    >
    $limit
) {

    $targetRecords =
        array_slice(
            $targetRecords,
            -$limit
        );

}


/* =========================================================================
   RESPONSE DATA
========================================================================= */

fx_history_response(
    true,
    count(
        $targetRecords
    )
    >
    0
        ?
        'Exchange-rate history loaded successfully.'
        :
        'Waiting for the selected currency to receive live history.',
    [

        'base' =>
            $base,

        'target' =>
            $target,

        'history' =>
            $targetRecords,

        'source' =>
            'exchange-rate-history.xlsx',

        'waiting' =>
            count(
                $targetRecords
            )
            ===
            0

    ]
);