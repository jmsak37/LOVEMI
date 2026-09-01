<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - LIVE EXCHANGE RATE REFRESH
|--------------------------------------------------------------------------
| Sources:
|  1. MoneyConvert       - free, USD base, frequent updates
|  2. ExchangeRate-API   - open access, no API key
|  3. Frankfurter        - free, no API key
|
| LOVEMI stores all rates relative to USD and derives other pairs
| mathematically from the USD rates.
|
| There is NO manual currency-price entry in this API.
|--------------------------------------------------------------------------
*/

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* =========================================================================
   RESPONSE
========================================================================= */

function refreshResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    http_response_code($status);

    echo json_encode(
        [
            'success' => $success,
            'message' => $message,
            'data' => $data
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
   REQUEST
========================================================================= */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    refreshResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* =========================================================================
   SESSION
========================================================================= */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_set_cookie_params(
        [
            'lifetime' => 0,
            'path' => '/',
            'secure' => $isHttps,
            'httponly' => true,
            'samesite' => 'Lax'
        ]
    );

    session_start();
}


/* =========================================================================
   DATABASE
========================================================================= */

try {

    $pdo = db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI LIVE FX DB] ' . $e->getMessage()
    );

    refreshResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );

}


/* =========================================================================
   AUTHENTICATE ADMIN
========================================================================= */

$adminId =
    (int)(
        $_SESSION['lovemi_user_id'] ?? 0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id'] ?? 0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION['lovemi_session_token'] ?? ''
        )
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    refreshResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [
            'code' => 'NOT_AUTHENTICATED'
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
                u.id = :admin_id
                AND s.id = :session_id
                AND s.session_token_hash = :token_hash
                AND s.two_factor_passed = 1
                AND s.revoked_at IS NULL
                AND s.expires_at > CURRENT_TIMESTAMP
                AND u.is_active = 1
                AND u.is_suspended = 0
                AND u.is_deleted = 0
                AND r.is_admin_role = 1
                AND p.slug = 'exchange_rates.manage'
            LIMIT 1
            "
        );

    $auth->execute(
        [
            ':admin_id' => $adminId,
            ':session_id' => $sessionId,
            ':token_hash' => $tokenHash
        ]
    );


    if (!$auth->fetch()) {

        refreshResponse(
            false,
            'You do not have permission to refresh exchange rates.',
            [
                'code' => 'PERMISSION_DENIED'
            ],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI LIVE FX AUTH] ' . $e->getMessage()
    );

    refreshResponse(
        false,
        'Unable to verify administrator access.',
        [
            'code' => 'AUTH_ERROR'
        ],
        500
    );

}


/* =========================================================================
   UPDATE SESSION ACTIVITY
========================================================================= */

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions
            SET last_activity_at = CURRENT_TIMESTAMP
            WHERE id = :session_id
              AND user_id = :user_id
            LIMIT 1
            "
        );

    $activity->execute(
        [
            ':session_id' => $sessionId,
            ':user_id' => $adminId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI LIVE FX ACTIVITY] ' . $e->getMessage()
    );

}


/* =========================================================================
   LOAD ALL ACTIVE CURRENCIES
========================================================================= */

try {

    $currencyStmt =
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
            WHERE is_active = 1
            ORDER BY code ASC
            "
        );

    $currencies =
        $currencyStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI LIVE FX CURRENCIES] ' . $e->getMessage()
    );

    refreshResponse(
        false,
        'Unable to load currencies.',
        [
            'code' => 'CURRENCY_LOAD_ERROR'
        ],
        500
    );

}


if (!$currencies) {

    refreshResponse(
        false,
        'No active currencies are configured.',
        [
            'code' => 'NO_CURRENCIES'
        ],
        409
    );

}


/* =========================================================================
   FIND USD
========================================================================= */

$usd =
    null;


foreach ($currencies as $currency) {

    if (
        strtoupper(
            (string)$currency['code']
        ) === 'USD'
    ) {

        $usd = $currency;

        break;

    }

}


if (!$usd) {

    refreshResponse(
        false,
        'USD is not configured as an active LOVEMI currency.',
        [
            'code' => 'USD_NOT_CONFIGURED'
        ],
        409
    );

}


$usdId =
    (int)$usd['id'];


/* =========================================================================
   HTTP JSON FETCHER
========================================================================= */

function httpJson(
    string $url,
    int $timeout = 20
): array {

    $ch =
        curl_init(
            $url
        );

    if ($ch === false) {

        return [
            'ok' => false,
            'http_code' => 0,
            'body' => null,
            'error' => 'curl_init failed'
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
                4,

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
                'LOVEMI-Live-FX/1.0'

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


    $httpCode =
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
        $httpCode < 200
        ||
        $httpCode >= 300
    ) {

        return [

            'ok' => false,

            'http_code' => $httpCode,

            'body' => null,

            'error' => $error !== ''
                ? $error
                : 'HTTP ' . $httpCode

        ];

    }


    $json =
        json_decode(
            $body,
            true
        );


    if (
        !is_array($json)
    ) {

        return [

            'ok' => false,

            'http_code' => $httpCode,

            'body' => null,

            'error' =>
                'Invalid JSON response'

        ];

    }


    return [

        'ok' => true,

        'http_code' => $httpCode,

        'body' => $json,

        'error' => null

    ];

}


/* =========================================================================
   SOURCE 1 - MONEYCONVERT
========================================================================= */

$sourceName =
    null;


$usdRates =
    [];


$sourceTimestamp =
    null;


/*
 * MoneyConvert publishes a USD-base JSON feed.
 */

$moneyConvert =
    httpJson(
        'https://cdn.moneyconvert.net/api/latest.json',
        15
    );


if (
    $moneyConvert['ok']
    &&
    isset(
        $moneyConvert['body']['rates']
    )
    &&
    is_array(
        $moneyConvert['body']['rates']
    )
) {

    $candidateRates =
        $moneyConvert['body']['rates'];


    $valid =
        true;


    foreach (
        $candidateRates
        as $code => $value
    ) {

        if (
            !is_numeric(
                (string)$value
            )
            ||
            (float)$value <= 0
        ) {

            continue;

        }


        $usdRates[
            strtoupper(
                (string)$code
            )
        ] =
            (float)$value;

    }


    if (
        isset(
            $usdRates['KES']
        )
        ||
        count(
            $usdRates
        ) >= 20
    ) {

        $sourceName =
            'moneyconvert.net';

        $sourceTimestamp =
            date(
                'Y-m-d H:i:s'
            );

    }

}


/* =========================================================================
   SOURCE 2 - EXCHANGE RATE API OPEN ACCESS
========================================================================= */

if (
    $sourceName === null
) {

    $exchangeApi =
        httpJson(
            'https://open.er-api.com/v6/latest/USD',
            15
        );


    if (
        $exchangeApi['ok']
        &&
        isset(
            $exchangeApi['body']['rates']
        )
        &&
        is_array(
            $exchangeApi['body']['rates']
        )
    ) {

        foreach (
            $exchangeApi['body']['rates']
            as $code => $value
        ) {

            if (
                !is_numeric(
                    (string)$value
                )
                ||
                (float)$value <= 0
            ) {

                continue;

            }


            $usdRates[
                strtoupper(
                    (string)$code
                )
            ] =
                (float)$value;

        }


        if (
            count(
                $usdRates
            ) >= 20
        ) {

            $sourceName =
                'open.er-api.com';


            if (
                !empty(
                    $exchangeApi['body']['time_last_update_unix']
                )
            ) {

                $sourceTimestamp =
                    date(
                        'Y-m-d H:i:s',
                        (int)
                        $exchangeApi[
                            'body'
                        ][
                            'time_last_update_unix'
                        ]
                    );

            } else {

                $sourceTimestamp =
                    date(
                        'Y-m-d H:i:s'
                    );

            }

        }

    }

}


/* =========================================================================
   SOURCE 3 - FRANKFURTER
========================================================================= */

if (
    $sourceName === null
) {

    $frankfurter =
        httpJson(
            'https://api.frankfurter.dev/v2/rates?base=USD',
            20
        );


    if (
        $frankfurter['ok']
        &&
        is_array(
            $frankfurter['body']
        )
    ) {

        foreach (
            $frankfurter['body']
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
                    (string)(
                        $row['quote']
                        ??
                        ''
                    )
                );


            $value =
                $row['rate']
                ??
                null;


            if (
                $code === ''
                ||
                !is_numeric(
                    (string)$value
                )
                ||
                (float)$value <= 0
            ) {

                continue;

            }


            $usdRates[
                $code
            ] =
                (float)$value;

        }


        if (
            count(
                $usdRates
            ) >= 10
        ) {

            $sourceName =
                'api.frankfurter.dev';


            $sourceTimestamp =
                date(
                    'Y-m-d H:i:s'
                );

        }

    }

}


/* =========================================================================
   NO SOURCE
========================================================================= */

if (
    $sourceName === null
) {

    refreshResponse(
        false,
        'Live market-rate services are currently unavailable. Existing rates were not changed.',
        [
            'code' =>
                'MARKET_SOURCE_UNAVAILABLE'
        ],
        502
    );

}


/* =========================================================================
   FORCE USD = 1
========================================================================= */

$usdRates['USD'] =
    1.0;


/* =========================================================================
   MAKE SURE REQUIRED LOVEMI CURRENCIES ARE AVAILABLE
========================================================================= */

$missing =
    [];


foreach (
    $currencies
    as $currency
) {

    $code =
        strtoupper(
            (string)
            $currency['code']
        );


    if (
        !isset(
            $usdRates[$code]
        )
        ||
        !is_numeric(
            (string)
            $usdRates[$code]
        )
        ||
        (float)
        $usdRates[$code]
        <= 0
    ) {

        /*
         * Some central-bank APIs do not cover every currency.
         * We skip unsupported currencies instead of inventing
         * a rate.
         */

        $missing[] =
            $code;

    }

}


/* =========================================================================
   TRANSACTION
========================================================================= */

$newRates =
    [];


$now =
    date(
        'Y-m-d H:i:s'
    );


try {

    $pdo->beginTransaction();


    /*
     * We create a fresh USD-base record for every available
     * LOVEMI currency.
     *
     * Other currency pairs are mathematically derived from
     * USD rates:
     *
     *   BASE -> TARGET
     *
     *   targetUSD / baseUSD
     *
     * This means there is only one live source value to trust.
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
                :base_currency_id,
                :target_currency_id,
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
            SET is_active = 0
            WHERE
                base_currency_id = :base_currency_id
                AND target_currency_id = :target_currency_id
                AND is_active = 1
            "
        );


    foreach (
        $currencies
        as $currency
    ) {

        $code =
            strtoupper(
                (string)
                $currency['code']
            );


        if (
            $code === 'USD'
        ) {

            continue;

        }


        if (
            !isset(
                $usdRates[$code]
            )
        ) {

            continue;

        }


        $targetId =
            (int)
            $currency['id'];


        $rate =
            (float)
            $usdRates[$code];


        /*
         * Only reasonable numeric rates are accepted.
         */

        if (
            !is_finite(
                $rate
            )
            ||
            $rate <= 0
            ||
            $rate > 100000000000
        ) {

            continue;

        }


        /*
         * Deactivate the previous current USD -> target row.
         */

        $deactivate->execute(
            [
                ':base_currency_id' =>
                    $usdId,

                ':target_currency_id' =>
                    $targetId

            ]
        );


        $insert->execute(
            [

                ':base_currency_id' =>
                    $usdId,

                ':target_currency_id' =>
                    $targetId,

                ':rate' =>
                    number_format(
                        $rate,
                        10,
                        '.',
                        ''
                    ),

                ':source' =>
                    $sourceName,

                ':effective_at' =>
                    $now

            ]
        );


        $newRates[] = [

            'base_currency_id' =>
                $usdId,

            'target_currency_id' =>
                $targetId,

            'base_code' =>
                'USD',

            'target_code' =>
                $code,

            'rate' =>
                $rate

        ];

    }


    /*
     * USD itself.
     *
     * Store USD -> USD as 1 only if an existing pair already exists.
     * The application can also mathematically treat USD as 1 without
     * requiring this database row.
     */

    try {

        $usdPairCheck =
            $pdo->prepare(
                "
                SELECT id
                FROM exchange_rates
                WHERE
                    base_currency_id = :base_id
                    AND target_currency_id = :target_id
                LIMIT 1
                "
            );


        $usdPairCheck->execute(
            [
                ':base_id' =>
                    $usdId,

                ':target_id' =>
                    $usdId

            ]
        );


        if (
            $usdPairCheck->fetch()
        ) {

            $deactivate->execute(
                [
                    ':base_currency_id' =>
                        $usdId,

                    ':target_currency_id' =>
                        $usdId

                ]
            );


            $insert->execute(
                [

                    ':base_currency_id' =>
                        $usdId,

                    ':target_currency_id' =>
                        $usdId,

                    ':rate' =>
                        '1.0000000000',

                    ':source' =>
                        $sourceName,

                    ':effective_at' =>
                        $now

                ]
            );

        }

    } catch (Throwable $usdError) {

        error_log(
            '[LOVEMI FX USD/USD] '
            . $usdError->getMessage()
        );

    }


    /*
     * Audit record.
     */

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
                    'admin_live_exchange_rate_refresh',
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
                    $adminId,

                ':new_values' =>
                    json_encode(
                        [

                            'source' =>
                                $sourceName,

                            'source_timestamp' =>
                                $sourceTimestamp,

                            'refresh_time' =>
                                $now,

                            'base_currency' =>
                                'USD',

                            'updated_pairs' =>
                                count(
                                    $newRates
                                ),

                            'missing_currencies' =>
                                $missing

                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null

            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI FX AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    refreshResponse(
        true,
        'Live exchange rates updated successfully.',
        [

            'source' =>
                $sourceName,

            'source_timestamp' =>
                $sourceTimestamp,

            'refresh_time' =>
                $now,

            'base_currency' =>
                'USD',

            'updated_pairs' =>
                count(
                    $newRates
                ),

            'missing_currencies' =>
                $missing,

            'rates' =>
                $newRates

        ]
    );

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI FX REFRESH SAVE] '
        . $e->getMessage()
    );


    refreshResponse(
        false,
        'Unable to save live exchange rates. Existing rates were not changed.',
        [
            'code' =>
                'REFRESH_SAVE_ERROR'
        ],
        500
    );

}