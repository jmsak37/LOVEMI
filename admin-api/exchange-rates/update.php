<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function exchangeUpdateResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    exchangeUpdateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* ============================================================
   INPUT
============================================================ */

$input =
    json_decode(
        file_get_contents(
            'php://input'
        )
        ?:
        '{}',
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
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


/* ============================================================
   DATABASE
============================================================ */

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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE UPDATE DB] '
        . $e->getMessage()
    );

    exchangeUpdateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ADMIN AUTH
============================================================ */

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ?? 0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ?? 0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION['lovemi_session_token']
            ?? ''
        )
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    exchangeUpdateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [],
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
            SELECT u.id

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


    $auth->execute(
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
        !$auth->fetch()
    ) {

        exchangeUpdateResponse(
            false,
            'You do not have permission to update exchange rates.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE UPDATE AUTH] '
        . $e->getMessage()
    );

    exchangeUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   INPUT VALUES
============================================================ */

$id =
    isset($input['id'])
        &&
        $input['id'] !== null
        &&
        $input['id'] !== ''
    ?
    (int)$input['id']
    :
    0;


$baseCurrencyId =
    (int)(
        $input['base_currency_id']
        ??
        0
    );


$targetCurrencyId =
    (int)(
        $input['target_currency_id']
        ??
        0
    );


$rateRaw =
    $input['rate']
    ??
    null;


$source =
    trim(
        (string)(
            $input['source']
            ??
            'manual_admin'
        )
    );


$effectiveAt =
    trim(
        (string)(
            $input['effective_at']
            ??
            ''
        )
    );


$isActive =
    filter_var(
        $input['is_active']
        ??
        true,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    $baseCurrencyId <= 0
    ||
    $targetCurrencyId <= 0
) {

    exchangeUpdateResponse(
        false,
        'Both base and target currencies are required.',
        [],
        422
    );

}


if (
    $baseCurrencyId ===
    $targetCurrencyId
) {

    exchangeUpdateResponse(
        false,
        'Base and target currencies must be different.',
        [],
        422
    );

}


if (
    $rateRaw === null
    ||
    $rateRaw === ''
    ||
    !is_numeric(
        (string)$rateRaw
    )
) {

    exchangeUpdateResponse(
        false,
        'A valid exchange rate is required.',
        [],
        422
    );

}


$rate =
    (float)$rateRaw;


if (
    !is_finite(
        $rate
    )
    ||
    $rate <= 0
) {

    exchangeUpdateResponse(
        false,
        'Exchange rate must be greater than zero.',
        [],
        422
    );

}


if (
    $rate > 9999999999
) {

    exchangeUpdateResponse(
        false,
        'Exchange rate is too large.',
        [],
        422
    );

}


if (
    mb_strlen(
        $source
    )
    >
    100
) {

    exchangeUpdateResponse(
        false,
        'Source is too long.',
        [],
        422
    );

}


/* ============================================================
   EFFECTIVE TIME
============================================================ */

if (
    $effectiveAt === ''
) {

    $effectiveAt =
        date(
            'Y-m-d H:i:s'
        );

} else {

    $normalizedDate =
        str_replace(
            'T',
            ' ',
            $effectiveAt
        );


    $timestamp =
        strtotime(
            $normalizedDate
        );


    if (
        $timestamp === false
    ) {

        exchangeUpdateResponse(
            false,
            'Invalid effective date/time.',
            [],
            422
        );

    }


    $effectiveAt =
        date(
            'Y-m-d H:i:s',
            $timestamp
        );

}


/* ============================================================
   CURRENCY CHECKS
============================================================ */

try {

    $currencyStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                code,
                is_active

            FROM currencies

            WHERE id IN
            (
                :base_id,
                :target_id
            )
            "
        );


    $currencyStmt->execute(
        [

            ':base_id' =>
                $baseCurrencyId,

            ':target_id' =>
                $targetCurrencyId

        ]
    );


    $currencyRows =
        $currencyStmt->fetchAll();


    if (
        count(
            $currencyRows
        )
        !==
        2
    ) {

        exchangeUpdateResponse(
            false,
            'One or both selected currencies do not exist.',
            [],
            422
        );

    }


    foreach (
        $currencyRows
        as $currency
    ) {

        if (
            (int)
            $currency['is_active']
            !==
            1
        ) {

            exchangeUpdateResponse(
                false,
                'Both currencies must be active.',
                [],
                422
            );

        }

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE CURRENCY CHECK] '
        . $e->getMessage()
    );

    exchangeUpdateResponse(
        false,
        'Unable to validate the selected currencies.',
        [],
        500
    );

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       EDIT EXISTING RECORD
    ======================================================== */

    if (
        $id > 0
    ) {

        $currentStmt =
            $pdo->prepare(
                "
                SELECT *

                FROM exchange_rates

                WHERE id = :id

                LIMIT 1

                FOR UPDATE
                "
            );


        $currentStmt->execute(
            [
                ':id' =>
                    $id
            ]
        );


        $current =
            $currentStmt->fetch();


        if (
            !$current
        ) {

            throw new RuntimeException(
                'RATE_NOT_FOUND'
            );

        }


        /*
         * If the edited pair/time is unchanged, update the row.
         * Otherwise check the unique pair/time before changing it.
         */

        $duplicateStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM exchange_rates

                WHERE

                    base_currency_id =
                        :base_currency_id

                    AND target_currency_id =
                        :target_currency_id

                    AND effective_at =
                        :effective_at

                    AND id <> :id

                LIMIT 1
                "
            );


        $duplicateStmt->execute(
            [

                ':base_currency_id' =>
                    $baseCurrencyId,

                ':target_currency_id' =>
                    $targetCurrencyId,

                ':effective_at' =>
                    $effectiveAt,

                ':id' =>
                    $id

            ]
        );


        if (
            $duplicateStmt->fetch()
        ) {

            throw new RuntimeException(
                'DUPLICATE_RATE_TIME'
            );

        }


        $update =
            $pdo->prepare(
                "
                UPDATE exchange_rates

                SET

                    base_currency_id =
                        :base_currency_id,

                    target_currency_id =
                        :target_currency_id,

                    rate =
                        :rate,

                    source =
                        :source,

                    effective_at =
                        :effective_at,

                    is_active =
                        :is_active

                WHERE id =
                    :id

                LIMIT 1
                "
            );


        $update->execute(
            [

                ':base_currency_id' =>
                    $baseCurrencyId,

                ':target_currency_id' =>
                    $targetCurrencyId,

                ':rate' =>
                    number_format(
                        $rate,
                        10,
                        '.',
                        ''
                    ),

                ':source' =>
                    $source
                    !==
                    ''
                        ?
                        $source
                        :
                        'manual_admin',

                ':effective_at' =>
                    $effectiveAt,

                ':is_active' =>
                    $isActive,

                ':id' =>
                    $id

            ]
        );


        $recordId =
            $id;


        $oldValues =
            $current;

    }

    /* ========================================================
       CREATE NEW RECORD
    ======================================================== */

    else {

        $duplicateStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM exchange_rates

                WHERE

                    base_currency_id =
                        :base_currency_id

                    AND target_currency_id =
                        :target_currency_id

                    AND effective_at =
                        :effective_at

                LIMIT 1
                "
            );


        $duplicateStmt->execute(
            [

                ':base_currency_id' =>
                    $baseCurrencyId,

                ':target_currency_id' =>
                    $targetCurrencyId,

                ':effective_at' =>
                    $effectiveAt

            ]
        );


        if (
            $duplicateStmt->fetch()
        ) {

            throw new RuntimeException(
                'DUPLICATE_RATE_TIME'
            );

        }


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
                    :is_active
                )
                "
            );


        $insert->execute(
            [

                ':base_currency_id' =>
                    $baseCurrencyId,

                ':target_currency_id' =>
                    $targetCurrencyId,

                ':rate' =>
                    number_format(
                        $rate,
                        10,
                        '.',
                        ''
                    ),

                ':source' =>
                    $source
                    !==
                    ''
                        ?
                        $source
                        :
                        'manual_admin',

                ':effective_at' =>
                    $effectiveAt,

                ':is_active' =>
                    $isActive

            ]
        );


        $recordId =
            (int)
            $pdo->lastInsertId();


        $oldValues =
            null;

    }


    /* ========================================================
       AUDIT
    ======================================================== */

    try {

        $newValues = [

            'id' =>
                $recordId,

            'base_currency_id' =>
                $baseCurrencyId,

            'target_currency_id' =>
                $targetCurrencyId,

            'rate' =>
                number_format(
                    $rate,
                    10,
                    '.',
                    ''
                ),

            'source' =>
                $source
                !==
                ''
                    ?
                    $source
                    :
                    'manual_admin',

            'effective_at' =>
                $effectiveAt,

            'is_active' =>
                $isActive

        ];


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
                    :action,
                    'exchange_rate',
                    :entity_id,
                    :old_values,
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

                ':action' =>
                    $id > 0
                        ?
                        'admin_update_exchange_rate'
                        :
                        'admin_create_exchange_rate',

                ':entity_id' =>
                    $recordId,

                ':old_values' =>
                    $oldValues === null
                        ?
                        null
                        :
                        json_encode(
                            $oldValues,
                            JSON_UNESCAPED_UNICODE
                        ),

                ':new_values' =>
                    json_encode(
                        $newValues,
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
            '[LOVEMI EXCHANGE UPDATE AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    exchangeUpdateResponse(
        true,
        $id > 0
            ?
            'Exchange rate updated successfully.'
            :
            'Exchange rate created successfully.',
        [
            'rate_id' =>
                $recordId
        ]
    );

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    switch (
        $e->getMessage()
    ) {

        case 'RATE_NOT_FOUND':

            exchangeUpdateResponse(
                false,
                'Exchange-rate record not found.',
                [],
                404
            );

        case 'DUPLICATE_RATE_TIME':

            exchangeUpdateResponse(
                false,
                'An exchange-rate record already exists for this currency pair at that exact effective time.',
                [
                    'code' =>
                        'DUPLICATE_RATE_TIME'
                ],
                409
            );

    }


    error_log(
        '[LOVEMI EXCHANGE UPDATE] '
        . $e->getMessage()
    );


    exchangeUpdateResponse(
        false,
        'Unable to save the exchange rate.',
        [],
        500
    );

}