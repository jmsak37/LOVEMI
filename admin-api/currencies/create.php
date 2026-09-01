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


function currencyCreateResponse(
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

    currencyCreateResponse(
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
   DB
============================================================ */

try {

    $pdo = db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CURRENCY CREATE DB] '
        . $e->getMessage()
    );

    currencyCreateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   AUTH
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

    currencyCreateResponse(
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

                AND p.slug = 'currencies.manage'

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

        currencyCreateResponse(
            false,
            'You do not have permission to create currencies.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CURRENCY CREATE AUTH] '
        . $e->getMessage()
    );

    currencyCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   INPUT VALUES
============================================================ */

$code =
    strtoupper(
        trim(
            (string)(
                $input['code']
                ??
                ''
            )
        )
    );


$name =
    trim(
        (string)(
            $input['name']
            ??
            ''
        )
    );


$symbol =
    trim(
        (string)(
            $input['symbol']
            ??
            ''
        )
    );


$decimalPlaces =
    (int)(
        $input['decimal_places']
        ??
        2
    );


$isBase =
    filter_var(
        $input['is_base']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


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
    !preg_match(
        '/^[A-Z0-9]{2,10}$/',
        $code
    )
) {

    currencyCreateResponse(
        false,
        'Currency code must contain 2 to 10 uppercase letters or numbers.',
        [],
        422
    );

}


if (
    $name === ''
) {

    currencyCreateResponse(
        false,
        'Currency name is required.',
        [],
        422
    );

}


if (
    mb_strlen($name) > 100
) {

    currencyCreateResponse(
        false,
        'Currency name cannot exceed 100 characters.',
        [],
        422
    );

}


if (
    $symbol === ''
) {

    currencyCreateResponse(
        false,
        'Currency symbol is required.',
        [],
        422
    );

}


if (
    mb_strlen($symbol) > 20
) {

    currencyCreateResponse(
        false,
        'Currency symbol cannot exceed 20 characters.',
        [],
        422
    );

}


if (
    $decimalPlaces < 0
    ||
    $decimalPlaces > 9
) {

    currencyCreateResponse(
        false,
        'Decimal places must be between 0 and 9.',
        [],
        422
    );

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       DUPLICATE CODE
    ======================================================== */

    $codeCheck =
        $pdo->prepare(
            "
            SELECT id

            FROM currencies

            WHERE code = :code

            LIMIT 1
            "
        );


    $codeCheck->execute(
        [
            ':code' =>
                $code
        ]
    );


    if (
        $codeCheck->fetch()
    ) {

        throw new RuntimeException(
            'DUPLICATE_CODE'
        );

    }


    /* ========================================================
       BASE CURRENCY
    ======================================================== */

    if (
        $isBase === 1
    ) {

        $baseCheck =
            $pdo->query(
                "
                SELECT id

                FROM currencies

                WHERE is_base = 1

                LIMIT 1
                "
            );


        if (
            $baseCheck->fetch()
        ) {

            throw new RuntimeException(
                'BASE_CURRENCY_EXISTS'
            );

        }

    }


    /* ========================================================
       INSERT
    ======================================================== */

    $insert =
        $pdo->prepare(
            "
            INSERT INTO currencies
            (
                code,
                name,
                symbol,
                decimal_places,
                is_base,
                is_active
            )
            VALUES
            (
                :code,
                :name,
                :symbol,
                :decimal_places,
                :is_base,
                :is_active
            )
            "
        );


    $insert->execute(
        [

            ':code' =>
                $code,

            ':name' =>
                $name,

            ':symbol' =>
                $symbol,

            ':decimal_places' =>
                $decimalPlaces,

            ':is_base' =>
                $isBase,

            ':is_active' =>
                $isActive

        ]
    );


    $currencyId =
        (int)
        $pdo->lastInsertId();


    /* ========================================================
       AUDIT
    ======================================================== */

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
                    'admin_create_currency',
                    'currency',
                    :entity_id,
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

                ':entity_id' =>
                    $currencyId,

                ':new_values' =>
                    json_encode(
                        [

                            'code' =>
                                $code,

                            'name' =>
                                $name,

                            'symbol' =>
                                $symbol,

                            'decimal_places' =>
                                $decimalPlaces,

                            'is_base' =>
                                $isBase,

                            'is_active' =>
                                $isActive

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

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI CURRENCY CREATE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();


    currencyCreateResponse(
        true,
        'Currency created successfully.',
        [
            'currency_id' =>
                $currencyId
        ]
    );

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    if (
        $e->getMessage()
        ===
        'DUPLICATE_CODE'
    ) {

        currencyCreateResponse(
            false,
            'A currency with this code already exists.',
            [
                'code' =>
                    'DUPLICATE_CODE'
            ],
            409
        );

    }


    if (
        $e->getMessage()
        ===
        'BASE_CURRENCY_EXISTS'
    ) {

        currencyCreateResponse(
            false,
            'A base currency already exists. Only one currency may be the LOVEMI base currency.',
            [
                'code' =>
                    'BASE_CURRENCY_EXISTS'
            ],
            409
        );

    }


    error_log(
        '[LOVEMI CURRENCY CREATE] '
        . $e->getMessage()
    );


    currencyCreateResponse(
        false,
        'Unable to create the currency.',
        [],
        500
    );

}