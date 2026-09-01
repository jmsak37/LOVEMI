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


function currencyUpdateResponse(
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

    currencyUpdateResponse(
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CURRENCY UPDATE DB] '
        . $e->getMessage()
    );

    currencyUpdateResponse(
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

    currencyUpdateResponse(
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

        currencyUpdateResponse(
            false,
            'You do not have permission to update currencies.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CURRENCY UPDATE AUTH] '
        . $e->getMessage()
    );

    currencyUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   VALUES
============================================================ */

$id =
    (int)(
        $input['id']
        ??
        0
    );


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
        false,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    $id <= 0
) {

    currencyUpdateResponse(
        false,
        'Invalid currency ID.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[A-Z0-9]{2,10}$/',
        $code
    )
) {

    currencyUpdateResponse(
        false,
        'Currency code must contain 2 to 10 uppercase letters or numbers.',
        [],
        422
    );

}


if (
    $name === ''
    ||
    mb_strlen($name) > 100
) {

    currencyUpdateResponse(
        false,
        'Currency name is required and cannot exceed 100 characters.',
        [],
        422
    );

}


if (
    $symbol === ''
    ||
    mb_strlen($symbol) > 20
) {

    currencyUpdateResponse(
        false,
        'Currency symbol is required and cannot exceed 20 characters.',
        [],
        422
    );

}


if (
    $decimalPlaces < 0
    ||
    $decimalPlaces > 9
) {

    currencyUpdateResponse(
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
       CURRENT RECORD
    ======================================================== */

    $currentStmt =
        $pdo->prepare(
            "
            SELECT *

            FROM currencies

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
            'CURRENCY_NOT_FOUND'
        );

    }


    /* ========================================================
       DUPLICATE CODE
    ======================================================== */

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM currencies

            WHERE

                code = :code

                AND id <> :id

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [
            ':code' =>
                $code,

            ':id' =>
                $id
        ]
    );


    if (
        $duplicateStmt->fetch()
    ) {

        throw new RuntimeException(
            'DUPLICATE_CODE'
        );

    }


    /* ========================================================
       BASE CURRENCY PROTECTION
    ======================================================== */

    if (
        $isBase === 1
    ) {

        $baseStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM currencies

                WHERE
                    is_base = 1

                    AND id <> :id

                LIMIT 1

                FOR UPDATE
                "
            );


        $baseStmt->execute(
            [
                ':id' =>
                    $id
            ]
        );


        if (
            $baseStmt->fetch()
        ) {

            throw new RuntimeException(
                'BASE_CURRENCY_EXISTS'
            );

        }

    }


    /*
     * Do not allow the active base currency to become
     * inactive. It would leave the application without
     * an active base currency.
     */

    if (
        (int)$current['is_base'] === 1
        &&
        $isActive === 0
    ) {

        throw new RuntimeException(
            'BASE_CURRENCY_MUST_BE_ACTIVE'
        );

    }


    /* ========================================================
       UPDATE
    ======================================================== */

    $update =
        $pdo->prepare(
            "
            UPDATE currencies

            SET

                code =
                    :code,

                name =
                    :name,

                symbol =
                    :symbol,

                decimal_places =
                    :decimal_places,

                is_base =
                    :is_base,

                is_active =
                    :is_active

            WHERE
                id = :id

            LIMIT 1
            "
        );


    $update->execute(
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
                $isActive,

            ':id' =>
                $id

        ]
    );


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
                    'admin_update_currency',
                    'currency',
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

                ':entity_id' =>
                    $id,

                ':old_values' =>
                    json_encode(
                        $current,
                        JSON_UNESCAPED_UNICODE
                    ),

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
            '[LOVEMI CURRENCY UPDATE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();


    currencyUpdateResponse(
        true,
        'Currency updated successfully.',
        [
            'currency_id' =>
                $id
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


    switch (
        $e->getMessage()
    ) {

        case 'CURRENCY_NOT_FOUND':

            currencyUpdateResponse(
                false,
                'Currency not found.',
                [
                    'code' =>
                        'CURRENCY_NOT_FOUND'
                ],
                404
            );

        case 'DUPLICATE_CODE':

            currencyUpdateResponse(
                false,
                'Another currency already uses this code.',
                [
                    'code' =>
                        'DUPLICATE_CODE'
                ],
                409
            );

        case 'BASE_CURRENCY_EXISTS':

            currencyUpdateResponse(
                false,
                'Another base currency already exists.',
                [
                    'code' =>
                        'BASE_CURRENCY_EXISTS'
                ],
                409
            );

        case 'BASE_CURRENCY_MUST_BE_ACTIVE':

            currencyUpdateResponse(
                false,
                'The LOVEMI base currency must remain active.',
                [
                    'code' =>
                        'BASE_CURRENCY_MUST_BE_ACTIVE'
                ],
                409
            );

    }


    error_log(
        '[LOVEMI CURRENCY UPDATE] '
        . $e->getMessage()
    );


    currencyUpdateResponse(
        false,
        'Unable to update the currency.',
        [],
        500
    );

}