<?php

declare(strict_types=1);

error_reporting(E_ALL);

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'display_startup_errors',
    '0'
);

require_once
    __DIR__
    . '/../../config/database.php';


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


function countriesUpdateResponse(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    countriesUpdateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


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
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


/* ============================================================
   SESSION
============================================================ */

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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI COUNTRY UPDATE DB] '
        .
        $e->getMessage()
    );


    countriesUpdateResponse(
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

    countriesUpdateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [],
        401
    );

}


$sessionTokenHash =
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
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :session_token_hash

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
                    'countries.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':session_token_hash' =>
                $sessionTokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        countriesUpdateResponse(
            false,
            'You do not have permission to update countries.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI COUNTRY UPDATE AUTH] '
        .
        $e->getMessage()
    );


    countriesUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   INPUT
============================================================ */

$id =
    (int)(
        $input['id']
        ??
        0
    );


$name =
    trim(
        (string)(
            $input['name']
            ??
            ''
        )
    );


$iso2 =
    strtoupper(
        trim(
            (string)(
                $input['iso2']
                ??
                ''
            )
        )
    );


$iso3 =
    strtoupper(
        trim(
            (string)(
                $input['iso3']
                ??
                ''
            )
        )
    );


$phoneCode =
    trim(
        (string)(
            $input['phone_code']
            ??
            ''
        )
    );


$currencyId =
    $input['currency_id']
    ??
    null;


$flagCode =
    strtoupper(
        trim(
            (string)(
                $input['flag_code']
                ??
                ''
            )
        )
    );


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

    countriesUpdateResponse(
        false,
        'Invalid country ID.',
        [],
        422
    );

}


if (
    $name === ''
) {

    countriesUpdateResponse(
        false,
        'Country name is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $name
    )
    >
    120
) {

    countriesUpdateResponse(
        false,
        'Country name is too long.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[A-Z]{2}$/',
        $iso2
    )
) {

    countriesUpdateResponse(
        false,
        'ISO2 must contain exactly two letters.',
        [],
        422
    );

}


if (
    $iso3 !== ''
    &&
    !preg_match(
        '/^[A-Z]{3}$/',
        $iso3
    )
) {

    countriesUpdateResponse(
        false,
        'ISO3 must contain exactly three letters.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^\+\d{1,9}$/',
        $phoneCode
    )
) {

    countriesUpdateResponse(
        false,
        'Phone code must start with + and contain digits only.',
        [],
        422
    );

}


if (
    $flagCode === ''
) {

    $flagCode =
        $iso2;

}


if (
    mb_strlen(
        $flagCode
    )
    >
    10
) {

    countriesUpdateResponse(
        false,
        'Flag code is too long.',
        [],
        422
    );

}


/* ============================================================
   CURRENCY
============================================================ */

if (
    $currencyId !== null
    &&
    $currencyId !== ''
) {

    if (
        filter_var(
            $currencyId,
            FILTER_VALIDATE_INT
        ) === false
        ||
        (int)$currencyId <= 0
    ) {

        countriesUpdateResponse(
            false,
            'Invalid currency.',
            [],
            422
        );

    }


    $currencyId =
        (int)$currencyId;


    $currencyCheck =
        $pdo->prepare(
            "
            SELECT id

            FROM currencies

            WHERE

                id =
                    :id

                AND is_active =
                    1

            LIMIT 1
            "
        );


    $currencyCheck->execute(
        [
            ':id' =>
                $currencyId
        ]
    );


    if (
        !$currencyCheck->fetch()
    ) {

        countriesUpdateResponse(
            false,
            'The selected currency does not exist or is inactive.',
            [],
            422
        );

    }

} else {

    $currencyId =
        null;

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    $currentStmt =
        $pdo->prepare(
            "
            SELECT *

            FROM countries

            WHERE id =
                :id

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
            'COUNTRY_NOT_FOUND'
        );

    }


    /* ========================================================
       DUPLICATE ISO / PHONE
    ======================================================== */

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM countries

            WHERE

                id <> :id

                AND
                (
                    iso2 = :iso2

                    OR iso3 = :iso3

                    OR phone_code = :phone_code
                )

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':id' =>
                $id,

            ':iso2' =>
                $iso2,

            ':iso3' =>
                $iso3 !== ''
                    ?
                    $iso3
                    :
                    $iso2,

            ':phone_code' =>
                $phoneCode

        ]
    );


    if (
        $duplicateStmt->fetch()
    ) {

        throw new RuntimeException(
            'DUPLICATE_COUNTRY'
        );

    }


    /* ========================================================
       UPDATE
    ======================================================== */

    $update =
        $pdo->prepare(
            "
            UPDATE countries

            SET

                name =
                    :name,

                iso2 =
                    :iso2,

                iso3 =
                    :iso3,

                phone_code =
                    :phone_code,

                currency_id =
                    :currency_id,

                flag_code =
                    :flag_code,

                is_active =
                    :is_active

            WHERE

                id =
                    :id

            LIMIT 1
            "
        );


    $update->execute(
        [

            ':name' =>
                $name,

            ':iso2' =>
                $iso2,

            ':iso3' =>
                $iso3 !== ''
                    ?
                    $iso3
                    :
                    null,

            ':phone_code' =>
                $phoneCode,

            ':currency_id' =>
                $currencyId,

            ':flag_code' =>
                $flagCode,

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
                    'admin_update_country',
                    'country',
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

                            'name' =>
                                $name,

                            'iso2' =>
                                $iso2,

                            'iso3' =>
                                $iso3 !== ''
                                    ?
                                    $iso3
                                    :
                                    null,

                            'phone_code' =>
                                $phoneCode,

                            'currency_id' =>
                                $currencyId,

                            'flag_code' =>
                                $flagCode,

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
            '[LOVEMI COUNTRY UPDATE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();


    countriesUpdateResponse(
        true,
        'Country updated successfully.',
        [
            'country_id' =>
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


    if (
        $e->getMessage()
        ===
        'COUNTRY_NOT_FOUND'
    ) {

        countriesUpdateResponse(
            false,
            'Country not found.',
            [],
            404
        );

    }


    if (
        $e->getMessage()
        ===
        'DUPLICATE_COUNTRY'
    ) {

        countriesUpdateResponse(
            false,
            'Another country already uses the same ISO or phone code.',
            [
                'code' =>
                    'DUPLICATE_COUNTRY'
            ],
            409
        );

    }


    error_log(
        '[LOVEMI COUNTRY UPDATE] '
        .
        $e->getMessage()
    );


    countriesUpdateResponse(
        false,
        'Unable to update the country.',
        [],
        500
    );

}