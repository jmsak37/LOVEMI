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


function countriesCreateResponse(
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
   REQUEST
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    countriesCreateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
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
        '[LOVEMI COUNTRY CREATE DB] '
        .
        $e->getMessage()
    );


    countriesCreateResponse(
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

    countriesCreateResponse(
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

        countriesCreateResponse(
            false,
            'You do not have permission to create countries.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI COUNTRY CREATE AUTH] '
        .
        $e->getMessage()
    );


    countriesCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   INPUT
============================================================ */

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
        true,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    $name === ''
) {

    countriesCreateResponse(
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

    countriesCreateResponse(
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

    countriesCreateResponse(
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

    countriesCreateResponse(
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

    countriesCreateResponse(
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

    countriesCreateResponse(
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
        (int)
        $currencyId
        <=
        0
    ) {

        countriesCreateResponse(
            false,
            'Invalid currency.',
            [],
            422
        );

    }


    $currencyId =
        (int)
        $currencyId;


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

        countriesCreateResponse(
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
   DUPLICATE CHECK
============================================================ */

try {

    $check =
        $pdo->prepare(
            "
            SELECT

                id,
                name,
                iso2,
                iso3,
                phone_code

            FROM countries

            WHERE

                iso2 =
                    :iso2

                OR iso3 =
                    :iso3

                OR phone_code =
                    :phone_code

            LIMIT 1
            "
        );


    $check->execute(
        [

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


    $existing =
        $check->fetch();


    if (
        $existing
    ) {

        countriesCreateResponse(
            false,
            'A country with the same ISO or phone code already exists.',
            [
                'code' =>
                    'DUPLICATE_COUNTRY',

                'existing' =>
                    $existing
            ],
            409
        );

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI COUNTRY DUP CHECK] '
        .
        $e->getMessage()
    );


    countriesCreateResponse(
        false,
        'Unable to validate the country.',
        [],
        500
    );

}


/* ============================================================
   INSERT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO countries
            (
                name,
                iso2,
                iso3,
                phone_code,
                currency_id,
                flag_code,
                is_active
            )
            VALUES
            (
                :name,
                :iso2,
                :iso3,
                :phone_code,
                :currency_id,
                :flag_code,
                :is_active
            )
            "
        );


    $stmt->execute(
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
                $isActive

        ]
    );


    $countryId =
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
                    'admin_create_country',
                    'country',
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
                    $countryId,

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
            '[LOVEMI COUNTRY CREATE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    countriesCreateResponse(
        true,
        'Country created successfully.',
        [
            'country_id' =>
                $countryId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI COUNTRY CREATE] '
        .
        $e->getMessage()
    );


    if (
        stripos(
            $e->getMessage(),
            'duplicate'
        )
        !==
        false
    ) {

        countriesCreateResponse(
            false,
            'The country conflicts with an existing country record.',
            [
                'code' =>
                    'DUPLICATE_COUNTRY'
            ],
            409
        );

    }


    countriesCreateResponse(
        false,
        'Unable to create the country.',
        [],
        500
    );

}