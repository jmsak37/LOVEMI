<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

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


function countriesDeleteResponse(
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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    countriesDeleteResponse(
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

    countriesDeleteResponse(
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
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION['lovemi_session_token']
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

    countriesDeleteResponse(
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

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        countriesDeleteResponse(
            false,
            'You do not have permission to delete countries.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    countriesDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


$id =
    (int)(
        $input['id']
        ??
        0
    );


if (
    $id <= 0
) {

    countriesDeleteResponse(
        false,
        'Invalid country ID.',
        [],
        422
    );

}


/* ============================================================
   DELETE
============================================================ */

try {

    $pdo->beginTransaction();


    $find =
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


    $find->execute(
        [
            ':id' =>
                $id
        ]
    );


    $country =
        $find->fetch();


    if (
        !$country
    ) {

        throw new RuntimeException(
            'COUNTRY_NOT_FOUND'
        );

    }


    /*
     * Check direct references from users.
     *
     * Country deletion can break user registration/profile
     * references, so block destructive deletion when used.
     */

    $userCheck =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM users

            WHERE country_id =
                :country_id
            "
        );


    $userCheck->execute(
        [
            ':country_id' =>
                $id
        ]
    );


    $userCount =
        (int)
        $userCheck->fetchColumn();


    if (
        $userCount > 0
    ) {

        throw new RuntimeException(
            'COUNTRY_HAS_USERS'
        );

    }


    $delete =
        $pdo->prepare(
            "
            DELETE FROM countries

            WHERE id =
                :id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':id' =>
                $id
        ]
    );


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
                    'admin_delete_country',
                    'country',
                    :entity_id,
                    :old_values,
                    NULL,
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
                        $country,
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
            '[LOVEMI COUNTRY DELETE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();


    countriesDeleteResponse(
        true,
        'Country deleted successfully.',
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

        countriesDeleteResponse(
            false,
            'Country not found.',
            [],
            404
        );

    }


    if (
        $e->getMessage()
        ===
        'COUNTRY_HAS_USERS'
    ) {

        countriesDeleteResponse(
            false,
            'This country cannot be permanently deleted because users are already assigned to it. Deactivate the country instead.',
            [
                'code' =>
                    'COUNTRY_HAS_USERS',

                'country_id' =>
                    $id
            ],
            409
        );

    }


    error_log(
        '[LOVEMI COUNTRY DELETE] '
        .
        $e->getMessage()
    );


    /*
     * Handle unexpected foreign-key restrictions cleanly.
     */

    if (
        stripos(
            $e->getMessage(),
            'foreign key'
        ) !== false
    ) {

        countriesDeleteResponse(
            false,
            'This country is still referenced by other LOVEMI records. Deactivate it instead of deleting it.',
            [
                'code' =>
                    'COUNTRY_REFERENCED'
            ],
            409
        );

    }


    countriesDeleteResponse(
        false,
        'Unable to delete the country.',
        [],
        500
    );

}