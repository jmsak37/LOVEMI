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


function currencyActivateResponse(
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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    currencyActivateResponse(
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
    !is_array($input)
) {

    $input =
        $_POST;

}


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


try {

    $pdo =
        db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

} catch (Throwable $e) {

    currencyActivateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


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

    currencyActivateResponse(
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

        currencyActivateResponse(
            false,
            'You do not have permission to activate currencies.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    currencyActivateResponse(
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

    currencyActivateResponse(
        false,
        'Invalid currency ID.',
        [],
        422
    );

}


try {

    $pdo->beginTransaction();


    $find =
        $pdo->prepare(
            "
            SELECT

                id,
                code,
                is_active

            FROM currencies

            WHERE id = :id

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


    $currency =
        $find->fetch();


    if (
        !$currency
    ) {

        throw new RuntimeException(
            'CURRENCY_NOT_FOUND'
        );

    }


    $update =
        $pdo->prepare(
            "
            UPDATE currencies

            SET
                is_active = 1

            WHERE id = :id

            LIMIT 1
            "
        );


    $update->execute(
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
                    'admin_activate_currency',
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
                        [
                            'is_active' =>
                                $currency['is_active']
                        ]
                    ),

                ':new_values' =>
                    json_encode(
                        [
                            'is_active' =>
                                1
                        ]
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
            '[LOVEMI CURRENCY ACTIVATE AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    currencyActivateResponse(
        true,
        'Currency activated successfully.',
        [
            'currency_id' =>
                $id
        ]
    );

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    if (
        $e->getMessage()
        ===
        'CURRENCY_NOT_FOUND'
    ) {

        currencyActivateResponse(
            false,
            'Currency not found.',
            [],
            404
        );

    }


    error_log(
        '[LOVEMI CURRENCY ACTIVATE] '
        . $e->getMessage()
    );


    currencyActivateResponse(
        false,
        'Unable to activate the currency.',
        [],
        500
    );

}