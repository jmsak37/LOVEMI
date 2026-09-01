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


function servicesDeactivateResponse(
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


$input =
    json_decode(
        file_get_contents('php://input') ?: '{}',
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    servicesDeactivateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

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

    $pdo = db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

} catch (Throwable $e) {

    servicesDeactivateResponse(
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

    servicesDeactivateResponse(
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
                    :session_token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND p.slug = 'services.manage'

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

        servicesDeactivateResponse(
            false,
            'You do not have permission to deactivate services.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    servicesDeactivateResponse(
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

    servicesDeactivateResponse(
        false,
        'Invalid service ID.',
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
                name,
                slug,
                is_active

            FROM services

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


    $service =
        $find->fetch();


    if (
        !$service
    ) {

        throw new RuntimeException(
            'SERVICE_NOT_FOUND'
        );

    }


    /*
     * Deactivation is deliberately used instead of deletion
     * when a service may already have historical subscriptions.
     */

    $update =
        $pdo->prepare(
            "
            UPDATE services

            SET
                is_active = 0

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
                    'admin_deactivate_service',
                    'service',
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
                                $service['is_active']
                        ]
                    ),

                ':new_values' =>
                    json_encode(
                        [
                            'is_active' =>
                                0
                        ]
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR'] ?? null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT'] ?? null

            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI SERVICE DEACTIVATE AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    servicesDeactivateResponse(
        true,
        'Service deactivated successfully.',
        [
            'service_id' =>
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
        'SERVICE_NOT_FOUND'
    ) {

        servicesDeactivateResponse(
            false,
            'Service not found.',
            [],
            404
        );

    }


    error_log(
        '[LOVEMI SERVICE DEACTIVATE] '
        . $e->getMessage()
    );


    servicesDeactivateResponse(
        false,
        'Unable to deactivate the service.',
        [],
        500
    );

}