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


function servicesDeleteResponse(
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


$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        $raw ?: '{}',
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    servicesDeleteResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

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

    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES DELETE DB] '
        . $e->getMessage()
    );

    servicesDeleteResponse(
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

    servicesDeleteResponse(
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
            ':admin_id' => $adminId,
            ':session_id' => $sessionId,
            ':session_token_hash' => $sessionTokenHash
        ]
    );

    if (!$auth->fetch()) {

        servicesDeleteResponse(
            false,
            'You do not have permission to delete services.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES DELETE AUTH] '
        . $e->getMessage()
    );

    servicesDeleteResponse(
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


if (
    $id <= 0
) {

    servicesDeleteResponse(
        false,
        'Invalid service ID.',
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

            FROM services

            WHERE id = :id

            LIMIT 1

            FOR UPDATE
            "
        );


    $find->execute(
        [
            ':id' => $id
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
     * Explicit relationship check.
     *
     * Existing subscriptions are important historical records,
     * therefore a service referenced by subscriptions should not
     * be physically deleted.
     */

    try {

        $subCheck =
            $pdo->prepare(
                "
                SELECT COUNT(*)

                FROM subscriptions

                WHERE service_id = :service_id
                "
            );


        $subCheck->execute(
            [
                ':service_id' =>
                    $id
            ]
        );


        $subscriptionCount =
            (int)
            $subCheck->fetchColumn();

    } catch (Throwable $relationshipError) {

        $subscriptionCount =
            0;

        error_log(
            '[LOVEMI SERVICE RELATIONSHIP CHECK] '
            .
            $relationshipError->getMessage()
        );

    }


    if (
        $subscriptionCount > 0
    ) {

        throw new RuntimeException(
            'SERVICE_HAS_SUBSCRIPTIONS'
        );

    }


    $delete =
        $pdo->prepare(
            "
            DELETE FROM services

            WHERE id = :id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':id' => $id
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
                    'admin_delete_service',
                    'service',
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
                        $service,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR'] ?? null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT'] ?? null

            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI SERVICE DELETE AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    servicesDeleteResponse(
        true,
        'Service deleted successfully.',
        [
            'service_id' =>
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


    $message =
        $e->getMessage();


    if (
        $message ===
        'SERVICE_NOT_FOUND'
    ) {

        servicesDeleteResponse(
            false,
            'Service not found.',
            [],
            404
        );

    }


    if (
        $message ===
        'SERVICE_HAS_SUBSCRIPTIONS'
    ) {

        servicesDeleteResponse(
            false,
            'This service cannot be permanently deleted because it already has subscription records. Deactivate it instead so historical records remain intact.',
            [
                'code' =>
                    'SERVICE_HAS_SUBSCRIPTIONS'
            ],
            409
        );

    }


    error_log(
        '[LOVEMI SERVICES DELETE] '
        . $message
    );


    servicesDeleteResponse(
        false,
        'Unable to delete the service.',
        [],
        500
    );

}