<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');


$isHttps =
    !empty($_SERVER['HTTPS']) &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax'
]);


if (
    session_status() !==
    PHP_SESSION_ACTIVE
) {
    session_start();
}


function adminActivateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'POST'
) {

    adminActivateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


$data =
    json_decode(
        file_get_contents('php://input') ?: '{}',
        true
    );


if (!is_array($data)) {
    $data = $_POST;
}


$currentAdminId =
    (int)(
        $_SESSION['lovemi_user_id'] ?? 0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id'] ?? 0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token'] ?? ''
    );


$targetId =
    (int)(
        $data['user_id']
        ??
        $data['admin_id']
        ??
        0
    );


if (
    $currentAdminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    adminActivateResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if (
    $targetId <= 0
) {

    adminActivateResponse(
        false,
        'A valid administrator ID is required.',
        [],
        422
    );

}


try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    adminActivateResponse(
        false,
        'Database connection failed.',
        [],
        500
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

                u.id,

                u.role_id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

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

            LIMIT 1
            "
        );


    $auth->execute([
        ':admin_id' =>
            $currentAdminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    adminActivateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    adminActivateResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


try {

    $permission =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                rp.role_id = :role_id

                AND p.slug = 'admins.manage'
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)$admin['role_id']
    ]);


    if (
        (int)$permission->fetchColumn() <=
        0
    ) {

        adminActivateResponse(
            false,
            'You do not have permission to activate administrators.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    adminActivateResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.account_status,

                u.is_deleted,

                r.is_admin_role,

                r.name AS role_name

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE
                u.id = :user_id

            LIMIT 1
            "
        );


    $targetStmt->execute([
        ':user_id' =>
            $targetId
    ]);


    $target =
        $targetStmt->fetch();

} catch (
    Throwable $e
) {

    adminActivateResponse(
        false,
        'Unable to load administrator.',
        [],
        500
    );

}


if (!$target) {

    adminActivateResponse(
        false,
        'Administrator not found.',
        [],
        404
    );

}


if (
    (int)$target['is_admin_role'] !== 1
) {

    adminActivateResponse(
        false,
        'This account does not have an administrator role.',
        [],
        409
    );

}


if (
    (int)$target['is_deleted'] === 1
) {

    adminActivateResponse(
        false,
        'A deleted administrator cannot be activated.',
        [],
        409
    );

}


try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                is_active = 1,

                is_suspended = 0,

                account_status = 'approved',

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $update->execute([
        ':user_id' =>
            $targetId
    ]);


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
                'admin_activated',
                'user',
                :entity_id,
                :old_values,
                :new_values,
                :ip,
                :agent
            )
            "
        );


    $audit->execute([

        ':user_id' =>
            $currentAdminId,

        ':entity_id' =>
            $targetId,

        ':old_values' =>
            json_encode(
                [
                    'account_status' =>
                        $target['account_status']
                ],
                JSON_UNESCAPED_UNICODE
            ),

        ':new_values' =>
            json_encode(
                [
                    'account_status' =>
                        'approved',

                    'is_active' =>
                        1,

                    'is_suspended' =>
                        0

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

    ]);


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI ACTIVATE ADMIN] ' .
        $e->getMessage()
    );


    adminActivateResponse(
        false,
        'Unable to activate administrator.',
        [],
        500
    );

}


adminActivateResponse(
    true,
    'Administrator activated successfully.'
);