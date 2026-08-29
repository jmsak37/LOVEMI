<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');

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


function suspendResponse(
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

    suspendResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


$adminId =
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


$data =
    json_decode(
        file_get_contents('php://input') ?: '{}',
        true
    );


if (!is_array($data)) {
    $data = $_POST;
}


$userId =
    (int)(
        $data['user_id']
        ??
        $data['id']
        ??
        0
    );


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    suspendResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if ($userId <= 0) {

    suspendResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


if ($userId === $adminId) {

    suspendResponse(
        false,
        'You cannot suspend your own administrator account.',
        [],
        403
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    suspendResponse(
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
        ':admin_id' => $adminId,
        ':session_id' => $sessionId,
        ':token_hash' => $tokenHash
    ]);


    $admin =
        $auth->fetch();

} catch (Throwable $e) {

    suspendResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    suspendResponse(
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

                AND p.slug = 'users.manage'
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

        suspendResponse(
            false,
            'You do not have permission to suspend users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    suspendResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                is_active = 0,

                is_suspended = 1,

                account_status = 'suspended',

                updated_at = CURRENT_TIMESTAMP

            WHERE

                id = :user_id

                AND is_deleted = 0

            LIMIT 1
            "
        );


    $update->execute([
        ':user_id' => $userId
    ]);


    if (
        $update->rowCount() !== 1
    ) {

        throw new RuntimeException(
            'USER_NOT_UPDATED'
        );

    }


    /*
     * Revoke active sessions so the suspended user cannot
     * continue using an existing authenticated session.
     */

    $revoke =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET revoked_at =
                CURRENT_TIMESTAMP

            WHERE
                user_id = :user_id

                AND revoked_at IS NULL
            "
        );


    $revoke->execute([
        ':user_id' => $userId
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
                'admin_user_suspended',
                'user',
                :entity_id,
                NULL,
                :new_values,
                :ip,
                :agent
            )
            "
        );


    $audit->execute([

        ':user_id' =>
            $adminId,

        ':entity_id' =>
            $userId,

        ':new_values' =>
            json_encode(
                [
                    'is_active' => 0,
                    'is_suspended' => 1,
                    'account_status' => 'suspended'
                ],
                JSON_UNESCAPED_UNICODE
            ),

        ':ip' =>
            $_SERVER['REMOTE_ADDR'] ?? null,

        ':agent' =>
            $_SERVER['HTTP_USER_AGENT'] ?? null

    ]);


    $pdo->commit();

} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        '[LOVEMI SUSPEND USER] ' .
        $e->getMessage()
    );

    suspendResponse(
        false,
        'Unable to suspend this user.',
        [],
        500
    );

}


suspendResponse(
    true,
    'User suspended successfully.'
);