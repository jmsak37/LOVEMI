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


function resetPasswordResponse(
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

    resetPasswordResponse(
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


$newPassword =
    (string)(
        $data['new_password']
        ??
        $data['password']
        ??
        ''
    );


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    resetPasswordResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if ($userId <= 0) {

    resetPasswordResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


if (
    strlen($newPassword) < 8
) {

    resetPasswordResponse(
        false,
        'New password must contain at least 8 characters.',
        [],
        422
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    resetPasswordResponse(
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

    resetPasswordResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    resetPasswordResponse(
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

        resetPasswordResponse(
            false,
            'You do not have permission to reset user passwords.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    resetPasswordResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                email,

                is_deleted

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $userStmt->execute([
        ':user_id' => $userId
    ]);


    $user =
        $userStmt->fetch();

} catch (Throwable $e) {

    resetPasswordResponse(
        false,
        'Unable to load user.',
        [],
        500
    );

}


if (!$user) {

    resetPasswordResponse(
        false,
        'User not found.',
        [],
        404
    );

}


if (
    (int)$user['is_deleted'] === 1
) {

    resetPasswordResponse(
        false,
        'Password cannot be reset for a deleted account.',
        [],
        409
    );

}


$passwordHash =
    password_hash(
        $newPassword,
        PASSWORD_DEFAULT
    );


if ($passwordHash === false) {

    resetPasswordResponse(
        false,
        'Unable to create a secure password hash.',
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

                password_hash = :password_hash,

                updated_at = CURRENT_TIMESTAMP

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $update->execute([
        ':password_hash' =>
            $passwordHash,

        ':user_id' =>
            $userId
    ]);


    /*
     * Revoke existing sessions to force the user to perform
     * the normal login + Google Authenticator process again.
     */

    $sessions =
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


    $sessions->execute([
        ':user_id' =>
            $userId
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
                'admin_user_password_reset',
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
                    'password_reset' => true,
                    'sessions_revoked' => true
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
        '[LOVEMI RESET PASSWORD] ' .
        $e->getMessage()
    );

    resetPasswordResponse(
        false,
        'Unable to reset the password.',
        [],
        500
    );

}


resetPasswordResponse(
    true,
    'Password reset successfully. Existing login sessions were revoked.'
);