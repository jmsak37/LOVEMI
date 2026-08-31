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


function deleteUserResponse(
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

    deleteUserResponse(
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

    deleteUserResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if ($userId <= 0) {

    deleteUserResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


if ($userId === $adminId) {

    deleteUserResponse(
        false,
        'You cannot delete your own administrator account.',
        [],
        403
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    deleteUserResponse(
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

                u.role_id,

                r.is_admin_role

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

    deleteUserResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    deleteUserResponse(
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

        deleteUserResponse(
            false,
            'You do not have permission to delete users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    deleteUserResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


try {

    $oldStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                username,
                full_names,
                email,
                role_id,
                account_status,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $oldStmt->execute([
        ':user_id' => $userId
    ]);


    $old =
        $oldStmt->fetch();

} catch (Throwable $e) {

    deleteUserResponse(
        false,
        'Unable to load user.',
        [],
        500
    );

}


if (!$old) {

    deleteUserResponse(
        false,
        'User not found.',
        [],
        404
    );

}


if (
    (int)$old['is_deleted'] === 1
) {

    deleteUserResponse(
        false,
        'This user has already been deleted.',
        [],
        409
    );

}


try {

    $pdo->beginTransaction();


    /*
     * Soft delete account rather than physically deleting
     * the user record. This preserves foreign-key history.
     */

    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                is_active = 0,

                is_suspended = 1,

                is_deleted = 1,

                account_status = 'deleted',

                updated_at = CURRENT_TIMESTAMP

            WHERE
                id = :user_id

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
            'USER_DELETE_FAILED'
        );

    }


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
                'admin_user_deleted',
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
            $adminId,

        ':entity_id' =>
            $userId,

        ':old_values' =>
            json_encode(
                $old,
                JSON_UNESCAPED_UNICODE
            ),

        ':new_values' =>
            json_encode(
                [
                    'is_active' => 0,
                    'is_suspended' => 1,
                    'is_deleted' => 1,
                    'account_status' => 'deleted'
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
        '[LOVEMI DELETE USER] ' .
        $e->getMessage()
    );

    deleteUserResponse(
        false,
        'Unable to delete this user.',
        [],
        500
    );

}


deleteUserResponse(
    true,
    'User account deleted successfully.'
);