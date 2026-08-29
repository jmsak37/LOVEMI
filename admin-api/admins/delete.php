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


function adminDeleteResponse(
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

    adminDeleteResponse(
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

    adminDeleteResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if (
    $targetId <= 0
) {

    adminDeleteResponse(
        false,
        'A valid administrator ID is required.',
        [],
        422
    );

}


if (
    $targetId ===
    $currentAdminId
) {

    adminDeleteResponse(
        false,
        'You cannot delete your own administrator account from this page.',
        [],
        403
    );

}


try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    adminDeleteResponse(
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


/* ============================================================
   CURRENT ADMIN
============================================================ */

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

    adminDeleteResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    adminDeleteResponse(
        false,
        'Administrator access is required.',
        [],
        403
    );

}


/* ============================================================
   PERMISSION
============================================================ */

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

        adminDeleteResponse(
            false,
            'You do not have permission to remove administrators.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    adminDeleteResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


/* ============================================================
   TARGET
============================================================ */

try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.role_id,

                u.account_status,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role

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

    adminDeleteResponse(
        false,
        'Unable to load administrator.',
        [],
        500
    );

}


if (!$target) {

    adminDeleteResponse(
        false,
        'Administrator not found.',
        [],
        404
    );

}


if (
    (int)$target['is_admin_role'] !== 1
) {

    adminDeleteResponse(
        false,
        'This account is not an administrator.',
        [],
        409
    );

}


if (
    (int)$target['is_deleted'] === 1
) {

    adminDeleteResponse(
        false,
        'This administrator has already been removed.',
        [],
        409
    );

}


/* ============================================================
   PROTECT LAST ACTIVE ADMINISTRATOR
============================================================ */

try {

    $countStmt =
        $pdo->query(
            "
            SELECT COUNT(*)

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE

                r.slug = 'admin'

                AND r.is_admin_role = 1

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0
            "
        );


    $activePrimaryAdmins =
        (int)$countStmt->fetchColumn();

} catch (
    Throwable $e
) {

    adminDeleteResponse(
        false,
        'Unable to check administrator safety rules.',
        [],
        500
    );

}


if (
    $target['role_slug'] ===
    'admin'
    &&
    $activePrimaryAdmins <= 1
) {

    adminDeleteResponse(
        false,
        'The last active Administrator account cannot be removed.',
        [
            'code' =>
                'LAST_ADMIN_PROTECTED'
        ],
        409
    );

}


/* ============================================================
   SOFT DELETE
============================================================ */

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                is_active = 0,

                is_suspended = 1,

                is_deleted = 1,

                account_status = 'deleted',

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


    if (
        $update->rowCount() !==
        1
    ) {

        throw new RuntimeException(
            'ADMIN_DELETE_FAILED'
        );

    }


    /*
     * Revoke all active sessions.
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
                'admin_deleted',
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
                    'username' =>
                        $target['username'],

                    'full_names' =>
                        $target['full_names'],

                    'email' =>
                        $target['email'],

                    'role_id' =>
                        (int)$target['role_id'],

                    'role_name' =>
                        $target['role_name'],

                    'account_status' =>
                        $target['account_status']

                ],
                JSON_UNESCAPED_UNICODE
            ),

        ':new_values' =>
            json_encode(
                [
                    'is_active' =>
                        0,

                    'is_suspended' =>
                        1,

                    'is_deleted' =>
                        1,

                    'account_status' =>
                        'deleted'

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
        '[LOVEMI DELETE ADMIN] ' .
        $e->getMessage()
    );


    adminDeleteResponse(
        false,
        'Unable to remove administrator.',
        [],
        500
    );

}


adminDeleteResponse(
    true,
    'Administrator removed successfully.'
);