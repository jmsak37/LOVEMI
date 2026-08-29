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


function verifyUserResponse(
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

    verifyUserResponse(
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

    verifyUserResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


if ($userId <= 0) {

    verifyUserResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    verifyUserResponse(
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

    verifyUserResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    verifyUserResponse(
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

        verifyUserResponse(
            false,
            'You do not have permission to verify users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    verifyUserResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


/* ============================================================
   WHICH VERIFICATIONS
============================================================ */

$emailVerified =
    array_key_exists(
        'email_verified',
        $data
    )
        ?
        (!empty($data['email_verified']) ? 1 : 0)
        :
        1;


$phoneVerified =
    array_key_exists(
        'phone_verified',
        $data
    )
        ?
        (!empty($data['phone_verified']) ? 1 : 0)
        :
        1;


$identityVerified =
    array_key_exists(
        'identity_verified',
        $data
    )
        ?
        (!empty($data['identity_verified']) ? 1 : 0)
        :
        1;


$ageVerified =
    array_key_exists(
        'age_verified',
        $data
    )
        ?
        (!empty($data['age_verified']) ? 1 : 0)
        :
        1;


/* ============================================================
   USER
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email_verified,

                phone_verified,

                identity_verified,

                age_verified,

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


    $stmt->execute([
        ':user_id' => $userId
    ]);


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    verifyUserResponse(
        false,
        'Unable to load user.',
        [],
        500
    );

}


if (!$user) {

    verifyUserResponse(
        false,
        'User not found.',
        [],
        404
    );

}


if (
    (int)$user['is_deleted'] === 1
) {

    verifyUserResponse(
        false,
        'A deleted account cannot be verified.',
        [],
        409
    );

}


/* ============================================================
   UPDATE
============================================================ */

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE users

            SET

                email_verified = :email_verified,

                phone_verified = :phone_verified,

                identity_verified = :identity_verified,

                age_verified = :age_verified,

                updated_at = CURRENT_TIMESTAMP

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $update->execute([

        ':email_verified' =>
            $emailVerified,

        ':phone_verified' =>
            $phoneVerified,

        ':identity_verified' =>
            $identityVerified,

        ':age_verified' =>
            $ageVerified,

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
                'admin_user_verification_updated',
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
                [
                    'email_verified' =>
                        (int)$user['email_verified'],

                    'phone_verified' =>
                        (int)$user['phone_verified'],

                    'identity_verified' =>
                        (int)$user['identity_verified'],

                    'age_verified' =>
                        (int)$user['age_verified']
                ],
                JSON_UNESCAPED_UNICODE
            ),

        ':new_values' =>
            json_encode(
                [
                    'email_verified' =>
                        $emailVerified,

                    'phone_verified' =>
                        $phoneVerified,

                    'identity_verified' =>
                        $identityVerified,

                    'age_verified' =>
                        $ageVerified
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
        '[LOVEMI VERIFY USER] ' .
        $e->getMessage()
    );

    verifyUserResponse(
        false,
        'Unable to update verification status.',
        [],
        500
    );

}


verifyUserResponse(
    true,
    'User verification updated successfully.',
    [
        'data' => [

            'user_id' =>
                $userId,

            'email_verified' =>
                $emailVerified,

            'phone_verified' =>
                $phoneVerified,

            'identity_verified' =>
                $identityVerified,

            'age_verified' =>
                $ageVerified

        ]
    ]
);