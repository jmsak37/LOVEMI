<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

ini_set('display_errors', '0');
error_reporting(E_ALL);


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


function userUpdateResponse(
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

    userUpdateResponse(
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


if (
    $adminId <= 0 ||
    $sessionId <= 0 ||
    $sessionToken === ''
) {

    userUpdateResponse(
        false,
        'You must log in first.',
        [],
        401
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


$userId =
    (int)(
        $data['user_id']
        ??
        $data['id']
        ??
        0
    );


if ($userId <= 0) {

    userUpdateResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


try {

    $pdo = db();

} catch (Throwable $e) {

    userUpdateResponse(
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

    userUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    userUpdateResponse(
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

        userUpdateResponse(
            false,
            'You do not have permission to update users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    userUpdateResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


/* ============================================================
   LOAD OLD
============================================================ */

try {

    $oldStmt =
        $pdo->prepare(
            "
            SELECT *

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

    userUpdateResponse(
        false,
        'Unable to load current user.',
        [],
        500
    );

}


if (!$old) {

    userUpdateResponse(
        false,
        'User not found.',
        [],
        404
    );

}


/* ============================================================
   INPUT
============================================================ */

$username =
    trim(
        (string)(
            $data['username']
            ??
            $old['username']
        )
    );


$fullNames =
    trim(
        (string)(
            $data['full_names']
            ??
            $old['full_names']
        )
    );


$gender =
    trim(
        (string)(
            $data['gender']
            ??
            $old['gender']
        )
    );


$email =
    strtolower(
        trim(
            (string)(
                $data['email']
                ??
                $old['email']
            )
        )
    );


$countryId =
    (int)(
        $data['country_id']
        ??
        $old['country_id']
    );


$phoneNumber =
    trim(
        (string)(
            $data['phone_number']
            ??
            $old['phone_number']
        )
    );


$phoneE164 =
    trim(
        (string)(
            $data['phone_e164']
            ??
            $old['phone_e164']
        )
    );


$roleId =
    (int)(
        $data['role_id']
        ??
        $old['role_id']
    );


$accountStatus =
    strtolower(
        trim(
            (string)(
                $data['account_status']
                ??
                $old['account_status']
            )
        )
    );


$dateOfBirth =
    trim(
        (string)(
            $data['date_of_birth']
            ??
            ($old['date_of_birth'] ?? '')
        )
    );


$emailVerified =
    !empty(
        $data['email_verified']
    )
        ? 1
        : 0;


$phoneVerified =
    !empty(
        $data['phone_verified']
    )
        ? 1
        : 0;


$identityVerified =
    !empty(
        $data['identity_verified']
    )
        ? 1
        : 0;


$ageVerified =
    !empty(
        $data['age_verified']
    )
        ? 1
        : 0;


$twoFactorEnabled =
    !empty(
        $data['two_factor_enabled']
    )
        ? 1
        : 0;


if (
    $username === '' ||
    $fullNames === '' ||
    $gender === '' ||
    $email === '' ||
    $countryId <= 0 ||
    $phoneNumber === '' ||
    $phoneE164 === '' ||
    $roleId <= 0
) {

    userUpdateResponse(
        false,
        'Required user fields are missing.',
        [],
        422
    );

}


if (
    !in_array(
        $accountStatus,
        [
            'pending',
            'approved',
            'suspended',
            'blocked'
        ],
        true
    )
) {

    userUpdateResponse(
        false,
        'Invalid account status.',
        [],
        422
    );

}


if (
    !in_array(
        $gender,
        [
            'Male',
            'Female'
        ],
        true
    )
) {

    userUpdateResponse(
        false,
        'Invalid gender.',
        [],
        422
    );

}


if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    userUpdateResponse(
        false,
        'Invalid email address.',
        [],
        422
    );

}


/* ============================================================
   DUPLICATE CHECK
============================================================ */

try {

    $duplicate =
        $pdo->prepare(
            "
            SELECT id

            FROM users

            WHERE

                id <> :user_id

                AND
                (
                    LOWER(username) =
                        LOWER(:username)

                    OR LOWER(email) =
                        LOWER(:email)
                )

            LIMIT 1
            "
        );


    $duplicate->execute([
        ':user_id' => $userId,
        ':username' => $username,
        ':email' => $email
    ]);


    if ($duplicate->fetch()) {

        userUpdateResponse(
            false,
            'Username or email already belongs to another account.',
            [],
            409
        );

    }

} catch (Throwable $e) {

    userUpdateResponse(
        false,
        'Unable to check duplicate account details.',
        [],
        500
    );

}


/* ============================================================
   ROLE/Country
============================================================ */

try {

    $roleStmt =
        $pdo->prepare(
            "
            SELECT id
            FROM roles
            WHERE id = :role_id
            LIMIT 1
            "
        );


    $roleStmt->execute([
        ':role_id' => $roleId
    ]);


    if (!$roleStmt->fetch()) {

        userUpdateResponse(
            false,
            'Selected role does not exist.',
            [],
            422
        );

    }


    $countryStmt =
        $pdo->prepare(
            "
            SELECT id
            FROM countries
            WHERE
                id = :country_id
                AND is_active = 1
            LIMIT 1
            "
        );


    $countryStmt->execute([
        ':country_id' => $countryId
    ]);


    if (!$countryStmt->fetch()) {

        userUpdateResponse(
            false,
            'Selected country does not exist or is inactive.',
            [],
            422
        );

    }

} catch (Throwable $e) {

    userUpdateResponse(
        false,
        'Unable to validate role or country.',
        [],
        500
    );

}


if (
    $dateOfBirth !== ''
) {

    $dob =
        DateTime::createFromFormat(
            'Y-m-d',
            $dateOfBirth
        );


    if (
        !$dob
        ||
        $dob->format('Y-m-d') !==
        $dateOfBirth
    ) {

        userUpdateResponse(
            false,
            'Invalid date of birth.',
            [],
            422
        );

    }

} else {

    $dateOfBirth = null;

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

                role_id = :role_id,

                username = :username,

                full_names = :full_names,

                gender = :gender,

                email = :email,

                country_id = :country_id,

                phone_number = :phone_number,

                phone_e164 = :phone_e164,

                date_of_birth = :date_of_birth,

                account_status = :account_status,

                email_verified = :email_verified,

                phone_verified = :phone_verified,

                identity_verified = :identity_verified,

                age_verified = :age_verified,

                two_factor_enabled = :two_factor_enabled,

                is_active =
                    CASE
                        WHEN :account_status =
                            'suspended'
                        THEN 0
                        ELSE is_active
                    END,

                is_suspended =
                    CASE
                        WHEN :account_status =
                            'suspended'
                        THEN 1
                        ELSE 0
                    END,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $update->execute([
        ':role_id' => $roleId,
        ':username' => $username,
        ':full_names' => $fullNames,
        ':gender' => $gender,
        ':email' => $email,
        ':country_id' => $countryId,
        ':phone_number' => $phoneNumber,
        ':phone_e164' => $phoneE164,
        ':date_of_birth' => $dateOfBirth,
        ':account_status' => $accountStatus,
        ':email_verified' => $emailVerified,
        ':phone_verified' => $phoneVerified,
        ':identity_verified' => $identityVerified,
        ':age_verified' => $ageVerified,
        ':two_factor_enabled' => $twoFactorEnabled,
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
                'admin_user_updated',
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
                    'role_id' => $roleId,
                    'username' => $username,
                    'full_names' => $fullNames,
                    'gender' => $gender,
                    'email' => $email,
                    'country_id' => $countryId,
                    'phone_number' => $phoneNumber,
                    'phone_e164' => $phoneE164,
                    'account_status' => $accountStatus,
                    'email_verified' => $emailVerified,
                    'phone_verified' => $phoneVerified,
                    'identity_verified' => $identityVerified,
                    'age_verified' => $ageVerified,
                    'two_factor_enabled' => $twoFactorEnabled
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
        '[LOVEMI UPDATE USER] ' .
        $e->getMessage()
    );

    userUpdateResponse(
        false,
        'Unable to update user.',
        [],
        500
    );

}


userUpdateResponse(
    true,
    'User updated successfully.',
    [
        'data' => [
            'user_id' => $userId
        ]
    ]
);