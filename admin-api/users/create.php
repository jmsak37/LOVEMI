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


function userCreateResponse(
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

    userCreateResponse(
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

    userCreateResponse(
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


$username =
    trim(
        (string)(
            $data['username'] ?? ''
        )
    );


$fullNames =
    trim(
        (string)(
            $data['full_names'] ?? ''
        )
    );


$gender =
    trim(
        (string)(
            $data['gender'] ?? ''
        )
    );


$email =
    strtolower(
        trim(
            (string)(
                $data['email'] ?? ''
            )
        )
    );


$countryId =
    (int)(
        $data['country_id'] ?? 0
    );


$phoneNumber =
    trim(
        (string)(
            $data['phone_number'] ?? ''
        )
    );


$phoneE164 =
    trim(
        (string)(
            $data['phone_e164'] ?? ''
        )
    );


$roleId =
    (int)(
        $data['role_id'] ?? 1
    );


$dateOfBirth =
    trim(
        (string)(
            $data['date_of_birth'] ?? ''
        )
    );


$password =
    (string)(
        $data['password'] ?? ''
    );


$emailVerified =
    !empty($data['email_verified'])
        ? 1
        : 0;


$phoneVerified =
    !empty($data['phone_verified'])
        ? 1
        : 0;


$identityVerified =
    !empty($data['identity_verified'])
        ? 1
        : 0;


$ageVerified =
    !empty($data['age_verified'])
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
    $roleId <= 0 ||
    $password === ''
) {

    userCreateResponse(
        false,
        'Please complete all required fields.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[A-Za-z0-9_.-]{3,50}$/',
        $username
    )
) {

    userCreateResponse(
        false,
        'Username contains invalid characters.',
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

    userCreateResponse(
        false,
        'Please provide a valid email address.',
        [],
        422
    );

}


if (
    strlen($password) < 8
) {

    userCreateResponse(
        false,
        'Password must contain at least 8 characters.',
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

    userCreateResponse(
        false,
        'Invalid gender.',
        [],
        422
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

        userCreateResponse(
            false,
            'Invalid date of birth.',
            [],
            422
        );

    }

} else {

    $dateOfBirth = null;

}


try {

    $pdo = db();

} catch (Throwable $e) {

    userCreateResponse(
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

    userCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (!$admin) {

    userCreateResponse(
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

        userCreateResponse(
            false,
            'You do not have permission to create users.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    userCreateResponse(
        false,
        'Unable to verify permission.',
        [],
        500
    );

}


/* ============================================================
   VERIFY ROLE
============================================================ */

try {

    $role =
        $pdo->prepare(
            "
            SELECT id, is_admin_role

            FROM roles

            WHERE id = :role_id

            LIMIT 1
            "
        );


    $role->execute([
        ':role_id' => $roleId
    ]);


    $roleRow =
        $role->fetch();

} catch (Throwable $e) {

    userCreateResponse(
        false,
        'Unable to validate role.',
        [],
        500
    );

}


if (!$roleRow) {

    userCreateResponse(
        false,
        'Selected role does not exist.',
        [],
        422
    );

}


/* ============================================================
   DUPLICATES
============================================================ */

try {

    $duplicate =
        $pdo->prepare(
            "
            SELECT id

            FROM users

            WHERE

                LOWER(username) =
                    LOWER(:username)

                OR LOWER(email) =
                    LOWER(:email)

            LIMIT 1
            "
        );


    $duplicate->execute([
        ':username' => $username,
        ':email' => $email
    ]);


    if ($duplicate->fetch()) {

        userCreateResponse(
            false,
            'Username or email already exists.',
            [
                'code' => 'DUPLICATE_USER'
            ],
            409
        );

    }

} catch (Throwable $e) {

    userCreateResponse(
        false,
        'Unable to check existing accounts.',
        [],
        500
    );

}


/* ============================================================
   COUNTRY
============================================================ */

try {

    $country =
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


    $country->execute([
        ':country_id' =>
            $countryId
    ]);


    if (!$country->fetch()) {

        userCreateResponse(
            false,
            'Selected country does not exist or is inactive.',
            [],
            422
        );

    }

} catch (Throwable $e) {

    userCreateResponse(
        false,
        'Unable to validate country.',
        [],
        500
    );

}


/* ============================================================
   PASSWORD
============================================================ */

$passwordHash =
    password_hash(
        $password,
        PASSWORD_DEFAULT
    );


if ($passwordHash === false) {

    userCreateResponse(
        false,
        'Unable to securely create password.',
        [],
        500
    );

}


/* ============================================================
   CREATE
============================================================ */

try {

    $pdo->beginTransaction();


    $insert =
        $pdo->prepare(
            "
            INSERT INTO users
            (
                role_id,
                username,
                full_names,
                gender,
                email,
                country_id,
                phone_number,
                phone_e164,
                date_of_birth,
                password_hash,
                account_status,
                email_verified,
                phone_verified,
                identity_verified,
                age_verified,
                is_active,
                is_suspended,
                is_deleted
            )
            VALUES
            (
                :role_id,
                :username,
                :full_names,
                :gender,
                :email,
                :country_id,
                :phone_number,
                :phone_e164,
                :date_of_birth,
                :password_hash,
                'approved',
                :email_verified,
                :phone_verified,
                :identity_verified,
                :age_verified,
                1,
                0,
                0
            )
            "
        );


    $insert->execute([

        ':role_id' =>
            $roleId,

        ':username' =>
            $username,

        ':full_names' =>
            $fullNames,

        ':gender' =>
            $gender,

        ':email' =>
            $email,

        ':country_id' =>
            $countryId,

        ':phone_number' =>
            $phoneNumber,

        ':phone_e164' =>
            $phoneE164,

        ':date_of_birth' =>
            $dateOfBirth,

        ':password_hash' =>
            $passwordHash,

        ':email_verified' =>
            $emailVerified,

        ':phone_verified' =>
            $phoneVerified,

        ':identity_verified' =>
            $identityVerified,

        ':age_verified' =>
            $ageVerified

    ]);


    $newUserId =
        (int)$pdo->lastInsertId();


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
                'admin_user_created',
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
            $newUserId,

        ':new_values' =>
            json_encode(
                [
                    'username' => $username,
                    'email' => $email,
                    'role_id' => $roleId
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
        '[LOVEMI CREATE USER] ' .
        $e->getMessage()
    );


    userCreateResponse(
        false,
        'Unable to create user.',
        [],
        500
    );

}


userCreateResponse(
    true,
    'User created successfully.',
    [
        'data' => [
            'user_id' =>
                $newUserId,

            'username' =>
                $username,

            'email' =>
                $email
        ]
    ]
);