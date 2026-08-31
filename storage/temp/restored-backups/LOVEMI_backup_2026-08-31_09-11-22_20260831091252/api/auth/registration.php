<?php
/**
 * ============================================================
 * LOVEMI - REGISTRATION API
 * ============================================================
 *
 * EMAIL verification only.
 *
 * Google Authenticator is configured after email verification.
 * Phone is stored but is NOT part of the verification process.
 * ============================================================
 */

declare(strict_types=1);


require_once __DIR__ . '/../../config/database.php';


header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   RESPONSE
============================================================ */

function registrationResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $extra
        ),
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
) {

    registrationResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   REQUEST
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


$data =
    json_decode(
        $rawBody ?: '{}',
        true
    );


if (!is_array($data)) {
    $data = [];
}


/* ============================================================
   INPUTS
============================================================ */

$username =
    trim(
        (string) (
            $data['username']
            ?? ''
        )
    );


$fullNames =
    trim(
        (string) (
            $data['full_names']
            ?? ''
        )
    );


$gender =
    trim(
        (string) (
            $data['gender']
            ?? ''
        )
    );


$dateOfBirth =
    trim(
        (string) (
            $data['date_of_birth']
            ?? ''
        )
    );


$email =
    strtolower(
        trim(
            (string) (
                $data['email']
                ?? ''
            )
        )
    );


$countryId =
    isset(
        $data['country_id']
    )
        ? (int)
          $data['country_id']
        : 0;


$phoneCode =
    trim(
        (string) (
            $data['phone_code']
            ?? ''
        )
    );


$phoneNumber =
    trim(
        (string) (
            $data['phone_number']
            ?? ''
        )
    );


$idNumber =
    trim(
        (string) (
            $data['id_number']
            ?? ''
        )
    );


$password =
    (string) (
        $data['password']
        ?? ''
    );


$confirmPassword =
    (string) (
        $data['confirm_password']
        ?? ''
    );


$registerAsAdmin =
    filter_var(
        $data['register_as_admin']
        ?? false,
        FILTER_VALIDATE_BOOLEAN
    );


$agree =
    filter_var(
        $data['agree']
        ?? false,
        FILTER_VALIDATE_BOOLEAN
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    !preg_match(
        '/^[A-Za-z0-9_.-]{3,50}$/',
        $username
    )
) {

    registrationResponse(
        false,
        'Invalid username.',
        [
            'code' =>
                'INVALID_USERNAME'
        ],
        422
    );

}


if (
    mb_strlen($fullNames) < 2
    ||
    mb_strlen($fullNames) > 180
) {

    registrationResponse(
        false,
        'Please enter your full names.',
        [
            'code' =>
                'INVALID_FULL_NAMES'
        ],
        422
    );

}


if (
    !in_array(
        $gender,
        [
            'Male',
            'Female',
            'Other'
        ],
        true
    )
) {

    registrationResponse(
        false,
        'Please select a valid gender.',
        [
            'code' =>
                'INVALID_GENDER'
        ],
        422
    );

}


/* ============================================================
   AGE
============================================================ */

$dob =
    DateTime::createFromFormat(
        'Y-m-d',
        $dateOfBirth
    );


if (
    !$dob
    ||
    $dob->format('Y-m-d')
        !==
    $dateOfBirth
) {

    registrationResponse(
        false,
        'Please provide a valid date of birth.',
        [
            'code' =>
                'INVALID_DATE_OF_BIRTH'
        ],
        422
    );

}


$today =
    new DateTime(
        'today'
    );


if (
    $dob > $today
) {

    registrationResponse(
        false,
        'Date of birth cannot be in the future.',
        [],
        422
    );

}


$age =
    $dob->diff(
        $today
    )->y;


if (
    $age < 18
) {

    registrationResponse(
        false,
        'You must be at least 18 years old.',
        [
            'code' =>
                'UNDER_18'
        ],
        422
    );

}


/* ============================================================
   EMAIL
============================================================ */

if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    registrationResponse(
        false,
        'Please enter a valid email address.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


/* ============================================================
   COUNTRY
============================================================ */

if (
    $countryId <= 0
) {

    registrationResponse(
        false,
        'Please select your country.',
        [
            'code' =>
                'COUNTRY_REQUIRED'
        ],
        422
    );

}


try {

    $pdo =
        db();


    $countryStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                name,
                phone_code
            FROM countries
            WHERE id = :id
              AND is_active = TRUE
            LIMIT 1
            "
        );


    $countryStmt->execute(
        [
            ':id' =>
                $countryId
        ]
    );


    $country =
        $countryStmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI REGISTRATION COUNTRY ERROR] '
        . $e->getMessage()
    );


    registrationResponse(
        false,
        'Unable to validate the selected country.',
        [],
        500
    );

}


if (!$country) {

    registrationResponse(
        false,
        'The selected country is not available.',
        [
            'code' =>
                'COUNTRY_NOT_FOUND'
        ],
        422
    );

}


if (
    (string)
    $country['phone_code']
    !==
    $phoneCode
) {

    registrationResponse(
        false,
        'The phone country code does not match the selected country.',
        [
            'code' =>
                'PHONE_CODE_MISMATCH'
        ],
        422
    );

}


/* ============================================================
   PHONE
============================================================ */

$nationalPhone =
    preg_replace(
        '/[^0-9]/',
        '',
        $phoneNumber
    );


if (
    !is_string($nationalPhone)
    ||
    strlen($nationalPhone) < 5
) {

    registrationResponse(
        false,
        'Please enter a valid phone number.',
        [
            'code' =>
                'INVALID_PHONE'
        ],
        422
    );

}


$phoneE164 =
    $phoneCode
    .
    $nationalPhone;


if (
    strlen($phoneE164) > 20
) {

    registrationResponse(
        false,
        'Phone number is too long.',
        [
            'code' =>
                'INVALID_PHONE'
        ],
        422
    );

}


/* ============================================================
   ID HASH
============================================================ */

$normalizedId =
    strtolower(
        preg_replace(
            '/[\s-]+/',
            '',
            $idNumber
        )
    );


if (
    strlen($normalizedId) < 4
) {

    registrationResponse(
        false,
        'Please enter a valid ID number.',
        [
            'code' =>
                'INVALID_ID'
        ],
        422
    );

}


$idNumberHash =
    hash(
        'sha256',
        $normalizedId
    );


/* ============================================================
   PASSWORD
============================================================ */

if (
    strlen($password) < 8
) {

    registrationResponse(
        false,
        'Password must contain at least 8 characters.',
        [
            'code' =>
                'PASSWORD_TOO_SHORT'
        ],
        422
    );

}


if (
    $password !==
    $confirmPassword
) {

    registrationResponse(
        false,
        'Passwords do not match.',
        [
            'code' =>
                'PASSWORD_MISMATCH'
        ],
        422
    );

}


if (!$agree) {

    registrationResponse(
        false,
        'Please accept the Terms of Service and Privacy Policy.',
        [
            'code' =>
                'TERMS_REQUIRED'
        ],
        422
    );

}


/* ============================================================
   PASSWORD HASH
============================================================ */

$passwordHash =
    password_hash(
        $password,
        PASSWORD_DEFAULT
    );


if (
    $passwordHash === false
) {

    registrationResponse(
        false,
        'Unable to secure your password.',
        [],
        500
    );

}


/* ============================================================
   FIRST ADMIN LOCK
============================================================ */

try {

    $lockResult =
        $pdo->query(
            "
            SELECT GET_LOCK(
                'lovemi_first_admin_registration',
                10
            ) AS lock_result
            "
        )->fetch();


    if (
        (int)
        ($lockResult['lock_result'] ?? 0)
        !==
        1
    ) {

        registrationResponse(
            false,
            'Registration is temporarily busy. Please try again.',
            [
                'code' =>
                    'REGISTRATION_BUSY'
            ],
            503
        );

    }


} catch (Throwable $e) {

    registrationResponse(
        false,
        'Registration is temporarily unavailable.',
        [],
        500
    );

}


/* ============================================================
   REGISTRATION TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       DUPLICATE USERNAME
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE LOWER(username) =
                  LOWER(:username)
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':username' =>
                $username
        ]
    );


    if ($stmt->fetch()) {

        throw new RuntimeException(
            'USERNAME_EXISTS'
        );

    }


    /* ========================================================
       DUPLICATE EMAIL
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE LOWER(email) =
                  LOWER(:email)
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':email' =>
                $email
        ]
    );


    if ($stmt->fetch()) {

        throw new RuntimeException(
            'EMAIL_EXISTS'
        );

    }


    /* ========================================================
       DUPLICATE PHONE
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE phone_e164 = :phone
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':phone' =>
                $phoneE164
        ]
    );


    if ($stmt->fetch()) {

        throw new RuntimeException(
            'PHONE_EXISTS'
        );

    }


    /* ========================================================
       DUPLICATE ID
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE id_number_hash = :id_hash
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':id_hash' =>
                $idNumberHash
        ]
    );


    if ($stmt->fetch()) {

        throw new RuntimeException(
            'ID_EXISTS'
        );

    }


    /* ========================================================
       ROLES
    ======================================================== */

    $roleStmt =
        $pdo->query(
            "
            SELECT id, slug
            FROM roles
            WHERE slug IN ('member','admin')
            "
        );


    $roles = [];


    while (
        $role =
            $roleStmt->fetch()
    ) {

        $roles[
            $role['slug']
        ] =
            (int)
            $role['id'];

    }


    if (
        !isset($roles['member'])
        ||
        !isset($roles['admin'])
    ) {

        throw new RuntimeException(
            'ROLES_NOT_CONFIGURED'
        );

    }


    /* ========================================================
       EXISTING ADMIN
    ======================================================== */

    $adminStmt =
        $pdo->query(
            "
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            WHERE r.slug = 'admin'

              AND u.is_deleted = FALSE

            LIMIT 1
            "
        );


    $adminExists =
        (bool)
        $adminStmt->fetch();


    /*
     * SERVER DECIDES THE ROLE.
     */

    if (
        !$adminExists
        &&
        $registerAsAdmin
    ) {

        $roleId =
            $roles['admin'];

        $roleSlug =
            'admin';

    } else {

        $roleId =
            $roles['member'];

        $roleSlug =
            'member';

    }


    /* ========================================================
       INSERT USER
    ======================================================== */

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
                id_number_hash,
                date_of_birth,
                password_hash,
                account_status,
                email_verified,
                phone_verified,
                identity_verified,
                age_verified,
                is_active,
                is_suspended,
                is_deleted,
                two_factor_enabled
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
                :id_number_hash,
                :date_of_birth,
                :password_hash,
                'pending',
                FALSE,
                FALSE,
                FALSE,
                TRUE,
                TRUE,
                FALSE,
                FALSE,
                FALSE
            )
            "
        );


    $insert->execute(
        [
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

            ':id_number_hash' =>
                $idNumberHash,

            ':date_of_birth' =>
                $dateOfBirth,

            ':password_hash' =>
                $passwordHash
        ]
    );


    $newUserId =
        (int)
        $pdo->lastInsertId();


    /* ========================================================
       EMAIL VERIFICATION CODE
    ======================================================== */

    $verificationCode =
        str_pad(
            (string)
            random_int(
                0,
                999999
            ),
            6,
            '0',
            STR_PAD_LEFT
        );


    $verificationHash =
        hash(
            'sha256',
            $verificationCode
        );


    $verificationExpires =
        date(
            'Y-m-d H:i:s',
            time() + 600
        );


    $verification =
        $pdo->prepare(
            "
            INSERT INTO verifications
            (
                user_id,
                email,
                verification_type,
                code_hash,
                attempt_count,
                send_count,
                expires_at
            )
            VALUES
            (
                :user_id,
                :email,
                'email_registration',
                :code_hash,
                0,
                1,
                :expires_at
            )
            "
        );


    $verification->execute(
        [
            ':user_id' =>
                $newUserId,

            ':email' =>
                $email,

            ':code_hash' =>
                $verificationHash,

            ':expires_at' =>
                $verificationExpires
        ]
    );


    /* ========================================================
       AUDIT
    ======================================================== */

    $audit =
        $pdo->prepare(
            "
            INSERT INTO audit_logs
            (
                user_id,
                action,
                entity_type,
                entity_id,
                new_values,
                ip_address,
                user_agent
            )
            VALUES
            (
                :user_id,
                'registration',
                'user',
                :entity_id,
                :new_values,
                :ip_address,
                :user_agent
            )
            "
        );


    $audit->execute(
        [
            ':user_id' =>
                $newUserId,

            ':entity_id' =>
                $newUserId,

            ':new_values' =>
                json_encode(
                    [
                        'role' =>
                            $roleSlug,

                        'account_status' =>
                            'pending'
                    ]
                ),

            ':ip_address' =>
                $_SERVER['REMOTE_ADDR']
                ?? null,

            ':user_agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ?? null
        ]
    );


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    try {

        $pdo->query(
            "
            SELECT RELEASE_LOCK(
                'lovemi_first_admin_registration'
            )
            "
        );

    } catch (Throwable $lockError) {

        error_log(
            '[LOVEMI LOCK RELEASE ERROR] '
            . $lockError->getMessage()
        );

    }


    switch (
        $e->getMessage()
    ) {

        case 'USERNAME_EXISTS':

            registrationResponse(
                false,
                'That username is already registered.',
                [
                    'code' =>
                        'USERNAME_EXISTS'
                ],
                409
            );

            break;


        case 'EMAIL_EXISTS':

            registrationResponse(
                false,
                'That email address is already registered.',
                [
                    'code' =>
                        'EMAIL_EXISTS'
                ],
                409
            );

            break;


        case 'PHONE_EXISTS':

            registrationResponse(
                false,
                'That phone number is already registered.',
                [
                    'code' =>
                        'PHONE_EXISTS'
                ],
                409
            );

            break;


        case 'ID_EXISTS':

            registrationResponse(
                false,
                'That ID number is already registered.',
                [
                    'code' =>
                        'ID_EXISTS'
                ],
                409
            );

            break;


        default:

            error_log(
                '[LOVEMI REGISTRATION ERROR] '
                . $e->getMessage()
            );


            registrationResponse(
                false,
                'Registration could not be completed.',
                [
                    'code' =>
                        'REGISTRATION_FAILED'
                ],
                500
            );

    }

}


/* ============================================================
   RELEASE LOCK
============================================================ */

try {

    $pdo->query(
        "
        SELECT RELEASE_LOCK(
            'lovemi_first_admin_registration'
        )
        "
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI LOCK RELEASE ERROR] '
        . $e->getMessage()
    );

}


/* ============================================================
   SEND EMAIL
============================================================ */

$emailSent =
    false;


try {

    require_once
        __DIR__
        . '/../../services/email/email-service.php';


    $emailSent =
        sendLovemiVerificationEmail(
            $email,
            $fullNames,
            $verificationCode
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFICATION EMAIL ERROR] '
        . $e->getMessage()
    );

}


if (!$emailSent) {

    /*
     * The account exists, but the verification email could not
     * be delivered. The user can use resend-email-code.php.
     */

    registrationResponse(
        true,
        'Your account was created, but we could not deliver the verification email. Please use Resend Code on the verification page.',
        [
            'user_id' =>
                $newUserId,

            'role' =>
                $roleSlug,

            'email_verification_required' =>
                true,

            'two_factor_required' =>
                true,

            'redirect' =>
                'verify-account.html?user='
                .
                rawurlencode(
                    (string)
                    $newUserId
                )
        ],
        201
    );

}


registrationResponse(
    true,
    'Your LOVEMI account has been created. A verification code has been sent to your email.',
    [
        'user_id' =>
            $newUserId,

        'role' =>
            $roleSlug,

        'email_verification_required' =>
            true,

        'two_factor_required' =>
            true,

        'redirect' =>
            'verify-account.html?user='
            .
            rawurlencode(
                (string)
                $newUserId
            )
    ],
    201
);