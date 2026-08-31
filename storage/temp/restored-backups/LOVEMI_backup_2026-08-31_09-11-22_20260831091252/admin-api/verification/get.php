<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET VERIFICATION DETAILS
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


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

ini_set(
    'display_errors',
    '0'
);


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function verificationGetResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        [
            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    verificationGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    verificationGetResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/*
|--------------------------------------------------------------------------
| ADMIN AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT
                u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug =
                    'users.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        verificationGetResponse(
            false,
            'You do not have permission to manage verification.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    verificationGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| USER ID
|--------------------------------------------------------------------------
*/

$userId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $userId <= 0
) {

    verificationGetResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| SYSTEM MINIMUM AGE
|--------------------------------------------------------------------------
*/

$minimumAge =
    18;


try {

    $setting =
        $pdo->prepare(
            "
            SELECT
                setting_value

            FROM system_settings

            WHERE
                setting_key =
                    'minimum_age'

            LIMIT 1
            "
        );


    $setting->execute();


    $value =
        $setting->fetchColumn();


    if (
        is_numeric(
            $value
        )
    ) {

        $minimumAge =
            (int)
            $value;

    }

} catch (
    Throwable $e
) {

    $minimumAge =
        18;

}


/*
|--------------------------------------------------------------------------
| USER
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.phone_number,

                u.phone_e164,

                u.date_of_birth,

                u.email_verified,

                u.phone_verified,

                u.identity_verified,

                u.age_verified,

                u.account_status,

                u.is_active,

                u.is_suspended,

                u.created_at,

                u.updated_at,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            u.id

                        AND p.photo_type =
                            'profile'

                        AND p.is_primary =
                            1

                        AND p.approval_status =
                            'approved'

                    ORDER BY p.id DESC

                    LIMIT 1

                ) AS avatar

            FROM users u

            WHERE

                u.id =
                    :user_id

                AND u.is_deleted =
                    0

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFICATION GET USER] '
        .
        $e->getMessage()
    );


    verificationGetResponse(
        false,
        'Unable to load the user.',
        [],
        500
    );

}


if (
    !$user
) {

    verificationGetResponse(
        false,
        'User not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| MASK PHONE
|--------------------------------------------------------------------------
*/

$phone =
    (string)(
        $user['phone_e164']
        ??
        $user['phone_number']
        ??
        ''
    );


$phoneDisplay =
    'Not supplied';


if (
    $phone !== ''
) {

    $length =
        strlen(
            $phone
        );


    if (
        $length > 4
    ) {

        $phoneDisplay =
            substr(
                $phone,
                0,
                min(
                    4,
                    $length
                )
            )
            .
            str_repeat(
                '•',
                max(
                    0,
                    $length - 7
                )
            )
            .
            substr(
                $phone,
                -3
            );

    } else {

        $phoneDisplay =
            $phone;

    }

}


/*
|--------------------------------------------------------------------------
| CALCULATE AGE
|--------------------------------------------------------------------------
*/

$calculatedAge =
    null;


if (
    !empty(
        $user['date_of_birth']
    )
) {

    try {

        $dob =
            new DateTimeImmutable(
                (string)
                $user['date_of_birth']
            );


        $today =
            new DateTimeImmutable(
                'today'
            );


        if (
            $dob <= $today
        ) {

            $calculatedAge =
                $dob->diff(
                    $today
                )->y;

        }

    } catch (
        Throwable $e
    ) {

        $calculatedAge =
            null;

    }

}


/*
|--------------------------------------------------------------------------
| AGE ELIGIBILITY
|--------------------------------------------------------------------------
*/

$ageEligible =
    $calculatedAge !== null
    &&
    $calculatedAge >= $minimumAge;


/*
|--------------------------------------------------------------------------
| DO NOT RETURN ENCRYPTED ID NUMBER
|--------------------------------------------------------------------------
*/

unset(
    $user['phone_number'],
    $user['phone_e164']
);


$user['phone_display'] =
    $phoneDisplay;


$user['calculated_age'] =
    $calculatedAge;


$user['minimum_age'] =
    $minimumAge;


$user['age_eligible'] =
    $ageEligible;


$user['avatar'] =
    $user['avatar']
    ??
    null;


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

verificationGetResponse(
    true,
    'Verification details loaded successfully.',
    [
        'user' =>
            $user
    ]
);