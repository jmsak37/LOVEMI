<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET PENDING ACCOUNT
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


function pendingGetResponse(
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
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' =>
            0,

        'path' =>
            '/',

        'secure' =>
            $isHttps,

        'httponly' =>
            true,

        'samesite' =>
            'Lax'
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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    pendingGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN
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

    pendingGetResponse(
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

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
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

        pendingGetResponse(
            false,
            'You do not have permission to manage pending accounts.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| USER
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

    pendingGetResponse(
        false,
        'A valid account ID is required.',
        [],
        422
    );

}


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.gender,

                u.email,

                u.country_id,

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

                u.is_deleted,

                u.created_at,

                u.updated_at,

                c.name AS country_name,

                c.iso2 AS country_iso2,

                c.phone_code,

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

                    ORDER BY
                        p.id DESC

                    LIMIT 1

                ) AS avatar

            FROM users u

            LEFT JOIN countries c
                ON c.id =
                    u.country_id

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
        '[LOVEMI PENDING GET USER] '
        .
        $e->getMessage()
    );


    pendingGetResponse(
        false,
        'Unable to load account details.',
        [],
        500
    );

}


if (
    !$user
) {

    pendingGetResponse(
        false,
        'Account not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| REQUIREMENTS
|--------------------------------------------------------------------------
*/

$requireEmail =
    true;

$requirePhone =
    true;

$requireIdentity =
    true;

$requireAge =
    true;


try {

    $settings =
        $pdo->query(
            "
            SELECT
                setting_key,
                setting_value

            FROM system_settings

            WHERE setting_key IN
            (
                'require_email_verification',
                'require_phone_verification',
                'require_identity_verification',
                'minimum_age'
            )
            "
        );


    while (
        $row =
            $settings->fetch()
    ) {

        switch (
            $row['setting_key']
        ) {

            case 'require_email_verification':

                $requireEmail =
                    filter_var(
                        $row['setting_value'],
                        FILTER_VALIDATE_BOOLEAN
                    );

                break;


            case 'require_phone_verification':

                $requirePhone =
                    filter_var(
                        $row['setting_value'],
                        FILTER_VALIDATE_BOOLEAN
                    );

                break;


            case 'require_identity_verification':

                $requireIdentity =
                    filter_var(
                        $row['setting_value'],
                        FILTER_VALIDATE_BOOLEAN
                    );

                break;

        }

    }

} catch (
    Throwable $e
) {

}


$minimumAge =
    18;


try {

    $ageStmt =
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


    $ageStmt->execute();


    $ageValue =
        $ageStmt->fetchColumn();


    if (
        is_numeric(
            $ageValue
        )
    ) {

        $minimumAge =
            (int)
            $ageValue;

    }

} catch (
    Throwable $e
) {

}


/*
|--------------------------------------------------------------------------
| CALCULATED AGE
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
| PHONE MASK
|--------------------------------------------------------------------------
*/

$phone =
    (string)(
        $user['phone_e164']
        ?:
        $user['phone_number']
        ?:
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
        $length > 7
    ) {

        $phoneDisplay =
            substr(
                $phone,
                0,
                4
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
| MISSING VERIFICATION
|--------------------------------------------------------------------------
*/

$missing =
    [];


if (
    $requireEmail
    &&
    !(bool)
    $user['email_verified']
) {

    $missing[] =
        'Email verification';

}


if (
    $requirePhone
    &&
    !(bool)
    $user['phone_verified']
) {

    $missing[] =
        'Phone verification';

}


if (
    $requireIdentity
    &&
    !(bool)
    $user['identity_verified']
) {

    $missing[] =
        'Identity verification';

}


$ageIsEligible =
    $calculatedAge !== null
    &&
    $calculatedAge >=
    $minimumAge;


if (
    $requireAge
    &&
    (
        !(bool)
        $user['age_verified']
        ||
        !$ageIsEligible
    )
) {

    $missing[] =
        $ageIsEligible
            ?
            'Age verification'
            :
            "Age requirement of {$minimumAge}";

}


/*
|--------------------------------------------------------------------------
| CAN APPROVE
|--------------------------------------------------------------------------
*/

$canApprove =
    count(
        $missing
    ) === 0;


/*
|--------------------------------------------------------------------------
| SANITIZE
|--------------------------------------------------------------------------
|
| Never send encrypted identity information to the browser.
|
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
    $ageIsEligible;


pendingGetResponse(
    true,
    'Account details loaded successfully.',
    [

        'user' =>
            $user,

        'can_approve' =>
            $canApprove,

        'missing_verifications' =>
            $missing,

        'requirements' => [

            'email' =>
                $requireEmail,

            'phone' =>
                $requirePhone,

            'identity' =>
                $requireIdentity,

            'age' =>
                $requireAge

        ]

    ]
);