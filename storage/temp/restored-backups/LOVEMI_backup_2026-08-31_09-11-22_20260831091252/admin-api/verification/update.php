<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - UPDATE VERIFICATION
|--------------------------------------------------------------------------
|
| Supported verification types:
|
| email
| phone
| identity
| age
| account
|
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

function verificationUpdateResponse(
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
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    verificationUpdateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

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

    verificationUpdateResponse(
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

    verificationUpdateResponse(
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

                u.id,

                u.username,

                u.full_names

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


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    verificationUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    verificationUpdateResponse(
        false,
        'You do not have permission to manage verification.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$userId =
    (int)(
        $input['user_id']
        ??
        0
    );


$type =
    strtolower(
        trim(
            (string)(
                $input['verification_type']
                ??
                ''
            )
        )
    );


$verified =
    filter_var(
        $input['verified']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


/*
|--------------------------------------------------------------------------
| VALID TYPES
|--------------------------------------------------------------------------
*/

$allowedTypes =
    [
        'email',
        'phone',
        'identity',
        'age',
        'account'
    ];


if (
    !in_array(
        $type,
        $allowedTypes,
        true
    )
) {

    verificationUpdateResponse(
        false,
        'Invalid verification type.',
        [],
        422
    );

}


if (
    $userId <= 0
) {

    verificationUpdateResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| LOAD USER
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email,

                phone_number,

                phone_e164,

                date_of_birth,

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

            FOR UPDATE
            "
        );


    /*
     * FOR UPDATE requires a transaction.
     */

    $pdo->beginTransaction();


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();


    if (
        !$user
    ) {

        throw new RuntimeException(
            'User not found.'
        );

    }


    if (
        (bool)
        $user['is_deleted']
    ) {

        throw new RuntimeException(
            'This account has been deleted.'
        );

    }

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    verificationUpdateResponse(
        false,
        $e->getMessage(),
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| AGE VERIFICATION
|--------------------------------------------------------------------------
*/

if (
    $type === 'age'
    &&
    $verified
) {

    if (
        empty(
            $user['date_of_birth']
        )
    ) {

        $pdo->rollBack();


        verificationUpdateResponse(
            false,
            'Age cannot be verified because the account has no date of birth.',
            [
                'code' =>
                    'DOB_REQUIRED'
            ],
            422
        );

    }


    /*
     * Read minimum age from system settings.
     */

    $minimumAge =
        18;


    try {

        $ageSetting =
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


        $ageSetting->execute();


        $settingValue =
            $ageSetting->fetchColumn();


        if (
            is_numeric(
                $settingValue
            )
        ) {

            $minimumAge =
                (int)
                $settingValue;

        }

    } catch (
        Throwable $e
    ) {

        /*
         * Safe default remains 18.
         */

        $minimumAge =
            18;

    }


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
            $dob > $today
        ) {

            throw new RuntimeException(
                'The date of birth is invalid.'
            );

        }


        $age =
            $dob->diff(
                $today
            )->y;


        if (
            $age < $minimumAge
        ) {

            $pdo->rollBack();


            verificationUpdateResponse(
                false,
                "The member does not meet the minimum age requirement of {$minimumAge}.",
                [
                    'code' =>
                        'MINIMUM_AGE_NOT_MET',

                    'age' =>
                        $age,

                    'minimum_age' =>
                        $minimumAge
                ],
                422
            );

        }

    } catch (
        Throwable $e
    ) {

        $pdo->rollBack();


        verificationUpdateResponse(
            false,
            'The member date of birth could not be validated.',
            [],
            422
        );

    }

}


/*
|--------------------------------------------------------------------------
| COLUMN / VALUE
|--------------------------------------------------------------------------
*/

$oldValues =
    [

        'email_verified' =>
            (int)
            $user['email_verified'],

        'phone_verified' =>
            (int)
            $user['phone_verified'],

        'identity_verified' =>
            (int)
            $user['identity_verified'],

        'age_verified' =>
            (int)
            $user['age_verified'],

        'account_status' =>
            $user['account_status']

    ];


/*
|--------------------------------------------------------------------------
| BUILD UPDATE
|--------------------------------------------------------------------------
*/

$updateSql =
    '';


$params =
    [
        ':user_id' =>
            $userId
    ];


switch (
    $type
) {

    case 'email':

        $updateSql =
            "
            UPDATE users

            SET

                email_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";

        $params[':value'] =
            $verified
                ?
                1
                :
                0;

        break;


    case 'phone':

        $updateSql =
            "
            UPDATE users

            SET

                phone_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";

        $params[':value'] =
            $verified
                ?
                1
                :
                0;

        break;


    case 'identity':

        $updateSql =
            "
            UPDATE users

            SET

                identity_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";

        $params[':value'] =
            $verified
                ?
                1
                :
                0;

        break;


    case 'age':

        $updateSql =
            "
            UPDATE users

            SET

                age_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";

        $params[':value'] =
            $verified
                ?
                1
                :
                0;

        break;


    case 'account':

        if (
            $verified
        ) {

            $updateSql =
                "
                UPDATE users

                SET

                    account_status =
                        'approved',

                    is_active =
                        1,

                    is_suspended =
                        0

                WHERE
                    id = :user_id

                LIMIT 1
                ";

        } else {

            $updateSql =
                "
                UPDATE users

                SET

                    account_status =
                        'pending'

                WHERE
                    id = :user_id

                LIMIT 1
                ";

        }

        break;

}


/*
|--------------------------------------------------------------------------
| UPDATE
|--------------------------------------------------------------------------
*/

try {

    $update =
        $pdo->prepare(
            $updateSql
        );


    $update->execute(
        $params
    );


    /*
     * Load resulting values.
     */

    $afterStmt =
        $pdo->prepare(
            "
            SELECT

                email_verified,

                phone_verified,

                identity_verified,

                age_verified,

                account_status

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $afterStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $after =
        $afterStmt->fetch();


    if (
        !$after
    ) {

        throw new RuntimeException(
            'Unable to read the updated verification state.'
        );

    }


    /*
     * Audit log.
     */

    try {

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
                    :action,
                    'user_verification',
                    :entity_id,
                    :old_values,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $newValues =
            [

                'verification_type' =>
                    $type,

                'verified' =>
                    $verified,

                'email_verified' =>
                    (int)
                    $after[
                        'email_verified'
                    ],

                'phone_verified' =>
                    (int)
                    $after[
                        'phone_verified'
                    ],

                'identity_verified' =>
                    (int)
                    $after[
                        'identity_verified'
                    ],

                'age_verified' =>
                    (int)
                    $after[
                        'age_verified'
                    ],

                'account_status' =>
                    $after[
                        'account_status'
                    ]

            ];


        $action =
            $verified
                ?
                'admin_verify_' . $type
                :
                'admin_remove_' . $type . '_verification';


        $audit->execute(
            [

                ':user_id' =>
                    $adminId,

                ':action' =>
                    $action,

                ':entity_id' =>
                    $userId,

                ':old_values' =>
                    json_encode(
                        $oldValues,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        $newValues,
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

            ]
        );

    } catch (
        Throwable $auditError
    ) {

        /*
         * Do not expose audit errors to the administrator,
         * but record them server-side.
         */

        error_log(
            '[LOVEMI VERIFICATION AUDIT ERROR] '
            .
            $auditError->getMessage()
        );

    }


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
        '[LOVEMI VERIFICATION UPDATE ERROR] '
        .
        $e->getMessage()
    );


    verificationUpdateResponse(
        false,
        'The verification update could not be completed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| NOTIFICATION
|--------------------------------------------------------------------------
|
| The notification system already exists in LOVEMI. We do not
| expose private verification information in the response.
|
*/

$label =
    match (
        $type
    ) {

        'email' =>
            'email',

        'phone' =>
            'phone',

        'identity' =>
            'identity',

        'age' =>
            'age',

        'account' =>
            'account',

        default =>
            'verification'

    };


$message =
    $verified
        ?
        "The member's {$label} verification has been completed."
        :
        "The member's {$label} verification has been removed.";


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

verificationUpdateResponse(
    true,
    $message,
    [

        'user_id' =>
            $userId,

        'verification_type' =>
            $type,

        'verified' =>
            $verified,

        'state' => [

            'email_verified' =>
                (int)
                $after[
                    'email_verified'
                ],

            'phone_verified' =>
                (int)
                $after[
                    'phone_verified'
                ],

            'identity_verified' =>
                (int)
                $after[
                    'identity_verified'
                ],

            'age_verified' =>
                (int)
                $after[
                    'age_verified'
                ],

            'account_status' =>
                $after[
                    'account_status'
                ]

        ]

    ]
);