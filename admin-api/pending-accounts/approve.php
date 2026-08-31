<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - APPROVE PENDING ACCOUNT
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


function pendingApproveResponse(
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
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    pendingApproveResponse(
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

    pendingApproveResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN SESSION
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

    pendingApproveResponse(
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


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    pendingApproveResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    pendingApproveResponse(
        false,
        'You do not have permission to approve accounts.',
        [],
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


if (
    $userId <= 0
) {

    pendingApproveResponse(
        false,
        'A valid account ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| START TRANSACTION
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
     * Lock the account while checking its current state.
     */

    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email,

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
            'The requested account was not found.'
        );

    }


    if (
        (bool)
        $user['is_deleted']
    ) {

        throw new RuntimeException(
            'This account has been deleted and cannot be approved.'
        );

    }


    $currentStatus =
        strtolower(
            (string)
            $user['account_status']
        );


    if (
        in_array(
            $currentStatus,
            [
                'approved',
                'active'
            ],
            true
        )
    ) {

        throw new RuntimeException(
            'This account is already approved.'
        );

    }


    /*
     * Read required verification settings.
     */

    $requireEmail =
        true;

    $requirePhone =
        true;

    $requireIdentity =
        true;


    try {

        $settings =
            $pdo->query(
                "
                SELECT
                    setting_key,
                    setting_value

                FROM system_settings

                WHERE
                    setting_key IN
                    (
                        'require_email_verification',
                        'require_phone_verification',
                        'require_identity_verification'
                    )
                "
            );


        while (
            $row =
                $settings->fetch()
        ) {

            $key =
                $row['setting_key'];


            $value =
                filter_var(
                    $row['setting_value'],
                    FILTER_VALIDATE_BOOLEAN
                );


            if (
                $key ===
                'require_email_verification'
            ) {

                $requireEmail =
                    $value;

            }


            if (
                $key ===
                'require_phone_verification'
            ) {

                $requirePhone =
                    $value;

            }


            if (
                $key ===
                'require_identity_verification'
            ) {

                $requireIdentity =
                    $value;

            }

        }

    } catch (
        Throwable $e
    ) {

    }


    /*
     * Age is always checked for LOVEMI account approval.
     */

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
     * Calculate age.
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


    $ageEligible =
        $calculatedAge !== null
        &&
        $calculatedAge >=
        $minimumAge;


    /*
     * Validate requirements.
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


    if (
        !(bool)
        $user['age_verified']
        ||
        !$ageEligible
    ) {

        $missing[] =
            $ageEligible
                ?
                'Age verification'
                :
                "Minimum age of {$minimumAge}";

    }


    if (
        count(
            $missing
        ) > 0
    ) {

        throw new RuntimeException(
            'This account cannot be approved yet. Missing: '
            .
            implode(
                ', ',
                $missing
            )
            .
            '.'
        );

    }


    /*
     * Old state for audit.
     */

    $oldValues =
        [

            'account_status' =>
                $user['account_status'],

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
                $user['age_verified']

        ];


    /*
     * Approve.
     */

    $update =
        $pdo->prepare(
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

                id =
                    :user_id

                AND is_deleted =
                    0

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    if (
        $update->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The account status could not be updated.'
        );

    }


    /*
     * Audit entry.
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
                    'admin_approve_account',
                    'user',
                    :entity_id,
                    :old_values,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute(
            [

                ':user_id' =>
                    $adminId,

                ':entity_id' =>
                    $userId,

                ':old_values' =>
                    json_encode(
                        $oldValues,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [
                            'account_status' =>
                                'approved',

                            'approved_by' =>
                                $adminId,

                            'approved_at' =>
                                date(
                                    'Y-m-d H:i:s'
                                )

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

            ]
        );

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI PENDING APPROVE AUDIT] '
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


    pendingApproveResponse(
        false,
        $e->getMessage(),
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

pendingApproveResponse(
    true,
    'The account has been approved successfully.',
    [

        'user_id' =>
            $userId,

        'account_status' =>
            'approved',

        'approved' =>
            true

    ]
);