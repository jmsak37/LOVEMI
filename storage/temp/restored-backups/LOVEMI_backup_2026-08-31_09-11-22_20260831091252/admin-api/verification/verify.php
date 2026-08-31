<?php

declare(strict_types=1);

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


/* =========================================================
   SESSION
========================================================= */

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


/* =========================================================
   RESPONSE
========================================================= */

function verifyAdminResponse(
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
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/* =========================================================
   METHOD
========================================================= */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    verifyAdminResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* =========================================================
   DATABASE
========================================================= */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    verifyAdminResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   ADMIN SESSION
========================================================= */

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

    verifyAdminResponse(
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


/* =========================================================
   ADMIN AUTHORIZATION
========================================================= */

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

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'users.manage'

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

        verifyAdminResponse(
            false,
            'You do not have permission to manage verification.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    verifyAdminResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* =========================================================
   INPUT
========================================================= */

$data =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data =
        $_POST;

}


$userId =
    (int)(
        $data['user_id']
        ??
        0
    );


$type =
    strtolower(
        trim(
            (string)(
                $data['verification_type']
                ??
                ''
            )
        )
    );


$action =
    strtolower(
        trim(
            (string)(
                $data['action']
                ??
                ''
            )
        )
    );


/* =========================================================
   VALIDATION
========================================================= */

if (
    $userId <= 0
) {

    verifyAdminResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


$allowedTypes = [

    'identity',
    'age',
    'all'

];


if (
    !in_array(
        $type,
        $allowedTypes,
        true
    )
) {

    verifyAdminResponse(
        false,
        'Invalid verification type.',
        [],
        422
    );

}


$allowedActions = [

    'verify',
    'remove'

];


if (
    !in_array(
        $action,
        $allowedActions,
        true
    )
) {

    verifyAdminResponse(
        false,
        'Invalid verification action.',
        [],
        422
    );

}


/* =========================================================
   USER
========================================================= */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email,

                email_verified,

                phone_verified,

                identity_verified,

                age_verified

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    verifyAdminResponse(
        false,
        'Unable to find the user.',
        [],
        500
    );

}


if (
    !$user
) {

    verifyAdminResponse(
        false,
        'User was not found.',
        [],
        404
    );

}


/* =========================================================
   VALUES
========================================================= */

$newValue =
    $action === 'verify'
        ?
        1
        :
        0;


/* =========================================================
   UPDATE
========================================================= */

try {

    $pdo->beginTransaction();


    if (
        $type === 'identity'
    ) {

        $sql =
            "
            UPDATE users

            SET
                identity_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";


        $stmt =
            $pdo->prepare(
                $sql
            );


        $stmt->execute(
            [

                ':value' =>
                    $newValue,

                ':user_id' =>
                    $userId

            ]
        );

    }


    elseif (
        $type === 'age'
    ) {

        $sql =
            "
            UPDATE users

            SET
                age_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";


        $stmt =
            $pdo->prepare(
                $sql
            );


        $stmt->execute(
            [

                ':value' =>
                    $newValue,

                ':user_id' =>
                    $userId

            ]
        );

    }


    else {

        /*
         * "all" means identity + age.
         *
         * Email and phone remain untouched because
         * they must be verified through their actual
         * verification mechanisms.
         */

        $sql =
            "
            UPDATE users

            SET

                identity_verified =
                    :value,

                age_verified =
                    :value

            WHERE
                id = :user_id

            LIMIT 1
            ";


        $stmt =
            $pdo->prepare(
                $sql
            );


        $stmt->execute(
            [

                ':value' =>
                    $newValue,

                ':user_id' =>
                    $userId

            ]
        );

    }


    /* =====================================================
       AUDIT
    ====================================================== */

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
                    $user['age_verified']

            ];


        $newValues =
            $oldValues;


        if (
            $type === 'identity'
            ||
            $type === 'all'
        ) {

            $newValues[
                'identity_verified'
            ] =
                $newValue;

        }


        if (
            $type === 'age'
            ||
            $type === 'all'
        ) {

            $newValues[
                'age_verified'
            ] =
                $newValue;

        }


        $audit->execute(
            [

                ':user_id' =>
                    $adminId,

                ':action' =>
                    'admin_verification_'
                    .
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

        error_log(
            '[LOVEMI VERIFICATION AUDIT] '
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
        '[LOVEMI VERIFICATION UPDATE] '
        .
        $e->getMessage()
    );


    verifyAdminResponse(
        false,
        'The verification status could not be updated.',
        [],
        500
    );

}


/* =========================================================
   MESSAGE
========================================================= */

if (
    $action === 'verify'
) {

    $message =
        $type === 'all'
            ?
            'Identity and age verification were marked as verified.'
            :
            ucfirst(
                $type
            )
            .
            ' verification was marked as verified.';

} else {

    $message =
        $type === 'all'
            ?
            'Identity and age verification were removed.'
            :
            ucfirst(
                $type
            )
            .
            ' verification was removed.';

}


/* =========================================================
   RESPONSE
========================================================= */

verifyAdminResponse(
    true,
    $message,
    [

        'user_id' =>
            $userId,

        'verification_type' =>
            $type,

        'action' =>
            $action,

        'value' =>
            $newValue

    ]
);