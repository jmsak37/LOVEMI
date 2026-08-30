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

function rejectVerificationResponse(
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

    rejectVerificationResponse(
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

    rejectVerificationResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   ADMIN AUTH
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

    rejectVerificationResponse(
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

        rejectVerificationResponse(
            false,
            'You do not have permission to manage verification.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    rejectVerificationResponse(
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
                'all'
            )
        )
    );


if (
    $userId <= 0
) {

    rejectVerificationResponse(
        false,
        'A valid user ID is required.',
        [],
        422
    );

}


if (
    !in_array(
        $type,
        [
            'identity',
            'age',
            'all'
        ],
        true
    )
) {

    rejectVerificationResponse(
        false,
        'Invalid verification type.',
        [],
        422
    );

}


/* =========================================================
   USER EXISTS
========================================================= */

try {

    $find =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                identity_verified,

                age_verified

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $find->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $find->fetch();

} catch (
    Throwable $e
) {

    rejectVerificationResponse(
        false,
        'Unable to find the user.',
        [],
        500
    );

}


if (
    !$user
) {

    rejectVerificationResponse(
        false,
        'User was not found.',
        [],
        404
    );

}


/* =========================================================
   OLD VALUES
========================================================= */

$oldValues = [

    'identity_verified' =>
        (int)
        $user['identity_verified'],

    'age_verified' =>
        (int)
        $user['age_verified']

];


/* =========================================================
   RESET VERIFICATION
========================================================= */

try {

    $pdo->beginTransaction();


    if (
        $type === 'identity'
    ) {

        $stmt =
            $pdo->prepare(
                "
                UPDATE users

                SET
                    identity_verified = 0

                WHERE
                    id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );

    }


    elseif (
        $type === 'age'
    ) {

        $stmt =
            $pdo->prepare(
                "
                UPDATE users

                SET
                    age_verified = 0

                WHERE
                    id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );

    }


    else {

        $stmt =
            $pdo->prepare(
                "
                UPDATE users

                SET

                    identity_verified = 0,

                    age_verified = 0

                WHERE
                    id = :user_id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );

    }


    /* =====================================================
       AUDIT
    ====================================================== */

    try {

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
                0;

        }


        if (
            $type === 'age'
            ||
            $type === 'all'
        ) {

            $newValues[
                'age_verified'
            ] =
                0;

        }


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
                    'admin_verification_rejected',
                    'user_verification',
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
            '[LOVEMI REJECT VERIFICATION AUDIT] '
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
        '[LOVEMI REJECT VERIFICATION] '
        .
        $e->getMessage()
    );


    rejectVerificationResponse(
        false,
        'Verification could not be removed.',
        [],
        500
    );

}


/* =========================================================
   RESPONSE
========================================================= */

rejectVerificationResponse(
    true,
    $type === 'all'
        ?
        'Identity and age verification have been removed.'
        :
        ucfirst(
            $type
        )
        .
        ' verification has been removed.',
    [

        'user_id' =>
            $userId,

        'verification_type' =>
            $type,

        'rejected' =>
            true

    ]
);