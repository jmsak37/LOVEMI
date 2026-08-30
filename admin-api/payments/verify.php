<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - VERIFY PAYMENT
|--------------------------------------------------------------------------
|
| This endpoint performs an ADMINISTRATIVE verification.
|
| It does NOT pretend to call M-Pesa/Card/PayPal automatically.
| Actual gateway verification belongs in the corresponding
| payment service.
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

function paymentVerifyResponse(
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

    paymentVerifyResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

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


$paymentId =
    (int)(
        $data['payment_id']
        ??
        0
    );


if (
    $paymentId <= 0
) {

    paymentVerifyResponse(
        false,
        'A valid payment ID is required.',
        [],
        422
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

    paymentVerifyResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN AUTHENTICATION
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

    paymentVerifyResponse(
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
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

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

                AND pm.slug = 'payments.manage'

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

        paymentVerifyResponse(
            false,
            'You do not have permission to verify payments.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    paymentVerifyResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| LOAD
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                *

            FROM payments

            WHERE
                id = :payment_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    $payment =
        $stmt->fetch();


    if (
        !$payment
    ) {

        throw new RuntimeException(
            'Payment not found.'
        );

    }


    $oldStatus =
        strtolower(
            (string)
            $payment['status']
        );


    if (
        $oldStatus === 'paid'
    ) {

        throw new RuntimeException(
            'This payment is already marked as paid.'
        );

    }


    if (
        $oldStatus === 'refunded'
    ) {

        throw new RuntimeException(
            'A refunded payment cannot be verified as paid.'
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Admin verification
    |--------------------------------------------------------------------------
    */

    $update =
        $pdo->prepare(
            "
            UPDATE payments

            SET

                status =
                    'paid',

                paid_at =
                    COALESCE(
                        paid_at,
                        CURRENT_TIMESTAMP
                    ),

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE

                id = :payment_id

                AND status <> 'paid'

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Audit
    |--------------------------------------------------------------------------
    */

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
                'admin_verify_payment',
                'payment',
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
                $paymentId,

            ':old_values' =>
                json_encode(
                    [
                        'status' =>
                            $oldStatus
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':new_values' =>
                json_encode(
                    [
                        'status' =>
                            'paid',

                        'verified_by_admin' =>
                            $adminId
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
        '[LOVEMI PAYMENT VERIFY] '
        .
        $e->getMessage()
    );


    paymentVerifyResponse(
        false,
        $e->getMessage(),
        [],
        409
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

paymentVerifyResponse(
    true,
    'Payment has been marked as paid successfully.',
    [

        'payment_id' =>
            $paymentId,

        'status' =>
            'paid'

    ]
);