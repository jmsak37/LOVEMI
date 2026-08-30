<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET PAYMENT
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

function paymentGetResponse(
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

    paymentGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTHENTICATION
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

    paymentGetResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$paymentId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $paymentId <= 0
) {

    paymentGetResponse(
        false,
        'A valid payment ID is required.',
        [],
        422
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

        paymentGetResponse(
            false,
            'You do not have permission to view payments.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    paymentGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| PAYMENT
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.user_id,

                p.service_id,

                p.subscription_id,

                p.payment_reference,

                p.gateway,

                p.gateway_transaction_id,

                p.payment_method,

                p.status,

                p.currency_id,

                p.base_amount_usd,

                p.exchange_rate,

                p.amount_expected,

                p.amount_paid,

                p.gateway_fee,

                p.phone_number,

                p.checkout_reference,

                p.paid_at,

                p.created_at,

                p.updated_at,

                u.username,

                u.full_names,

                u.email,

                sv.name AS service_name,

                sv.slug AS service_slug,

                c.code AS currency_code,

                c.name AS currency_name,

                c.symbol AS currency_symbol

            FROM payments p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN services sv
                ON sv.id = p.service_id

            LEFT JOIN currencies c
                ON c.id = p.currency_id

            WHERE
                p.id = :payment_id

            LIMIT 1
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

} catch (
    Throwable $e
) {

    paymentGetResponse(
        false,
        'Unable to load payment information.',
        [],
        500
    );

}


if (
    !$payment
) {

    paymentGetResponse(
        false,
        'Payment not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| RECEIPT
|--------------------------------------------------------------------------
*/

try {

    $receiptStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                receipt_number,

                receipt_path,

                issued_at

            FROM payment_receipts

            WHERE
                payment_id = :payment_id

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $receiptStmt->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    $receipt =
        $receiptStmt->fetch();

} catch (
    Throwable $e
) {

    $receipt =
        null;

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

paymentGetResponse(
    true,
    'Payment loaded successfully.',
    [

        'payment' =>
            $payment,

        'receipt' =>
            $receipt

    ]
);