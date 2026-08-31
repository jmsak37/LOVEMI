<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET SUBSCRIPTION
|--------------------------------------------------------------------------
*/

require_once
    __DIR__ . '/../../config/database.php';


header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

ini_set(
    'display_errors',
    '0'
);


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
    !== PHP_SESSION_ACTIVE
) {

    session_start();

}


function getResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'GET'
) {

    getResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

}


$id =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $id <= 0
) {

    getResponse(
        false,
        'A valid subscription ID is required.',
        [],
        422
    );

}


try {

    $pdo = db();

} catch (
    Throwable $e
) {

    getResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


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


$token =
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
    $token === ''
) {

    getResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $token
    );


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

            INNER JOIN permissions p
                ON p.id = rp.permission_id

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

                AND p.slug = 'premium.manage'

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

        getResponse(
            false,
            'You do not have permission to view subscriptions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    getResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                s.*,

                u.username,
                u.full_names,
                u.email,

                sv.name AS service_name,
                sv.slug AS service_slug,
                sv.description AS service_description,
                sv.duration_days,
                sv.max_usage,
                sv.base_price_usd,
                sv.is_premium,

                c.code AS currency_code,
                c.name AS currency_name,
                c.symbol AS currency_symbol

            FROM subscriptions s

            INNER JOIN users u
                ON u.id = s.user_id

            INNER JOIN services sv
                ON sv.id = s.service_id

            LEFT JOIN currencies c
                ON c.id = s.currency_id

            WHERE

                s.id = :id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':id' =>
                $id
        ]
    );


    $subscription =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    getResponse(
        false,
        'Unable to load subscription.',
        [],
        500
    );

}


if (
    !$subscription
) {

    getResponse(
        false,
        'Subscription not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| AVATAR
|--------------------------------------------------------------------------
*/

$avatarUrl = null;


try {

    $photo =
        $pdo->prepare(
            "
            SELECT file_path

            FROM photos

            WHERE

                user_id = :user_id

                AND photo_type = 'profile'

                AND is_primary = 1

                AND approval_status = 'approved'

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $photo->execute(
        [
            ':user_id' =>
                (int)
                $subscription['user_id']
        ]
    );


    $avatarUrl =
        $photo->fetchColumn()
        ?:
        null;

} catch (
    Throwable $e
) {
}


/*
|--------------------------------------------------------------------------
| PAYMENT
|--------------------------------------------------------------------------
*/

$payment = null;


if (
    !empty(
        $subscription['payment_id']
    )
) {

    try {

        $paymentStmt =
            $pdo->prepare(
                "
                SELECT

                    id,
                    payment_reference,
                    gateway,
                    gateway_transaction_id,
                    payment_method,
                    status,
                    currency_id,
                    base_amount_usd,
                    exchange_rate,
                    amount_expected,
                    amount_paid,
                    gateway_fee,
                    phone_number,
                    checkout_reference,
                    paid_at,
                    created_at

                FROM payments

                WHERE
                    id = :payment_id

                LIMIT 1
                "
            );


        $paymentStmt->execute(
            [
                ':payment_id' =>
                    (int)
                    $subscription['payment_id']
            ]
        );


        $payment =
            $paymentStmt->fetch()
            ?:
            null;

    } catch (
        Throwable $e
    ) {
    }

}


getResponse(
    true,
    'Subscription loaded successfully.',
    [

        'subscription' =>
            array_merge(
                $subscription,
                [
                    'avatar_url' =>
                        $avatarUrl,

                    'payment' =>
                        $payment

                ]
            )

    ]
);