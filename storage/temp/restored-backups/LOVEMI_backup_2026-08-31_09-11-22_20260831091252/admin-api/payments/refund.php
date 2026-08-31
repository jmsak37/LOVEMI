<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - RECORD REFUND
|--------------------------------------------------------------------------
|
| IMPORTANT:
|
| This endpoint records the payment as refunded in LOVEMI.
| It does NOT claim to send money back through a payment
| gateway. The actual gateway refund should be performed
| through the appropriate gateway integration.
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

function paymentRefundResponse(
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

    paymentRefundResponse(
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


$reason =
    trim(
        (string)(
            $data['reason']
            ??
            ''
        )
    );


if (
    $paymentId <= 0
) {

    paymentRefundResponse(
        false,
        'A valid payment ID is required.',
        [],
        422
    );

}


if (
    $reason === ''
) {

    paymentRefundResponse(
        false,
        'A refund reason is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $reason
    )
    >
    1000
) {

    paymentRefundResponse(
        false,
        'The refund reason is too long.',
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

    paymentRefundResponse(
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

    paymentRefundResponse(
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

        paymentRefundResponse(
            false,
            'You do not have permission to refund payments.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    paymentRefundResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| REFUND RECORD
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                service_id,

                subscription_id,

                payment_reference,

                gateway,

                status,

                amount_paid,

                currency_id

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
        $oldStatus !== 'paid'
    ) {

        throw new RuntimeException(
            'Only paid payments can be recorded as refunded.'
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Mark payment refunded
    |--------------------------------------------------------------------------
    */

    $update =
        $pdo->prepare(
            "
            UPDATE payments

            SET

                status =
                    'refunded',

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :payment_id

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
    | If a related subscription is active,
    | expire it immediately.
    |--------------------------------------------------------------------------
    */

    if (
        !empty(
            $payment['subscription_id']
        )
    ) {

        $subscriptionUpdate =
            $pdo->prepare(
                "
                UPDATE subscriptions

                SET

                    status =
                        CASE
                            WHEN status = 'active'
                                THEN 'cancelled'
                            ELSE status
                        END,

                    end_at =
                        CASE
                            WHEN status = 'active'
                                THEN CURRENT_TIMESTAMP
                            ELSE end_at
                        END,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE
                    id = :subscription_id

                LIMIT 1
                "
            );


        $subscriptionUpdate->execute(
            [
                ':subscription_id' =>
                    (int)
                    $payment['subscription_id']
            ]
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Notification
    |--------------------------------------------------------------------------
    */

    $notificationType =
        $pdo->prepare(
            "
            SELECT id

            FROM notification_types

            WHERE slug =
                'payment_failed'

            LIMIT 1
            "
        );


    $notificationType->execute();


    $notificationTypeId =
        $notificationType->fetchColumn()
        ?:
        null;


    $notification =
        $pdo->prepare(
            "
            INSERT INTO notifications
            (
                user_id,
                notification_type_id,
                sender_id,
                title,
                message,
                reference_type,
                reference_id
            )
            VALUES
            (
                :user_id,
                :notification_type_id,
                :sender_id,
                'Payment Refunded',
                :message,
                'payment',
                :reference_id
            )
            "
        );


    $notification->execute(
        [
            ':user_id' =>
                (int)
                $payment['user_id'],

            ':notification_type_id' =>
                $notificationTypeId,

            ':sender_id' =>
                $adminId,

            ':message' =>
                'Your payment '
                .
                $payment['payment_reference']
                .
                ' has been recorded as refunded. Reason: '
                .
                $reason,

            ':reference_id' =>
                $paymentId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | AUDIT
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
                'admin_refund_payment',
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
                            'refunded',

                        'reason' =>
                            $reason,

                        'recorded_by_admin' =>
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
        '[LOVEMI PAYMENT REFUND] '
        .
        $e->getMessage()
    );


    paymentRefundResponse(
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

paymentRefundResponse(
    true,
    'The payment refund has been recorded in LOVEMI.',
    [

        'payment_id' =>
            $paymentId,

        'status' =>
            'refunded',

        'gateway_refund_required' =>
            true,

        'reason' =>
            $reason

    ]
);