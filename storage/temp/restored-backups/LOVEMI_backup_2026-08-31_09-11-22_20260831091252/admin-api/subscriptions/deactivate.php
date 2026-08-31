<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - DEACTIVATE SUBSCRIPTION
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


function deactivateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

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


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
) {

    deactivateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


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


$subscriptionId =
    (int)(
        $data['subscription_id']
        ??
        0
    );


if (
    $subscriptionId <= 0
) {

    deactivateResponse(
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

    deactivateResponse(
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

    deactivateResponse(
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

        deactivateResponse(
            false,
            'You do not have permission to deactivate subscriptions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    deactivateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                status,
                start_at,
                end_at

            FROM subscriptions

            WHERE id = :id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':id' =>
                $subscriptionId
        ]
    );


    $subscription =
        $stmt->fetch();


    if (
        !$subscription
    ) {

        throw new RuntimeException(
            'Subscription not found.'
        );

    }


    if (
        strtolower(
            (string)
            $subscription['status']
        )
        !==
        'active'
    ) {

        throw new RuntimeException(
            'Only an active subscription can be deactivated.'
        );

    }


    $update =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET

                status = 'cancelled',

                end_at =
                    CURRENT_TIMESTAMP,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':id' =>
                $subscriptionId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Notification
    |--------------------------------------------------------------------------
    */

    $typeStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM notification_types

            WHERE slug = 'premium_expired'

            LIMIT 1
            "
        );


    $typeStmt->execute();


    $typeId =
        $typeStmt->fetchColumn()
        ?:
        null;


    $notify =
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
                'Premium Deactivated',
                :message,
                'subscription',
                :reference_id
            )
            "
        );


    $notify->execute(
        [
            ':user_id' =>
                (int)
                $subscription['user_id'],

            ':notification_type_id' =>
                $typeId,

            ':sender_id' =>
                $adminId,

            ':message' =>
                'Your LOVEMI Premium subscription has been deactivated.',

            ':reference_id' =>
                $subscriptionId
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
                'admin_deactivate_subscription',
                'subscription',
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
                $subscriptionId,

            ':old_values' =>
                json_encode(
                    [
                        'status' =>
                            $subscription['status'],

                        'start_at' =>
                            $subscription['start_at'],

                        'end_at' =>
                            $subscription['end_at']
                    ]
                ),

            ':new_values' =>
                json_encode(
                    [
                        'status' =>
                            'cancelled',

                        'end_at' =>
                            date(
                                'Y-m-d H:i:s'
                            )
                    ]
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
        '[LOVEMI DEACTIVATE SUBSCRIPTION] '
        .
        $e->getMessage()
    );


    deactivateResponse(
        false,
        $e->getMessage(),
        [],
        409
    );

}


deactivateResponse(
    true,
    'Subscription deactivated successfully.',
    [
        'subscription_id' =>
            $subscriptionId,

        'status' =>
            'cancelled'
    ]
);