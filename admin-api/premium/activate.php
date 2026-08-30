<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - ACTIVATE PREMIUM API
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
| RESPONSE
|--------------------------------------------------------------------------
*/

function premiumActivateResponse(
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

    premiumActivateResponse(
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


$subscriptionId =
    (int)(
        $data['subscription_id']
        ??
        0
    );


if (
    $subscriptionId <= 0
) {

    premiumActivateResponse(
        false,
        'A valid subscription ID is required.',
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

    premiumActivateResponse(
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

    premiumActivateResponse(
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

                AND pm.slug = 'premium.manage'

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

        premiumActivateResponse(
            false,
            'You do not have permission to manage premium subscriptions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    premiumActivateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| LOAD SUBSCRIPTION
|--------------------------------------------------------------------------
*/

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

                sv.duration_days,

                sv.max_usage,

                sv.base_price_usd,

                sv.is_premium

            FROM subscriptions s

            INNER JOIN users u
                ON u.id = s.user_id

            INNER JOIN services sv
                ON sv.id = s.service_id

            WHERE
                s.id = :subscription_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':subscription_id' =>
                $subscriptionId
        ]
    );


    $subscription =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    premiumActivateResponse(
        false,
        'Unable to load the subscription.',
        [],
        500
    );

}


if (
    !$subscription
) {

    premiumActivateResponse(
        false,
        'Premium subscription not found.',
        [],
        404
    );

}


if (
    !(bool)
    $subscription['is_premium']
) {

    premiumActivateResponse(
        false,
        'The selected service is not a premium service.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| USER STATE
|--------------------------------------------------------------------------
*/

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                is_active,

                is_suspended,

                is_deleted,

                email_verified,

                account_status

            FROM users

            WHERE
                id = :user_id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                (int)
                $subscription['user_id']
        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    premiumActivateResponse(
        false,
        'Unable to verify the member account.',
        [],
        500
    );

}


if (
    !$user
    ||
    !(bool)$user['is_active']
    ||
    (bool)$user['is_suspended']
    ||
    (bool)$user['is_deleted']
) {

    premiumActivateResponse(
        false,
        'The member account is not currently active.',
        [],
        403
    );

}


/*
|--------------------------------------------------------------------------
| ACTIVE CHECK
|--------------------------------------------------------------------------
*/

if (
    strtolower(
        (string)
        $subscription['status']
    )
    ===
    'active'
    &&
    !empty(
        $subscription['end_at']
    )
    &&
    strtotime(
        (string)
        $subscription['end_at']
    )
    > time()
) {

    premiumActivateResponse(
        false,
        'This premium subscription is already active.',
        [
            'code' =>
                'ALREADY_ACTIVE'
        ],
        409
    );

}


/*
|--------------------------------------------------------------------------
| DATES
|--------------------------------------------------------------------------
|
| If an existing subscription has a future end date, preserve it.
| Otherwise activation begins now.
|--------------------------------------------------------------------------
*/

$now =
    new DateTimeImmutable(
        'now'
    );


$startAt =
    $now->format(
        'Y-m-d H:i:s'
    );


$durationDays =
    max(
        1,
        (int)(
            $subscription['duration_days']
            ??
            30
        )
    );


$endAt =
    $now
        ->modify(
            '+'
            .
            $durationDays
            .
            ' days'
        )
        ->format(
            'Y-m-d H:i:s'
        );


$basePrice =
    (float)(
        $subscription['base_amount_usd']
        ??
        $subscription['base_price_usd']
        ??
        0
    );


/*
|--------------------------------------------------------------------------
| ACTIVATE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    /*
    |--------------------------------------------------------------------------
    | Make sure another active subscription does not exist.
    |--------------------------------------------------------------------------
    */

    $existing =
        $pdo->prepare(
            "
            SELECT id

            FROM subscriptions

            WHERE

                user_id = :user_id

                AND status = 'active'

                AND end_at > CURRENT_TIMESTAMP

                AND id <> :subscription_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $existing->execute(
        [
            ':user_id' =>
                (int)
                $subscription['user_id'],

            ':subscription_id' =>
                $subscriptionId
        ]
    );


    if (
        $existing->fetch()
    ) {

        throw new RuntimeException(
            'This user already has another active premium subscription.'
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Update subscription
    |--------------------------------------------------------------------------
    */

    $update =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET

                status =
                    'active',

                start_at =
                    :start_at,

                end_at =
                    :end_at,

                base_amount_usd =
                    :base_amount_usd,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :subscription_id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':start_at' =>
                $startAt,

            ':end_at' =>
                $endAt,

            ':base_amount_usd' =>
                $basePrice,

            ':subscription_id' =>
                $subscriptionId
        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Premium activated notification
    |--------------------------------------------------------------------------
    */

    $notificationType =
        $pdo->prepare(
            "
            SELECT id

            FROM notification_types

            WHERE slug =
                'premium_activated'

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
                'Premium Activated',
                :message,
                'subscription',
                :reference_id
            )
            "
        );


    $notification->execute(
        [
            ':user_id' =>
                (int)
                $subscription['user_id'],

            ':notification_type_id' =>
                $notificationTypeId,

            ':sender_id' =>
                $adminId,

            ':message' =>
                'Your LOVEMI Premium subscription has been activated by administration.',

            ':reference_id' =>
                $subscriptionId
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
                'admin_activate_premium',
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
                    ],
                    JSON_UNESCAPED_UNICODE
                    |
                    JSON_UNESCAPED_SLASHES
                ),

            ':new_values' =>
                json_encode(
                    [
                        'status' =>
                            'active',

                        'start_at' =>
                            $startAt,

                        'end_at' =>
                            $endAt
                    ],
                    JSON_UNESCAPED_UNICODE
                    |
                    JSON_UNESCAPED_SLASHES
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
        '[LOVEMI PREMIUM ACTIVATE] '
        .
        $e->getMessage()
    );


    premiumActivateResponse(
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

premiumActivateResponse(
    true,
    'Premium subscription activated successfully.',
    [

        'subscription_id' =>
            $subscriptionId,

        'status' =>
            'active',

        'start_at' =>
            $startAt,

        'end_at' =>
            $endAt

    ]
);