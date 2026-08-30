<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - EXTEND PREMIUM API
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

function premiumExtendResponse(
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

    premiumExtendResponse(
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


$days =
    (int)(
        $data['days']
        ??
        0
    );


if (
    $subscriptionId <= 0
) {

    premiumExtendResponse(
        false,
        'A valid subscription ID is required.',
        [],
        422
    );

}


if (
    $days <= 0
    ||
    $days > 3650
) {

    premiumExtendResponse(
        false,
        'Days must be between 1 and 3650.',
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

    premiumExtendResponse(
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

    premiumExtendResponse(
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

        premiumExtendResponse(
            false,
            'You do not have permission to manage premium subscriptions.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    premiumExtendResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| LOAD AND UPDATE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                s.*,

                sv.name AS service_name,

                u.username,

                u.full_names

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id = s.service_id

            INNER JOIN users u
                ON u.id = s.user_id

            WHERE
                s.id = :subscription_id

            LIMIT 1

            FOR UPDATE
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


    if (
        !$subscription
    ) {

        throw new RuntimeException(
            'Premium subscription not found.'
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
            'Only an active premium subscription can be extended.'
        );

    }


    $currentEnd =
        !empty(
            $subscription['end_at']
        )
            ?
            new DateTimeImmutable(
                (string)
                $subscription['end_at']
            )
            :
            new DateTimeImmutable(
                'now'
            );


    $now =
        new DateTimeImmutable(
            'now'
        );


    if (
        $currentEnd < $now
    ) {

        $currentEnd =
            $now;

    }


    $newEnd =
        $currentEnd
            ->modify(
                '+'
                .
                $days
                .
                ' days'
            );


    $newEndString =
        $newEnd->format(
            'Y-m-d H:i:s'
        );


    $update =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET

                end_at =
                    :end_at,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :subscription_id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':end_at' =>
                $newEndString,

            ':subscription_id' =>
                $subscriptionId
        ]
    );


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
                'Premium Extended',
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
                'Your LOVEMI Premium subscription has been extended by '
                .
                $days
                .
                ' days.',

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
                'admin_extend_premium',
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
                        'end_at' =>
                            $newEndString,

                        'added_days' =>
                            $days
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
        '[LOVEMI PREMIUM EXTEND] '
        .
        $e->getMessage()
    );


    premiumExtendResponse(
        false,
        $e->getMessage(),
        [],
        409
    );

}


premiumExtendResponse(
    true,
    'Premium subscription extended successfully.',
    [

        'subscription_id' =>
            $subscriptionId,

        'added_days' =>
            $days,

        'end_at' =>
            $newEndString

    ]
);