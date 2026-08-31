<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function premiumExpireResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    premiumExpireResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   ADMIN AUTHENTICATION
============================================================ */

$adminId =
    isset(
        $_SESSION['lovemi_admin_id']
    )
        ?
        (int)
        $_SESSION['lovemi_admin_id']
        :
        0;


/*
 * Support installations that store the administrator's user ID
 * in the normal session and distinguish it using an admin flag.
 */

if (
    $adminId <= 0
    &&
    isset(
        $_SESSION['lovemi_is_admin']
    )
    &&
    (bool)
    $_SESSION['lovemi_is_admin']
) {

    $adminId =
        isset(
            $_SESSION['lovemi_user_id']
        )
            ?
            (int)
            $_SESSION['lovemi_user_id']
            :
            0;

}


if (
    $adminId <= 0
) {

    premiumExpireResponse(
        false,
        'Administrator access is required.',
        [
            'code' =>
                'ADMIN_AUTHENTICATION_REQUIRED',

            'redirect' =>
                'admin/index.html'

        ],
        403
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM EXPIRE DB] '
        .
        $e->getMessage()
    );


    premiumExpireResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   VERIFY ADMIN
============================================================ */

try {

    $adminStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.is_active,
                u.is_suspended,
                u.is_deleted,

                r.name AS role_name,
                r.slug AS role_slug

            FROM users u

            INNER JOIN admins a
                ON a.user_id =
                   u.id

            LEFT JOIN roles r
                ON r.id =
                   a.role_id

            WHERE u.id =
                  :admin_id

              AND a.is_active =
                  1

            LIMIT 1
            "
        );


    $adminStmt->execute(
        [
            ':admin_id' =>
                $adminId
        ]
    );


    $admin =
        $adminStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM EXPIRE ADMIN] '
        .
        $e->getMessage()
    );


    premiumExpireResponse(
        false,
        'Unable to verify administrator access.',
        [
            'code' =>
                'ADMIN_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$admin
) {

    /*
     * Some early LOVEMI installations may use only
     * lovemi_admin_id without the admins table being seeded.
     *
     * Do not allow access just because a session value exists.
     */

    premiumExpireResponse(
        false,
        'Your administrator account could not be verified.',
        [
            'code' =>
                'ADMIN_NOT_VERIFIED'
        ],
        403
    );
}


if (
    (int)
    $admin['is_deleted']
    ===
    1
    ||
    (int)
    $admin['is_suspended']
    ===
    1
    ||
    (int)
    $admin['is_active']
    !==
    1
) {

    premiumExpireResponse(
        false,
        'Your administrator account is not active.',
        [
            'code' =>
                'ADMIN_INACTIVE'
        ],
        403
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $raw,
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


$subscriptionId =
    isset(
        $input['subscription_id']
    )
        ?
        (int)
        $input['subscription_id']
        :
        0;


$userId =
    isset(
        $input['user_id']
    )
        ?
        (int)
        $input['user_id']
        :
        0;


$mode =
    strtolower(
        trim(
            (string)
            (
                $input['mode']
                ??
                'single'
            )
        )
    );


if (
    !in_array(
        $mode,
        [
            'single',
            'sweep'
        ],
        true
    )
) {

    premiumExpireResponse(
        false,
        'Invalid expiration mode.',
        [
            'code' =>
                'INVALID_MODE'
        ],
        422
    );
}


/* ============================================================
   SINGLE SUBSCRIPTION
============================================================ */

if (
    $mode ===
    'single'
) {

    if (
        $subscriptionId <= 0
        &&
        $userId <= 0
    ) {

        premiumExpireResponse(
            false,
            'Provide subscription_id or user_id for single expiration.',
            [
                'code' =>
                    'SUBSCRIPTION_IDENTIFIER_REQUIRED'
            ],
            422
        );
    }


    try {

        if (
            $subscriptionId > 0
        ) {

            $where =
                's.id = :subscription_id';


            $params = [

                ':subscription_id' =>
                    $subscriptionId

            ];

        } else {

            $where =
                "
                s.user_id = :user_id
                ";


            $params = [

                ':user_id' =>
                    $userId

            ];

        }


        $findStmt =
            $pdo->prepare(
                "
                SELECT

                    s.id,
                    s.user_id,
                    s.status,
                    s.start_at,
                    s.end_at,

                    sv.name AS service_name,
                    sv.slug AS service_slug

                FROM subscriptions s

                INNER JOIN services sv
                    ON sv.id =
                       s.service_id

                WHERE
                    {$where}

                  AND sv.slug =
                      'lovemi-premium'

                ORDER BY
                    s.id DESC

                LIMIT 1
                "
            );


        $findStmt->execute(
            $params
        );


        $subscription =
            $findStmt->fetch();

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PREMIUM EXPIRE FIND] '
            .
            $e->getMessage()
        );


        premiumExpireResponse(
            false,
            'Unable to find the Premium subscription.',
            [
                'code' =>
                    'SUBSCRIPTION_LOOKUP_FAILED'
            ],
            500
        );
    }


    if (
        !$subscription
    ) {

        premiumExpireResponse(
            false,
            'Premium subscription not found.',
            [
                'code' =>
                    'SUBSCRIPTION_NOT_FOUND'
            ],
            404
        );
    }


    if (
        $subscription['status'] ===
        'expired'
    ) {

        premiumExpireResponse(
            true,
            'This Premium subscription has already expired.',
            [

                'expired' =>
                    false,

                'subscription_id' =>
                    (int)
                    $subscription['id'],

                'status' =>
                    'expired'

            ]
        );
    }


    /*
    |--------------------------------------------------------------------------
    | Expiration requires the subscription to actually be due.
    |--------------------------------------------------------------------------
    |
    | To manually terminate a still-active subscription, the admin
    | should use the admin deactivate endpoint. This endpoint is
    | for expiry processing.
    |--------------------------------------------------------------------------
    */

    if (
        !empty(
            $subscription['end_at']
        )
        &&
        strtotime(
            (string)
            $subscription['end_at']
        )
        >
        time()
    ) {

        premiumExpireResponse(
            false,
            'This Premium subscription has not yet reached its expiry time.',
            [

                'code' =>
                    'PREMIUM_NOT_EXPIRED',

                'subscription_id' =>
                    (int)
                    $subscription['id'],

                'end_at' =>
                    $subscription['end_at']

            ],
            409
        );
    }


    try {

        $updateStmt =
            $pdo->prepare(
                "
                UPDATE subscriptions

                SET

                    status =
                        'expired'

                WHERE id =
                    :subscription_id

                AND status =
                    'active'

                LIMIT 1
                "
            );


        $updateStmt->execute(
            [
                ':subscription_id' =>
                    (int)
                    $subscription['id']
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PREMIUM EXPIRE UPDATE] '
            .
            $e->getMessage()
        );


        premiumExpireResponse(
            false,
            'Unable to expire the Premium subscription.',
            [
                'code' =>
                    'EXPIRY_UPDATE_FAILED'
            ],
            500
        );
    }


    /*
     * Create Premium-expired notification when notification type
     * is available in the database.
     */

    try {

        $notificationTypeStmt =
            $pdo->prepare(
                "
                SELECT

                    id

                FROM notification_types

                WHERE slug =
                    'premium_expired'

                LIMIT 1
                "
            );


        $notificationTypeStmt->execute();


        $notificationTypeId =
            $notificationTypeStmt->fetchColumn();


        if (
            $notificationTypeId
        ) {

            $notificationStmt =
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
                        NULL,
                        'Premium Expired',
                        'Your LOVEMI Premium subscription has expired.',
                        'subscription',
                        :subscription_id
                    )
                    "
                );


            $notificationStmt->execute(
                [

                    ':user_id' =>
                        (int)
                        $subscription['user_id'],

                    ':notification_type_id' =>
                        (int)
                        $notificationTypeId,

                    ':subscription_id' =>
                        (int)
                        $subscription['id']

                ]
            );

        }

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PREMIUM EXPIRED NOTIFICATION] '
            .
            $e->getMessage()
        );

    }


    premiumExpireResponse(
        true,
        'Premium subscription expired successfully.',
        [

            'expired' =>
                true,

            'subscription_id' =>
                (int)
                $subscription['id'],

            'user_id' =>
                (int)
                $subscription['user_id'],

            'status' =>
                'expired',

            'expired_at' =>
                date(
                    'Y-m-d H:i:s'
                )

        ]
    );
}


/* ============================================================
   EXPIRY SWEEP
============================================================ */

try {

    $selectStmt =
        $pdo->prepare(
            "
            SELECT

                s.id,
                s.user_id,
                s.end_at

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id =
                   s.service_id

            WHERE s.status =
                  'active'

              AND s.end_at IS NOT NULL

              AND s.end_at <=
                  CURRENT_TIMESTAMP

              AND sv.slug =
                  'lovemi-premium'

            ORDER BY
                s.id ASC
            "
        );


    $selectStmt->execute();


    $expiredRows =
        $selectStmt->fetchAll();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PREMIUM EXPIRY SWEEP SELECT] '
        .
        $e->getMessage()
    );


    premiumExpireResponse(
        false,
        'Unable to find expired Premium subscriptions.',
        [
            'code' =>
                'EXPIRY_SWEEP_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    count(
        $expiredRows
    )
    ===
    0
) {

    premiumExpireResponse(
        true,
        'No expired Premium subscriptions were found.',
        [

            'expired_count' =>
                0,

            'notifications_created' =>
                0

        ]
    );
}


/* ============================================================
   SWEEP TRANSACTION
============================================================ */

$expiredCount =
    0;


$notificationsCreated =
    0;


try {

    $pdo->beginTransaction();


    $updateStmt =
        $pdo->prepare(
            "
            UPDATE subscriptions

            SET
                status = 'expired'

            WHERE id =
                :subscription_id

              AND status =
                  'active'

            LIMIT 1
            "
        );


    $notificationTypeStmt =
        $pdo->prepare(
            "
            SELECT

                id

            FROM notification_types

            WHERE slug =
                'premium_expired'

            LIMIT 1
            "
        );


    $notificationTypeStmt->execute();


    $notificationTypeId =
        $notificationTypeStmt->fetchColumn();


    $notificationStmt =
        null;


    if (
        $notificationTypeId
    ) {

        $notificationStmt =
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
                    NULL,
                    'Premium Expired',
                    'Your LOVEMI Premium subscription has expired.',
                    'subscription',
                    :subscription_id
                )
                "
            );

    }


    foreach (
        $expiredRows
        as $row
    ) {

        $updateStmt->execute(
            [
                ':subscription_id' =>
                    (int)
                    $row['id']
            ]
        );


        if (
            $updateStmt->rowCount() ===
            1
        ) {

            $expiredCount++;


            if (
                $notificationStmt
            ) {

                $notificationStmt->execute(
                    [

                        ':user_id' =>
                            (int)
                            $row['user_id'],

                        ':notification_type_id' =>
                            (int)
                            $notificationTypeId,

                        ':subscription_id' =>
                            (int)
                            $row['id']

                    ]
                );


                if (
                    $notificationStmt->rowCount()
                    ===
                    1
                ) {

                    $notificationsCreated++;

                }

            }

        }

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
        '[LOVEMI PREMIUM EXPIRY SWEEP] '
        .
        $e->getMessage()
    );


    premiumExpireResponse(
        false,
        'Unable to complete the Premium expiry sweep.',
        [
            'code' =>
                'EXPIRY_SWEEP_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

premiumExpireResponse(
    true,
    'Premium expiry sweep completed successfully.',
    [

        'expired_count' =>
            $expiredCount,

        'notifications_created' =>
            $notificationsCreated,

        'processed_at' =>
            date(
                'Y-m-d H:i:s'
            )

    ]
);