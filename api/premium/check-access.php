<?php
/**
 * ============================================================
 * LOVEMI - PREMIUM ACCESS CHECK API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\premium\check-access.php
 *
 * Purpose:
 * - Verify the current PHP authentication session.
 * - Validate the database session token.
 * - Verify that the account is active.
 * - Check for an active LOVEMI Premium subscription.
 * - Automatically treat expired subscriptions as expired.
 * - Return safe premium-access information.
 *
 * IMPORTANT:
 * This endpoint NEVER trusts a user_id supplied by the browser.
 * The user is identified from the server-side PHP session.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   LOAD DATABASE
   ============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   RESPONSE HEADERS
   ============================================================ */

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


/* ============================================================
   HTTPS DETECTION
   ============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== 'off';


/* ============================================================
   SESSION COOKIE CONFIGURATION
   ============================================================ */

session_set_cookie_params(
    [
        'lifetime' => 0,

        'path' => '/',

        'domain' => '',

        'secure' => $isHttps,

        'httponly' => true,

        'samesite' => 'Lax'
    ]
);


/* ============================================================
   START PHP SESSION
   ============================================================ */

if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   JSON RESPONSE
   ============================================================ */

function premiumResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $extra
        ),
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );


    exit;
}


/* ============================================================
   REQUEST METHOD
   ============================================================ */

/*
 * Access checks are read-only.
 *
 * GET is enough for this endpoint.
 */

if (
    !in_array(
        $_SERVER['REQUEST_METHOD'] ?? '',
        ['GET', 'POST'],
        true
    )
) {

    premiumResponse(
        false,
        'Only GET or POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   DATABASE CONNECTION
   ============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM DATABASE ERROR] '
        . $e->getMessage()
    );


    premiumResponse(
        false,
        'Unable to check premium access.',
        [
            'authenticated' =>
                false,

            'has_premium' =>
                false,

            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   SESSION VALUES
   ============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ? trim(
            (string)
            $_SESSION['lovemi_session_token']
        )
        : '';


/* ============================================================
   NO AUTHENTICATED USER
   ============================================================ */

if (
    $userId <= 0
    || $sessionToken === ''
) {

    premiumResponse(
        true,
        'You are not logged in.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'UNAUTHENTICATED'
        ]
    );

}


/* ============================================================
   HASH SESSION TOKEN
   ============================================================ */

$sessionTokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/* ============================================================
   VALIDATE DATABASE SESSION
   ============================================================ */

try {

    $sessionStmt =
        $pdo->prepare(
            "
            SELECT

                us.id AS session_id,

                us.user_id,

                us.expires_at,

                us.revoked_at,

                u.username,

                u.account_status,

                u.is_active,

                u.is_suspended,

                u.is_deleted

            FROM user_sessions us

            INNER JOIN users u
                ON u.id = us.user_id

            WHERE
                us.session_token_hash =
                    :session_token_hash

            LIMIT 1
            "
        );


    $sessionStmt->execute(
        [
            ':session_token_hash' =>
                $sessionTokenHash
        ]
    );


    $session =
        $sessionStmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SESSION QUERY ERROR] '
        . $e->getMessage()
    );


    premiumResponse(
        false,
        'Unable to verify your login session.',
        [
            'authenticated' =>
                false,

            'has_premium' =>
                false,

            'code' =>
                'SESSION_ERROR'
        ],
        500
    );

}


/* ============================================================
   INVALID SESSION
   ============================================================ */

if (!$session) {

    unset(
        $_SESSION['lovemi_user_id'],
        $_SESSION['lovemi_session_token'],
        $_SESSION['lovemi_database_session_id']
    );


    premiumResponse(
        true,
        'Your login session is no longer valid.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'UNAUTHENTICATED'
        ]
    );

}


/* ============================================================
   VERIFY USER ID MATCH
   ============================================================ */

$databaseUserId =
    (int) $session['user_id'];


if (
    $databaseUserId !== $userId
) {

    /*
     * Possible session tampering.
     */

    error_log(
        '[LOVEMI SECURITY] Session user mismatch.'
        . ' Session user ID: '
        . $userId
        . ' Database user ID: '
        . $databaseUserId
    );


    unset(
        $_SESSION['lovemi_user_id'],
        $_SESSION['lovemi_session_token'],
        $_SESSION['lovemi_database_session_id']
    );


    premiumResponse(
        true,
        'Your login session is invalid.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'INVALID_SESSION'
        ]
    );

}


/* ============================================================
   CHECK SESSION REVOCATION
   ============================================================ */

if (
    $session['revoked_at'] !== null
    && $session['revoked_at'] !== ''
) {

    unset(
        $_SESSION['lovemi_user_id'],
        $_SESSION['lovemi_session_token'],
        $_SESSION['lovemi_database_session_id']
    );


    premiumResponse(
        true,
        'Your login session has been revoked.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'SESSION_REVOKED'
        ]
    );

}


/* ============================================================
   CHECK SESSION EXPIRY
   ============================================================ */

if (
    $session['expires_at'] !== null
) {

    $expiresTimestamp =
        strtotime(
            (string)
            $session['expires_at']
        );


    if (
        $expiresTimestamp !== false
        && $expiresTimestamp <= time()
    ) {

        /*
         * Revoke the expired session.
         */

        try {

            $revokeStmt =
                $pdo->prepare(
                    "
                    UPDATE user_sessions

                    SET revoked_at =
                        CURRENT_TIMESTAMP

                    WHERE id =
                        :session_id

                    LIMIT 1
                    "
                );


            $revokeStmt->execute(
                [
                    ':session_id' =>
                        (int)
                        $session['session_id']
                ]
            );

        } catch (Throwable $e) {

            error_log(
                '[LOVEMI PREMIUM SESSION REVOKE ERROR] '
                . $e->getMessage()
            );

        }


        unset(
            $_SESSION['lovemi_user_id'],
            $_SESSION['lovemi_session_token'],
            $_SESSION['lovemi_database_session_id']
        );


        premiumResponse(
            true,
            'Your login session has expired.',
            [
                'authenticated' =>
                    false,

                'logged_in' =>
                    false,

                'has_premium' =>
                    false,

                'premium' =>
                    false,

                'premium_active' =>
                    false,

                'code' =>
                    'SESSION_EXPIRED'
            ]
        );

    }

}


/* ============================================================
   CHECK ACCOUNT STATUS
   ============================================================ */

$accountStatus =
    strtolower(
        trim(
            (string)
            $session['account_status']
        )
    );


$isActive =
    (bool)
    $session['is_active'];


$isSuspended =
    (bool)
    $session['is_suspended'];


$isDeleted =
    (bool)
    $session['is_deleted'];


if ($isDeleted) {

    premiumResponse(
        true,
        'This account is no longer available.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'ACCOUNT_DELETED'
        ]
    );

}


if (
    !$isActive
    || $isSuspended
    || in_array(
        $accountStatus,
        [
            'suspended',
            'blocked',
            'disabled',
            'deleted'
        ],
        true
    )
) {

    premiumResponse(
        true,
        'Your account is currently unavailable.',
        [
            'authenticated' =>
                false,

            'logged_in' =>
                false,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ]
    );

}


/* ============================================================
   REFRESH LAST ACTIVITY
   ============================================================ */

try {

    $activityStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET last_activity_at =
                CURRENT_TIMESTAMP

            WHERE id =
                :session_id

            LIMIT 1
            "
        );


    $activityStmt->execute(
        [
            ':session_id' =>
                (int)
                $session['session_id']
        ]
    );


    $userActivityStmt =
        $pdo->prepare(
            "
            UPDATE users

            SET last_seen_at =
                CURRENT_TIMESTAMP

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $userActivityStmt->execute(
        [
            ':user_id' =>
                $databaseUserId
        ]
    );


} catch (Throwable $e) {

    /*
     * Activity update failure is logged but should not
     * incorrectly deny a valid premium user.
     */

    error_log(
        '[LOVEMI PREMIUM ACTIVITY ERROR] '
        . $e->getMessage()
    );

}


/* ============================================================
   FIND LOVEMI PREMIUM SERVICE
   ============================================================ */

try {

    $serviceStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                name,
                slug,
                service_type,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium,
                is_active

            FROM services

            WHERE slug =
                'lovemi-premium'

              AND is_premium =
                TRUE

            LIMIT 1
            "
        );


    $serviceStmt->execute();


    $service =
        $serviceStmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SERVICE ERROR] '
        . $e->getMessage()
    );


    premiumResponse(
        false,
        'Unable to determine the premium service.',
        [
            'authenticated' =>
                true,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'SERVICE_ERROR'
        ],
        500
    );

}


/* ============================================================
   SERVICE NOT FOUND
   ============================================================ */

if (!$service) {

    premiumResponse(
        false,
        'The LOVEMI Premium service is not configured.',
        [
            'authenticated' =>
                true,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'PREMIUM_SERVICE_NOT_CONFIGURED'
        ],
        500
    );

}


/* ============================================================
   CHECK SERVICE ACTIVE
   ============================================================ */

if (
    !(bool)
    $service['is_active']
) {

    premiumResponse(
        true,
        'LOVEMI Premium is currently unavailable.',
        [
            'authenticated' =>
                true,

            'logged_in' =>
                true,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'service_active' =>
                false,

            'code' =>
                'PREMIUM_SERVICE_INACTIVE'
        ]
    );

}


/* ============================================================
   FIND ACTIVE SUBSCRIPTION
   ============================================================ */

try {

    $subscriptionStmt =
        $pdo->prepare(
            "
            SELECT

                s.id AS subscription_id,

                s.user_id,

                s.service_id,

                s.status,

                s.start_at,

                s.end_at,

                s.base_amount_usd,

                s.amount_paid,

                s.currency_id,

                s.exchange_rate,

                s.usage_limit,

                s.usage_used,

                c.code AS currency_code,

                c.name AS currency_name,

                c.symbol AS currency_symbol,

                s.payment_id

            FROM subscriptions s

            LEFT JOIN currencies c
                ON c.id = s.currency_id

            WHERE
                s.user_id =
                    :user_id

              AND s.service_id =
                    :service_id

              AND s.status =
                    'active'

              AND s.start_at IS NOT NULL

              AND s.start_at <=
                    CURRENT_TIMESTAMP

              AND s.end_at IS NOT NULL

              AND s.end_at >
                    CURRENT_TIMESTAMP

            ORDER BY
                s.end_at DESC

            LIMIT 1
            "
        );


    $subscriptionStmt->execute(
        [
            ':user_id' =>
                $databaseUserId,

            ':service_id' =>
                (int)
                $service['id']
        ]
    );


    $subscription =
        $subscriptionStmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM SUBSCRIPTION ERROR] '
        . $e->getMessage()
    );


    premiumResponse(
        false,
        'Unable to check your premium subscription.',
        [
            'authenticated' =>
                true,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'code' =>
                'SUBSCRIPTION_QUERY_ERROR'
        ],
        500
    );

}


/* ============================================================
   NO ACTIVE SUBSCRIPTION
   ============================================================ */

if (!$subscription) {

    /*
     * Check whether there is an expired active record.
     *
     * This also keeps the database status accurate.
     */

    try {

        $expireStmt =
            $pdo->prepare(
                "
                UPDATE subscriptions

                SET
                    status =
                        'expired'

                WHERE
                    user_id =
                        :user_id

                  AND service_id =
                        :service_id

                  AND status =
                        'active'

                  AND end_at IS NOT NULL

                  AND end_at <=
                        CURRENT_TIMESTAMP
                "
            );


        $expireStmt->execute(
            [
                ':user_id' =>
                    $databaseUserId,

                ':service_id' =>
                    (int)
                    $service['id']
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PREMIUM EXPIRY UPDATE ERROR] '
            . $e->getMessage()
        );

    }


    premiumResponse(
        true,
        'You do not have an active LOVEMI Premium subscription.',
        [
            'authenticated' =>
                true,

            'logged_in' =>
                true,

            'has_premium' =>
                false,

            'premium' =>
                false,

            'premium_active' =>
                false,

            'service_active' =>
                true,

            'subscription' =>
                null,

            'code' =>
                'PREMIUM_REQUIRED'
        ]
    );

}


/* ============================================================
   CALCULATE REMAINING TIME
   ============================================================ */

$endTimestamp =
    strtotime(
        (string)
        $subscription['end_at']
    );


$startTimestamp =
    strtotime(
        (string)
        $subscription['start_at']
    );


$remainingSeconds =
    0;


$remainingDays =
    0;


if (
    $endTimestamp !== false
) {

    $remainingSeconds =
        max(
            0,
            $endTimestamp - time()
        );


    $remainingDays =
        (int)
        ceil(
            $remainingSeconds / 86400
        );

}


/* ============================================================
   FINAL ACTIVE PREMIUM RESPONSE
   ============================================================ */

premiumResponse(
    true,
    'LOVEMI Premium is active.',
    [
        'authenticated' =>
            true,

        'logged_in' =>
            true,

        'has_premium' =>
            true,

        'premium' =>
            true,

        'premium_active' =>
            true,

        'service_active' =>
            true,

        'code' =>
            'PREMIUM_ACTIVE',

        'service' =>
            [
                'id' =>
                    (int)
                    $service['id'],

                'name' =>
                    (string)
                    $service['name'],

                'slug' =>
                    (string)
                    $service['slug'],

                'duration_days' =>
                    (int)
                    $service['duration_days']
            ],

        'subscription' =>
            [
                'id' =>
                    (int)
                    $subscription['subscription_id'],

                'status' =>
                    (string)
                    $subscription['status'],

                'start_at' =>
                    $subscription['start_at'],

                'end_at' =>
                    $subscription['end_at'],

                'base_amount_usd' =>
                    (float)
                    $subscription['base_amount_usd'],

                /*
                 * This is the amount actually paid in the
                 * user's currency. It is safe to expose.
                 */
                'amount_paid' =>
                    (float)
                    $subscription['amount_paid'],

                'currency' =>
                    $subscription['currency_code'],

                'currency_name' =>
                    $subscription['currency_name'],

                'currency_symbol' =>
                    $subscription['currency_symbol'],

                'exchange_rate' =>
                    $subscription['exchange_rate']
                    !== null
                        ? (float)
                          $subscription['exchange_rate']
                        : null,

                'usage_limit' =>
                    $subscription['usage_limit'] !== null
                        ? (int)
                          $subscription['usage_limit']
                        : null,

                'usage_used' =>
                    (int)
                    $subscription['usage_used'],

                'remaining_seconds' =>
                    $remainingSeconds,

                'remaining_days' =>
                    $remainingDays
            ]
    ]
);