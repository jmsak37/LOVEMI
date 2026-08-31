<?php
/**
 * ============================================================
 * LOVEMI - CREATE CONNECTION
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\connections\create.php
 *
 * RULE:
 *
 * Premium user
 *      +
 * Click another eligible member
 *      =
 * Connection is created
 *
 * The receiving member does NOT need premium.
 *
 * Phone/WhatsApp information is NOT returned here.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (
    session_status() !== PHP_SESSION_ACTIVE
) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function connectionResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
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

    connectionResponse(
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
   AUTHENTICATION
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
          $_SESSION['lovemi_user_id']
        : 0;


if (
    $currentUserId <= 0
) {

    connectionResponse(
        false,
        'Please log in before creating a connection.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
        ],
        401
    );
}


/* ============================================================
   REQUEST
============================================================ */

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
    $data = [];
}


$targetUserId =
    isset(
        $data['user_id']
    )
        ? (int)
          $data['user_id']
        : 0;


$source =
    trim(
        (string)(
            $data['source']
            ?? 'unknown'
        )
    );


if (
    $targetUserId <= 0
) {

    connectionResponse(
        false,
        'The selected member is invalid.',
        [
            'code' =>
                'INVALID_TARGET'
        ],
        422
    );
}


/* ============================================================
   SELF CONNECTION
============================================================ */

if (
    $targetUserId ===
    $currentUserId
) {

    connectionResponse(
        false,
        'You cannot connect with your own account.',
        [
            'code' =>
                'SELF_CONNECTION'
        ],
        422
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION DB] '
        . $e->getMessage()
    );

    connectionResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   CURRENT USER
============================================================ */

$userStmt =
    $pdo->prepare(
        "
        SELECT

            u.id,
            u.email_verified,
            u.is_active,
            u.is_suspended,
            u.is_deleted,

            EXISTS
            (
                SELECT 1

                FROM subscriptions s

                WHERE s.user_id = u.id

                  AND s.status = 'active'

                  AND s.starts_at <= CURRENT_TIMESTAMP

                  AND
                      (
                          s.ends_at IS NULL
                          OR
                          s.ends_at > CURRENT_TIMESTAMP
                      )

                LIMIT 1
            ) AS has_premium

        FROM users u

        WHERE u.id = :id

        LIMIT 1
        "
    );


$userStmt->execute(
    [
        ':id' =>
            $currentUserId
    ]
);


$currentUser =
    $userStmt->fetch();


if (
    !$currentUser
) {

    connectionResponse(
        false,
        'Your account could not be found.',
        [],
        404
    );
}


/* ============================================================
   ACCOUNT CHECK
============================================================ */

if (
    !(bool)$currentUser['email_verified']
) {

    connectionResponse(
        false,
        'Your email must be verified first.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED'
        ],
        403
    );
}


if (
    !(bool)$currentUser['is_active']
    ||
    (bool)$currentUser['is_suspended']
    ||
    (bool)$currentUser['is_deleted']
) {

    connectionResponse(
        false,
        'Your account cannot create connections.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   PREMIUM CHECK
============================================================ */

if (
    !(bool)$currentUser['has_premium']
) {

    connectionResponse(
        false,
        'Premium access is required to create a connection.',
        [
            'code' =>
                'PREMIUM_REQUIRED',

            'allowed' =>
                false,

            'redirect' =>
                'premium.html?return=dashboard.html'
        ],
        403
    );
}


/* ============================================================
   TARGET USER
============================================================ */

$targetStmt =
    $pdo->prepare(
        "
        SELECT

            id,
            full_names,
            username,
            gender,
            email_verified,
            is_active,
            is_suspended,
            is_deleted

        FROM users

        WHERE id = :id

        LIMIT 1
        "
    );


$targetStmt->execute(
    [
        ':id' =>
            $targetUserId
    ]
);


$targetUser =
    $targetStmt->fetch();


if (
    !$targetUser
) {

    connectionResponse(
        false,
        'The selected member could not be found.',
        [
            'code' =>
                'TARGET_NOT_FOUND'
        ],
        404
    );
}


if (
    !(bool)$targetUser['email_verified']
    ||
    !(bool)$targetUser['is_active']
    ||
    (bool)$targetUser['is_suspended']
    ||
    (bool)$targetUser['is_deleted']
) {

    connectionResponse(
        false,
        'This member is not currently available for connections.',
        [
            'code' =>
                'TARGET_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   BLOCK CHECK
============================================================ */

$blockStmt =
    $pdo->prepare(
        "
        SELECT id

        FROM blocks

        WHERE
            (
                blocker_id = :user_a
                AND
                blocked_id = :user_b
            )

            OR

            (
                blocker_id = :user_b2
                AND
                blocked_id = :user_a2
            )

        LIMIT 1
        "
    );


$blockStmt->execute(
    [
        ':user_a' =>
            $currentUserId,

        ':user_b' =>
            $targetUserId,

        ':user_b2' =>
            $targetUserId,

        ':user_a2' =>
            $currentUserId
    ]
);


if (
    $blockStmt->fetch()
) {

    connectionResponse(
        false,
        'This connection cannot be created.',
        [
            'code' =>
                'CONNECTION_BLOCKED'
        ],
        403
    );
}


/* ============================================================
   CHECK EXISTING CONNECTION
============================================================ */

$existingStmt =
    $pdo->prepare(
        "
        SELECT

            id,
            requester_id,
            receiver_id,
            status

        FROM connections

        WHERE
            (
                requester_id = :user_a
                AND
                receiver_id = :user_b
            )

            OR

            (
                requester_id = :user_b2
                AND
                receiver_id = :user_a2
            )

        LIMIT 1
        "
    );


$existingStmt->execute(
    [
        ':user_a' =>
            $currentUserId,

        ':user_b' =>
            $targetUserId,

        ':user_b2' =>
            $targetUserId,

        ':user_a2' =>
            $currentUserId
    ]
);


$existing =
    $existingStmt->fetch();


/* ============================================================
   EXISTING
============================================================ */

if (
    $existing
) {

    if (
        strtolower(
            (string)
            $existing['status']
        )
        ===
        'accepted'
    ) {

        connectionResponse(
            true,
            'You are already connected with this member.',
            [
                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'accepted',

                'already_connected' =>
                    true
            ]
        );
    }


    /*
     * Convert an existing pending connection to an active
     * connection because the authenticated initiator has premium.
     */

    try {

        $update =
            $pdo->prepare(
                "
                UPDATE connections

                SET

                    status = 'accepted',

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );


        $update->execute(
            [
                ':id' =>
                    (int)
                    $existing['id']
            ]
        );


        connectionResponse(
            true,
            'Connection created successfully.',
            [
                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'accepted',

                'connected' =>
                    true
            ]
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CONNECTION UPDATE] '
            . $e->getMessage()
        );

        connectionResponse(
            false,
            'Unable to activate this connection.',
            [],
            500
        );
    }
}


/* ============================================================
   CREATE CONNECTION
============================================================ */

try {

    $pdo->beginTransaction();


    $insert =
        $pdo->prepare(
            "
            INSERT INTO connections
            (
                requester_id,
                receiver_id,
                status,
                created_at,
                updated_at
            )
            VALUES
            (
                :requester_id,
                :receiver_id,
                'accepted',
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insert->execute(
        [
            ':requester_id' =>
                $currentUserId,

            ':receiver_id' =>
                $targetUserId
        ]
    );


    $connectionId =
        (int)
        $pdo->lastInsertId();


    /*
     * Create notification for the receiving member.
     *
     * We only store notification metadata.
     * Contact information is not placed in notification text.
     */

    try {

        $notification =
            $pdo->prepare(
                "
                INSERT INTO notifications
                (
                    user_id,
                    type,
                    title,
                    message,
                    entity_type,
                    entity_id,
                    is_read,
                    created_at
                )
                VALUES
                (
                    :user_id,
                    'connection',
                    'New Connection',
                    :message,
                    'connection',
                    :entity_id,
                    FALSE,
                    CURRENT_TIMESTAMP
                )
                "
            );


        $notification->execute(
            [
                ':user_id' =>
                    $targetUserId,

                ':message' =>
                    'Someone connected with you on LOVEMI.',

                ':entity_id' =>
                    $connectionId
            ]
        );

    } catch (Throwable $notificationError) {

        /*
         * Do not break the connection when the optional
         * notification record cannot be inserted.
         */

        error_log(
            '[LOVEMI CONNECTION NOTIFICATION] '
            . $notificationError->getMessage()
        );

    }


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CONNECTION CREATE] '
        . $e->getMessage()
    );


    connectionResponse(
        false,
        'Unable to create the connection.',
        [
            'code' =>
                'CONNECTION_CREATE_ERROR'
        ],
        500
    );
}


/* ============================================================
   SUCCESS
============================================================ */

connectionResponse(
    true,
    'Connection created successfully.',
    [
        'connection_id' =>
            $connectionId,

        'status' =>
            'accepted',

        'connected' =>
            true,

        'target_user_id' =>
            $targetUserId,

        'redirect' =>
            'connections.html'
    ],
    201
);