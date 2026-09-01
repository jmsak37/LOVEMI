<?php
/**
 * ============================================================
 * LOVEMI - CREATE CONNECTION REQUEST
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\posts\connect.php
 *
 * RULE:
 *
 * Premium member
 *      +
 * another eligible member
 *      =
 * pending connection request
 *
 * The receiving member does NOT need Premium.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   PHP ERROR SETTINGS
============================================================ */

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'html_errors',
    '0'
);

error_reporting(
    E_ALL
);


/* ============================================================
   OUTPUT BUFFER
============================================================ */

ob_start();


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
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
   RESPONSE
============================================================ */

function connectResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    if (
        ob_get_length()
    ) {

        ob_clean();

    }


    http_response_code(
        $status
    );


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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/* ============================================================
   EXCEPTION HANDLER
============================================================ */

set_exception_handler(
    function (
        Throwable $e
    ): void {

        error_log(
            '[LOVEMI CONNECT EXCEPTION] '
            .
            $e->getMessage()
        );


        connectResponse(
            false,
            'The connection service is temporarily unavailable.',
            [
                'code' =>
                    'SERVER_EXCEPTION'
            ],
            500
        );

    }
);


/* ============================================================
   ERROR HANDLER
============================================================ */

set_error_handler(
    function (
        int $severity,
        string $message,
        string $file,
        int $line
    ): bool {

        throw new ErrorException(
            $message,
            0,
            $severity,
            $file,
            $line
        );

    }
);


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    connectResponse(
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
   SESSION
============================================================ */

if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   AUTHENTICATION
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    connectResponse(
        false,
        'Please log in before connecting with another member.',
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
   REQUEST BODY
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        $raw ?: '{}',
        true
    );


if (
    !is_array($input)
) {

    $input = [];

}


/* ============================================================
   TARGET USER
============================================================ */

$targetUserId =
    isset(
        $input['user_id']
    )
        ?
        (int)
        $input['user_id']
        :
        0;


if (
    $targetUserId <= 0
) {

    connectResponse(
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

    connectResponse(
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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT DB] '
        .
        $e->getMessage()
    );


    connectResponse(
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

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                email_verified,

                account_status,

                is_active,

                is_suspended,

                is_deleted

            FROM users

            WHERE id = :id

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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT CURRENT USER QUERY] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to verify your account.',
        [
            'code' =>
                'CURRENT_USER_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$currentUser
) {

    connectResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'CURRENT_USER_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   CURRENT ACCOUNT CHECK
============================================================ */

if (
    !(bool)
    $currentUser['email_verified']
) {

    connectResponse(
        false,
        'Please verify your email before creating a connection.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED'
        ],
        403
    );

}


if (
    !(bool)
    $currentUser['is_active']
    ||
    (bool)
    $currentUser['is_suspended']
    ||
    (bool)
    $currentUser['is_deleted']
    ||
    in_array(
        strtolower(
            (string)
            $currentUser['account_status']
        ),
        [
            'suspended',
            'blocked',
            'disabled',
            'deleted'
        ],
        true
    )
) {

    connectResponse(
        false,
        'Your account is currently unavailable.',
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

try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT

                s.id,

                s.start_at,

                s.end_at,

                s.status

            FROM subscriptions s

            INNER JOIN services sv
                ON sv.id = s.service_id

            WHERE

                s.user_id = :user_id

                AND sv.slug = 'lovemi-premium'

                AND sv.is_premium = TRUE

                AND sv.is_active = TRUE

                AND s.status = 'active'

                AND s.start_at IS NOT NULL

                AND s.start_at <= CURRENT_TIMESTAMP

                AND s.end_at IS NOT NULL

                AND s.end_at > CURRENT_TIMESTAMP

            ORDER BY
                s.end_at DESC,
                s.id DESC

            LIMIT 1
            "
        );


    $premiumStmt->execute(
        [
            ':user_id' =>
                $currentUserId
        ]
    );


    $premium =
        $premiumStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT PREMIUM QUERY] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to verify Premium access.',
        [
            'code' =>
                'PREMIUM_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$premium
) {

    connectResponse(
        false,
        'Premium access is required to send a connection request.',
        [
            'code' =>
                'PREMIUM_REQUIRED',

            'allowed' =>
                false,

            'premium_active' =>
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

try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                username,

                full_names,

                gender,

                email_verified,

                account_status,

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


    $target =
        $targetStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT TARGET QUERY] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to verify the selected member.',
        [
            'code' =>
                'TARGET_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$target
) {

    connectResponse(
        false,
        'The selected member could not be found.',
        [
            'code' =>
                'TARGET_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   TARGET ACCOUNT CHECK
============================================================ */

if (
    !(bool)
    $target['email_verified']
    ||
    !(bool)
    $target['is_active']
    ||
    (bool)
    $target['is_suspended']
    ||
    (bool)
    $target['is_deleted']
    ||
    in_array(
        strtolower(
            (string)
            $target['account_status']
        ),
        [
            'suspended',
            'blocked',
            'disabled',
            'deleted'
        ],
        true
    )
) {

    connectResponse(
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

try {

    $blockStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM blocked_users

            WHERE

                (
                    user_id = :current_a
                    AND
                    blocked_user_id = :target_a
                )

                OR

                (
                    user_id = :target_b
                    AND
                    blocked_user_id = :current_b
                )

            LIMIT 1
            "
        );


    $blockStmt->execute(
        [
            ':current_a' =>
                $currentUserId,

            ':target_a' =>
                $targetUserId,

            ':target_b' =>
                $targetUserId,

            ':current_b' =>
                $currentUserId
        ]
    );


    $blocked =
        $blockStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT BLOCK QUERY] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to verify whether this connection is allowed.',
        [
            'code' =>
                'BLOCK_QUERY_ERROR'
        ],
        500
    );

}


if (
    $blocked
) {

    connectResponse(
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
   EXISTING CONNECTION
============================================================ */

try {

    $existingStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                connected_user_id,

                initiated_by,

                status,

                connected_at,

                created_at,

                updated_at

            FROM connections

            WHERE

                (
                    user_id = :user_a
                    AND
                    connected_user_id = :user_b
                )

                OR

                (
                    user_id = :user_c
                    AND
                    connected_user_id = :user_d
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

            ':user_c' =>
                $targetUserId,

            ':user_d' =>
                $currentUserId
        ]
    );


    $existing =
        $existingStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CONNECT EXISTING QUERY] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to check the existing connection.',
        [
            'code' =>
                'EXISTING_CONNECTION_QUERY_ERROR'
        ],
        500
    );

}


/* ============================================================
   EXISTING CONNECTION HANDLING
============================================================ */

if (
    $existing
) {

    $existingStatus =
        strtolower(
            (string)
            $existing['status']
        );


    if (
        in_array(
            $existingStatus,
            [
                'accepted',
                'connected'
            ],
            true
        )
    ) {

        connectResponse(
            true,
            'You are already connected with this member.',
            [
                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    $existingStatus,

                'already_connected' =>
                    true,

                'connected' =>
                    true,

                'target_user_id' =>
                    $targetUserId
            ]
        );

    }


    /*
     * An existing pending request from the current user.
     */

    if (
        $existingStatus ===
        'pending'
        &&
        (int)
        $existing['initiated_by']
        ===
        $currentUserId
    ) {

        connectResponse(
            true,
            'Your connection request is already pending.',
            [
                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'pending',

                'already_pending' =>
                    true,

                'target_user_id' =>
                    $targetUserId
            ]
        );

    }


    /*
     * If the other member already sent a pending request,
     * tell the current member to respond to it instead of
     * creating a duplicate pair.
     */

    if (
        $existingStatus ===
        'pending'
        &&
        (int)
        $existing['initiated_by']
        !==
        $currentUserId
    ) {

        connectResponse(
            false,
            'This member has already sent you a connection request. Please review it from your Connections page.',
            [
                'code' =>
                    'REQUEST_ALREADY_RECEIVED',

                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'pending'
            ],
            409
        );

    }


    /*
     * If a previous request was rejected/cancelled, reuse
     * the existing unique pair record by changing it to pending.
     */

    if (
        in_array(
            $existingStatus,
            [
                'rejected',
                'cancelled'
            ],
            true
        )
    ) {

        try {

            $update =
                $pdo->prepare(
                    "
                    UPDATE connections

                    SET

                        user_id =
                            :user_id,

                        connected_user_id =
                            :connected_user_id,

                        initiated_by =
                            :initiated_by,

                        status =
                            'pending',

                        connected_at =
                            NULL,

                        updated_at =
                            CURRENT_TIMESTAMP

                    WHERE id =
                        :id

                    LIMIT 1
                    "
                );


            $update->execute(
                [
                    ':user_id' =>
                        $currentUserId,

                    ':connected_user_id' =>
                        $targetUserId,

                    ':initiated_by' =>
                        $currentUserId,

                    ':id' =>
                        (int)
                        $existing['id']
                ]
            );


            if (
                $update->rowCount()
                <
                1
            ) {

                throw new RuntimeException(
                    'Existing connection could not be updated.'
                );

            }


            connectResponse(
                true,
                'Connection request sent successfully.',
                [
                    'connection_id' =>
                        (int)
                        $existing['id'],

                    'status' =>
                        'pending',

                    'request_sent' =>
                        true,

                    'target_user_id' =>
                        $targetUserId
                ],
                200
            );

        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI CONNECT REUSE REQUEST] '
                .
                $e->getMessage()
            );


            connectResponse(
                false,
                'Unable to send the connection request.',
                [
                    'code' =>
                        'REQUEST_UPDATE_ERROR'
                ],
                500
            );

        }

    }

}


/* ============================================================
   CREATE NEW CONNECTION
============================================================ */

try {

    $pdo->beginTransaction();


    $insert =
        $pdo->prepare(
            "
            INSERT INTO connections
            (
                user_id,
                connected_user_id,
                initiated_by,
                status,
                connected_at,
                created_at,
                updated_at
            )
            VALUES
            (
                :user_id,
                :connected_user_id,
                :initiated_by,
                'pending',
                NULL,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insert->execute(
        [
            ':user_id' =>
                $currentUserId,

            ':connected_user_id' =>
                $targetUserId,

            ':initiated_by' =>
                $currentUserId
        ]
    );


    $connectionId =
        (int)
        $pdo->lastInsertId();


    /*
     * Notify the receiving member.
     *
     * We use the existing notification_types table when
     * a matching type exists.
     *
     * If no matching type exists, the request still succeeds.
     */

    try {

        $notificationTypeStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM notification_types

                WHERE slug IN
                (
                    'connection_request',
                    'new_connection_request',
                    'connection'
                )

                ORDER BY
                    CASE slug
                        WHEN 'connection_request'
                            THEN 1

                        WHEN 'new_connection_request'
                            THEN 2

                        WHEN 'connection'
                            THEN 3

                        ELSE 4
                    END

                LIMIT 1
                "
            );


        $notificationTypeStmt->execute();


        $notificationTypeId =
            $notificationTypeStmt->fetchColumn();


        if (
            $notificationTypeId !== false
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
                        is_read,
                        created_at
                    )
                    VALUES
                    (
                        :user_id,
                        :notification_type_id,
                        :sender_id,
                        :title,
                        :message,
                        FALSE,
                        CURRENT_TIMESTAMP
                    )
                    "
                );


            $notificationStmt->execute(
                [
                    ':user_id' =>
                        $targetUserId,

                    ':notification_type_id' =>
                        (int)
                        $notificationTypeId,

                    ':sender_id' =>
                        $currentUserId,

                    ':title' =>
                        'New Connection Request',

                    ':message' =>
                        'You have received a new connection request on LOVEMI.'
                ]
            );

        }

    } catch (
        Throwable $notificationError
    ) {

        /*
         * Notification failure must never cancel an otherwise
         * valid connection request.
         */

        error_log(
            '[LOVEMI CONNECT NOTIFICATION] '
            .
            $notificationError->getMessage()
        );

    }


    $pdo->commit();

} catch (
    PDOException $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CONNECT PDO] '
        .
        $e->getMessage()
    );


    /*
     * Unique connection pair.
     *
     * Another request may have been created between our
     * existence check and INSERT.
     */

    if (
        (int)
        $e->errorInfo[1] ===
        1062
    ) {

        connectResponse(
            false,
            'A connection request for this member already exists.',
            [
                'code' =>
                    'CONNECTION_ALREADY_EXISTS'
            ],
            409
        );

    }


    connectResponse(
        false,
        'Unable to send the connection request.',
        [
            'code' =>
                'CONNECTION_INSERT_ERROR'
        ],
        500
    );

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI CONNECT INSERT] '
        .
        $e->getMessage()
    );


    connectResponse(
        false,
        'Unable to send the connection request.',
        [
            'code' =>
                'CONNECTION_INSERT_ERROR'
        ],
        500
    );

}


/* ============================================================
   SUCCESS
============================================================ */

connectResponse(
    true,
    'Connection request sent successfully.',
    [
        'connection_id' =>
            $connectionId,

        'status' =>
            'pending',

        'request_sent' =>
            true,

        'connected' =>
            false,

        'target_user_id' =>
            $targetUserId
    ],
    201
);