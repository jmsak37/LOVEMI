<?php

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
    session_status()
    !== PHP_SESSION_ACTIVE
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
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
   REQUEST BODY
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    )
    ?: '';


$data =
    json_decode(
        $rawBody,
        true
    );


if (
    !is_array($data)
) {

    $data = [];

}


/* ============================================================
   TARGET
============================================================ */

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
   SELF
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
        .
        $e->getMessage()
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

$currentUserStmt =
    $pdo->prepare(
        "

        SELECT

            id,

            email_verified,

            is_active,

            is_suspended,

            is_deleted,

            account_status,

            EXISTS
            (
                SELECT 1

                FROM subscriptions s

                INNER JOIN services sv
                    ON sv.id = s.service_id

                WHERE

                    s.user_id = users.id

                    AND

                    sv.slug = 'lovemi-premium'

                    AND

                    sv.is_active = 1

                    AND

                    s.status = 'active'

                    AND

                    (
                        s.start_at IS NULL
                        OR
                        s.start_at <= CURRENT_TIMESTAMP
                    )

                    AND

                    (
                        s.end_at IS NULL
                        OR
                        s.end_at > CURRENT_TIMESTAMP
                    )

                LIMIT 1
            ) AS has_premium

        FROM users

        WHERE id = :id

        LIMIT 1

        "
    );


$currentUserStmt->execute(
    [
        ':id' =>
            $currentUserId
    ]
);


$currentUser =
    $currentUserStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !$currentUser
) {

    connectionResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   ACCOUNT CHECK
============================================================ */

if (
    (int)$currentUser['email_verified']
    !==
    1
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
    (int)$currentUser['is_active']
    !==
    1

    ||

    (int)$currentUser['is_suspended']
    ===
    1

    ||

    (int)$currentUser['is_deleted']
    ===
    1

    ||

    strtolower(
        (string)
        $currentUser['account_status']
    )
    !==
    'approved'
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
    (int)$currentUser['has_premium']
    !==
    1
) {

    connectionResponse(
        false,
        'Premium access is required to create a new connection.',
        [
            'code' =>
                'PREMIUM_REQUIRED',

            'allowed' =>
                false,

            'redirect' =>
                'premium.html?return=discover.html'
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

            username,

            full_names,

            gender,

            email_verified,

            is_active,

            is_suspended,

            is_deleted,

            account_status

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
    $targetStmt->fetch(
        PDO::FETCH_ASSOC
    );


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


/* ============================================================
   TARGET AVAILABILITY
============================================================ */

if (
    (int)$targetUser['email_verified']
    !==
    1
    ||
    (int)$targetUser['is_active']
    !==
    1
    ||
    (int)$targetUser['is_suspended']
    ===
    1
    ||
    (int)$targetUser['is_deleted']
    ===
    1
    ||
    strtolower(
        (string)
        $targetUser['account_status']
    )
    !==
    'approved'
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

        FROM blocked_users

        WHERE

            (
                user_id = :user_a

                AND

                blocked_user_id = :user_b
            )

            OR

            (
                user_id = :user_b2

                AND

                blocked_user_id = :user_a2
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
   EXISTING CONNECTION
============================================================ */

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
                user_id = :user_b2

                AND

                connected_user_id = :user_a2
            )

        ORDER BY

            id DESC

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
    $existingStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    $existing
) {

    $existingStatus =
        strtolower(
            trim(
                (string)
                $existing['status']
            )
        );


    /* --------------------------------------------------------
       ALREADY CONNECTED
    -------------------------------------------------------- */

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

        $conversationId =
            null;


        $conversationStmt =
            $pdo->prepare(
                "

                SELECT

                    id

                FROM conversations

                WHERE

                    (
                        user_one_id = :user_one_a

                        AND

                        user_two_id = :user_two_a
                    )

                    OR

                    (
                        user_one_id = :user_one_b

                        AND

                        user_two_id = :user_two_b
                    )

                ORDER BY

                    id DESC

                LIMIT 1

                "
            );


        $conversationStmt->execute(
            [

                ':user_one_a' =>
                    $currentUserId,

                ':user_two_a' =>
                    $targetUserId,

                ':user_one_b' =>
                    $targetUserId,

                ':user_two_b' =>
                    $currentUserId

            ]
        );


        $conversation =
            $conversationStmt->fetch(
                PDO::FETCH_ASSOC
            );


        if (
            $conversation
        ) {

            $conversationId =
                (int)
                $conversation['id'];

        }


        connectionResponse(
            true,
            'You are already connected with this member.',
            [

                'code' =>
                    'ALREADY_CONNECTED',

                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'accepted',

                'connected' =>
                    true,

                'conversation_id' =>
                    $conversationId

            ]
        );
    }


    /* --------------------------------------------------------
       PENDING SENT
    -------------------------------------------------------- */

    if (
        $existingStatus ===
        'pending'
    ) {

        if (
            (int)
            $existing['initiated_by']
            ===
            $currentUserId
        ) {

            connectionResponse(
                true,
                'Your connection request is already waiting for acceptance.',
                [

                    'code' =>
                        'ALREADY_PENDING',

                    'connection_id' =>
                        (int)
                        $existing['id'],

                    'status' =>
                        'pending_sent',

                    'connected' =>
                        false

                ]
            );
        }


        /*
         * The other member already sent the request.
         * Do not silently accept it.
         *
         * They must accept it themselves.
         */

        connectionResponse(
            false,
            'This member has already sent you a connection request. Please check your Connections page.',
            [

                'code' =>
                    'PENDING_RECEIVED',

                'connection_id' =>
                    (int)
                    $existing['id'],

                'status' =>
                    'pending_received'

            ],
            409
        );
    }


    /* --------------------------------------------------------
       REJECTED / CANCELLED
       --------------------------------------------------------
       Remove the old record so the premium user can create
       a fresh request.
    -------------------------------------------------------- */

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

        $deleteOld =
            $pdo->prepare(
                "

                DELETE FROM connections

                WHERE id = :id

                LIMIT 1

                "
            );


        $deleteOld->execute(
            [
                ':id' =>
                    (int)
                    $existing['id']
            ]
        );

    }

}


/* ============================================================
   CREATE NEW PENDING REQUEST
============================================================ */

$connectionId =
    0;


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


    /* ========================================================
       NOTIFICATION
    ======================================================== */

    try {

        /*
         * Existing LOVEMI notification type:
         *
         * 1 = New Connection
         *
         * The notification schema uses notification_type_id,
         * sender_id, reference_type and reference_id.
         */

        $audioId =
            null;


        $audioStmt =
            $pdo->prepare(
                "

                SELECT id

                FROM notification_audio

                WHERE notification_type_id = 1

                  AND is_active = 1

                ORDER BY

                    sort_order ASC,

                    id ASC

                LIMIT 1

                "
            );


        $audioStmt->execute();


        $audioRow =
            $audioStmt->fetch(
                PDO::FETCH_ASSOC
            );


        if (
            $audioRow
        ) {

            $audioId =
                (int)
                $audioRow['id'];

        }


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

                    reference_id,

                    audio_id,

                    is_read,

                    created_at
                )

                VALUES
                (
                    :user_id,

                    1,

                    :sender_id,

                    :title,

                    :message,

                    'connection',

                    :reference_id,

                    :audio_id,

                    0,

                    CURRENT_TIMESTAMP
                )

                "
            );


        $notification->execute(
            [

                ':user_id' =>
                    $targetUserId,

                ':sender_id' =>
                    $currentUserId,

                ':title' =>
                    'New Connection Request',

                ':message' =>
                    'Someone sent you a connection request on LOVEMI.',

                ':reference_id' =>
                    $connectionId,

                ':audio_id' =>
                    $audioId

            ]
        );

    } catch (Throwable $notificationError) {

        /*
         * Connection creation must still succeed if
         * optional notification insertion fails.
         */

        error_log(
            '[LOVEMI CONNECTION NOTIFICATION] '
            .
            $notificationError->getMessage()
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
        .
        $e->getMessage()
    );


    connectionResponse(
        false,
        'Unable to create the connection request.',
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
    'Connection request sent successfully. Please be patient while the other member accepts it.',
    [

        'code' =>
            'CONNECTION_REQUEST_SENT',

        'connection_id' =>
            $connectionId,

        'status' =>
            'pending_sent',

        'connected' =>
            false,

        'target_user_id' =>
            $targetUserId,

        'conversation_id' =>
            null

    ],
    201
);