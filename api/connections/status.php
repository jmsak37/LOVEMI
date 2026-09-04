<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function connectionStatusResponse(
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
    !== 'GET'
) {

    connectionStatusResponse(
        false,
        'Only GET requests are allowed.',
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
    !== PHP_SESSION_ACTIVE
) {

    session_start();

}


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

    connectionStatusResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=discover.html'
        ],
        401
    );
}


/* ============================================================
   TARGET
============================================================ */

$targetUserId =
    isset(
        $_GET['user_id']
    )
        ? (int)
          $_GET['user_id']
        : 0;


if (
    $targetUserId <= 0
) {

    connectionStatusResponse(
        false,
        'The selected member is invalid.',
        [
            'code' =>
                'INVALID_TARGET'
        ],
        422
    );
}


if (
    $targetUserId ===
    $currentUserId
) {

    connectionStatusResponse(
        false,
        'You cannot chat with your own account.',
        [
            'code' =>
                'SELF_TARGET'
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
        '[LOVEMI CONNECTION STATUS DB] '
        .
        $e->getMessage()
    );

    connectionStatusResponse(
        false,
        'Unable to connect to the database.',
        [],
        500
    );
}


/* ============================================================
   TARGET USER
============================================================ */

$userStmt =
    $pdo->prepare(
        "

        SELECT

            id,
            username,
            full_names,
            gender,
            account_status,
            email_verified,
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
            $targetUserId
    ]
);


$targetUser =
    $userStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !$targetUser
) {

    connectionStatusResponse(
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

    connectionStatusResponse(
        false,
        'Messaging with this member is unavailable.',
        [
            'code' =>
                'BLOCKED'
        ],
        403
    );
}


/* ============================================================
   CONNECTION
============================================================ */

$connectionStmt =
    $pdo->prepare(
        "

        SELECT

            c.id AS connection_id,

            c.user_id,

            c.connected_user_id,

            c.initiated_by,

            c.status,

            c.connected_at,

            c.created_at,

            c.updated_at

        FROM connections c

        WHERE

            (
                c.user_id = :user_a
                AND
                c.connected_user_id = :user_b
            )

            OR

            (
                c.user_id = :user_b2
                AND
                c.connected_user_id = :user_a2
            )

        ORDER BY

            c.id DESC

        LIMIT 1

        "
    );


$connectionStmt->execute(
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


$connection =
    $connectionStmt->fetch(
        PDO::FETCH_ASSOC
    );


/* ============================================================
   NO CONNECTION
============================================================ */

if (
    !$connection
) {

    connectionStatusResponse(
        true,
        'No connection exists.',
        [

            'status' =>
                'none',

            'connection' =>
                null,

            'conversation_id' =>
                null,

            'target_user' =>
                [

                    'id' =>
                        (int)
                        $targetUser['id'],

                    'username' =>
                        (string)
                        $targetUser['username'],

                    'full_name' =>
                        (string)
                        $targetUser['full_names'],

                    'gender' =>
                        (string)
                        $targetUser['gender']

                ]

        ]
    );
}


/* ============================================================
   STATUS
============================================================ */

$status =
    strtolower(
        trim(
            (string)
            $connection['status']
        )
    );


$normalizedStatus =
    match ($status) {

        'accepted',
        'connected'
            => 'accepted',

        'pending'
            =>
            (
                (int)
                $connection['initiated_by']
                ===
                $currentUserId
            )
                ?
                'pending_sent'
                :
                'pending_received',

        'rejected'
            => 'rejected',

        'cancelled'
            => 'cancelled',

        default
            => $status

    };


/* ============================================================
   CONVERSATION
============================================================ */

$conversationId =
    null;


if (
    $normalizedStatus ===
    'accepted'
) {

    $conversationStmt =
        $pdo->prepare(
            "

            SELECT

                id,
                connection_id,
                user_one_id,
                user_two_id,
                status,
                created_at,
                updated_at

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

}


/* ============================================================
   RESPONSE
============================================================ */

connectionStatusResponse(
    true,
    'Connection status loaded.',
    [

        'status' =>
            $normalizedStatus,

        'connection' =>
            [

                'id' =>
                    (int)
                    $connection['connection_id'],

                'connection_id' =>
                    (int)
                    $connection['connection_id'],

                'user_id' =>
                    (int)
                    $connection['user_id'],

                'connected_user_id' =>
                    (int)
                    $connection['connected_user_id'],

                'initiated_by' =>
                    (int)
                    $connection['initiated_by'],

                'status' =>
                    $normalizedStatus,

                'connected_at' =>
                    $connection['connected_at'] !== null
                        ?
                        (string)
                        $connection['connected_at']
                        :
                        null,

                'created_at' =>
                    (string)
                    $connection['created_at'],

                'updated_at' =>
                    (string)
                    $connection['updated_at'],

                'conversation_id' =>
                    $conversationId

            ],

        'conversation_id' =>
            $conversationId,

        'target_user' =>
            [

                'id' =>
                    (int)
                    $targetUser['id'],

                'username' =>
                    (string)
                    $targetUser['username'],

                'full_name' =>
                    (string)
                    $targetUser['full_names'],

                'gender' =>
                    (string)
                    $targetUser['gender']

            ]

    ]
);