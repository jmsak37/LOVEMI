<?php
/**
 * ============================================================
 * LOVEMI - CREATE / OPEN CONVERSATION API
 * ============================================================
 *
 * POST JSON:
 *
 * {
 *   "user_id": 4
 * }
 *
 * Behavior:
 *
 * 1. Authenticated user is required.
 * 2. Normal member must have active Premium.
 * 3. Administrator/moderator/support can use chat without
 *    Premium.
 * 4. User cannot connect with himself.
 * 5. Blocked pairs cannot chat.
 * 6. A direct connection is created as "connected".
 * 7. Conversation is created/reused.
 * 8. Conversation ID is returned.
 *
 * ============================================================
 */

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

function chatCreateResponse(
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

    chatCreateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

/* ============================================================
   AUTH
============================================================ */

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {

    chatCreateResponse(
        false,
        'Please log in to connect with another member.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}

/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents('php://input');

$input =
    json_decode(
        (string) $raw,
        true
    );

if (!is_array($input)) {
    $input = $_POST;
}

$targetUserId =
    (int)
    (
        $input['user_id']
        ??
        $input['connected_user_id']
        ??
        0
    );

if ($targetUserId <= 0) {

    chatCreateResponse(
        false,
        'The user you want to connect with is required.',
        [
            'code' => 'TARGET_USER_REQUIRED'
        ],
        422
    );
}

if ($targetUserId === $currentUserId) {

    chatCreateResponse(
        false,
        'You cannot connect with your own account.',
        [
            'code' => 'SELF_CONNECTION_NOT_ALLOWED'
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
        '[LOVEMI CREATE CONVERSATION DB] ' .
        $e->getMessage()
    );

    chatCreateResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}

/* ============================================================
   CURRENT USER ROLE / ACCOUNT
============================================================ */

try {

    $meStmt =
        $pdo->prepare(
            "
            SELECT
                u.id,
                u.role_id,
                u.account_status,
                u.is_active,
                u.is_suspended,
                u.is_deleted,
                r.slug AS role_slug

            FROM users u

            LEFT JOIN roles r
                ON r.id = u.role_id

            WHERE u.id = :id

            LIMIT 1
            "
        );

    $meStmt->execute(
        [
            ':id' => $currentUserId
        ]
    );

    $me =
        $meStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE CONVERSATION CURRENT USER] ' .
        $e->getMessage()
    );

    chatCreateResponse(
        false,
        'Unable to verify your account.',
        [
            'code' => 'CURRENT_USER_LOOKUP_FAILED'
        ],
        500
    );
}

if (!$me) {

    chatCreateResponse(
        false,
        'Your account could not be found.',
        [
            'code' => 'CURRENT_USER_NOT_FOUND'
        ],
        404
    );
}

if (
    (int) $me['is_deleted'] === 1
    ||
    (int) $me['is_suspended'] === 1
    ||
    (int) $me['is_active'] !== 1
) {

    chatCreateResponse(
        false,
        'Your account cannot currently use messaging.',
        [
            'code' => 'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}

$roleSlug =
    strtolower(
        (string)
        (
            $me['role_slug']
            ??
            ''
        )
    );

$isStaff =
    in_array(
        $roleSlug,
        [
            'admin',
            'moderator',
            'support'
        ],
        true
    );

/* ============================================================
   PREMIUM CHECK
============================================================ */

if (!$isStaff) {

    try {

        $premiumStmt =
            $pdo->prepare(
                "
                SELECT
                    s.id

                FROM subscriptions s

                INNER JOIN services sv
                    ON sv.id = s.service_id

                WHERE s.user_id = :user_id

                  AND s.status = 'active'

                  AND s.start_at <= CURRENT_TIMESTAMP

                  AND s.end_at > CURRENT_TIMESTAMP

                  AND sv.is_active = 1

                  AND sv.is_premium = 1

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

        $premiumId =
            $premiumStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CREATE CONVERSATION PREMIUM] ' .
            $e->getMessage()
        );

        chatCreateResponse(
            false,
            'Unable to verify Premium access.',
            [
                'code' =>
                    'PREMIUM_LOOKUP_FAILED'
            ],
            500
        );
    }

    if (!$premiumId) {

        chatCreateResponse(
            false,
            'Premium access is required to connect and start a conversation.',
            [
                'code' => 'PREMIUM_REQUIRED',
                'redirect' => 'premium.html'
            ],
            403
        );
    }
}

/* ============================================================
   TARGET USER
============================================================ */

try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.gender,
                u.account_status,
                u.is_active,
                u.is_suspended,
                u.is_deleted,

                p.allow_messages,
                p.profile_visibility

            FROM users u

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE u.id = :id

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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE CONVERSATION TARGET] ' .
        $e->getMessage()
    );

    chatCreateResponse(
        false,
        'Unable to load the selected profile.',
        [],
        500
    );
}

if (!$target) {

    chatCreateResponse(
        false,
        'The selected member does not exist.',
        [
            'code' => 'TARGET_USER_NOT_FOUND'
        ],
        404
    );
}

if (
    (int) $target['is_deleted'] === 1
    ||
    (int) $target['is_suspended'] === 1
    ||
    (int) $target['is_active'] !== 1
) {

    chatCreateResponse(
        false,
        'This member is currently unavailable.',
        [
            'code' => 'TARGET_USER_UNAVAILABLE'
        ],
        404
    );
}

/*
 * A public connection is not exposed to a private profile.
 * Staff are allowed to initiate conversations for support.
 */

if (
    !$isStaff
    &&
    strtolower(
        (string)
        (
            $target['profile_visibility']
            ??
            'public'
        )
    )
    !== 'public'
) {

    chatCreateResponse(
        false,
        'This profile is private.',
        [
            'code' => 'PROFILE_PRIVATE'
        ],
        403
    );
}

if (
    isset($target['allow_messages'])
    &&
    (int) $target['allow_messages'] !== 1
) {

    chatCreateResponse(
        false,
        'This member is not accepting messages.',
        [
            'code' => 'MESSAGES_DISABLED'
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
                    user_id = :user_one
                    AND
                    blocked_user_id = :user_two
                )

                OR

                (
                    user_id = :user_three
                    AND
                    blocked_user_id = :user_four
                )

            LIMIT 1
            "
        );

    $blockStmt->execute(
        [

            ':user_one' =>
                $currentUserId,

            ':user_two' =>
                $targetUserId,

            ':user_three' =>
                $targetUserId,

            ':user_four' =>
                $currentUserId

        ]
    );

    $blocked =
        $blockStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE CONVERSATION BLOCK] ' .
        $e->getMessage()
    );

    chatCreateResponse(
        false,
        'Unable to verify connection safety.',
        [],
        500
    );
}

if ($blocked) {

    chatCreateResponse(
        false,
        'Messaging is unavailable because one of these accounts has blocked the other.',
        [
            'code' => 'USER_BLOCKED'
        ],
        403
    );
}

/* ============================================================
   CREATE / RESTORE CONNECTION + CONVERSATION
============================================================ */

try {

    $pdo->beginTransaction();

    /*
     * Check whether a connection already exists.
     */

    $connectionStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                status

            FROM connections

            WHERE user_low_id = LEAST(
                :current_user_1,
                :target_user_1
            )

              AND user_high_id = GREATEST(
                :current_user_2,
                :target_user_2
              )

            LIMIT 1
            "
        );

    $connectionStmt->execute(
        [

            ':current_user_1' =>
                $currentUserId,

            ':target_user_1' =>
                $targetUserId,

            ':current_user_2' =>
                $currentUserId,

            ':target_user_2' =>
                $targetUserId

        ]
    );

    $connection =
        $connectionStmt->fetch();


    $connectionWasCreated =
        false;

    $connectionId =
        0;


    if (!$connection) {

        /*
         * "connected" is intentional.
         * Clicking the profile while authorized means an
         * immediate connection under the LOVEMI requirement.
         */

        $insertConnection =
            $pdo->prepare(
                "
                INSERT INTO connections
                (
                    user_id,
                    connected_user_id,
                    initiated_by,
                    status,
                    connected_at
                )
                VALUES
                (
                    :user_id,
                    :connected_user_id,
                    :initiated_by,
                    'connected',
                    CURRENT_TIMESTAMP
                )
                "
            );

        $insertConnection->execute(
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

        $connectionWasCreated =
            true;

    } else {

        $connectionId =
            (int)
            $connection['id'];

        /*
         * Restore an older/pending/rejected connection into an
         * active connection when the authorized user connects.
         */

        if (
            !in_array(
                strtolower(
                    (string)
                    $connection['status']
                ),
                [
                    'connected',
                    'accepted'
                ],
                true
            )
        ) {

            $updateConnection =
                $pdo->prepare(
                    "
                    UPDATE connections

                    SET

                        initiated_by =
                            :initiated_by,

                        status =
                            'connected',

                        connected_at =
                            CURRENT_TIMESTAMP

                    WHERE id = :id

                    LIMIT 1
                    "
                );

            $updateConnection->execute(
                [

                    ':initiated_by' =>
                        $currentUserId,

                    ':id' =>
                        $connectionId

                ]
            );

        }
    }

    /*
     * Find conversation.
     */

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                status

            FROM conversations

            WHERE user_low_id = LEAST(
                    :user_one_1,
                    :user_two_1
                )

              AND user_high_id = GREATEST(
                    :user_one_2,
                    :user_two_2
                )

            LIMIT 1
            "
        );

    $conversationStmt->execute(
        [

            ':user_one_1' =>
                $currentUserId,

            ':user_two_1' =>
                $targetUserId,

            ':user_one_2' =>
                $currentUserId,

            ':user_two_2' =>
                $targetUserId

        ]
    );

    $conversation =
        $conversationStmt->fetch();


    if (!$conversation) {

        $insertConversation =
            $pdo->prepare(
                "
                INSERT INTO conversations
                (
                    connection_id,
                    user_one_id,
                    user_two_id,
                    status
                )
                VALUES
                (
                    :connection_id,
                    :user_one_id,
                    :user_two_id,
                    'active'
                )
                "
            );

        $insertConversation->execute(
            [

                ':connection_id' =>
                    $connectionId,

                ':user_one_id' =>
                    $currentUserId,

                ':user_two_id' =>
                    $targetUserId

            ]
        );

        $conversationId =
            (int)
            $pdo->lastInsertId();

    } else {

        $conversationId =
            (int)
            $conversation['id'];


        if (
            strtolower(
                (string)
                $conversation['status']
            )
            !==
            'active'
        ) {

            $restoreConversation =
                $pdo->prepare(
                    "
                    UPDATE conversations

                    SET
                        status = 'active'

                    WHERE id = :id

                    LIMIT 1
                    "
                );

            $restoreConversation->execute(
                [
                    ':id' =>
                        $conversationId
                ]
            );
        }

    }


    /*
     * If the connection already existed and was changed to
     * connected, manually create the connection notifications.
     * New inserts already trigger them through the saved DB
     * trigger, so only do this for the existing connection case.
     */

    if (
        !$connectionWasCreated
        &&
        $connection
    ) {

        $oldStatus =
            strtolower(
                (string)
                $connection['status']
            );


        if (
            !in_array(
                $oldStatus,
                [
                    'connected',
                    'accepted'
                ],
                true
            )
        ) {

            $notificationTypeStmt =
                $pdo->prepare(
                    "
                    SELECT
                        id

                    FROM notification_types

                    WHERE slug =
                        'new_connection'

                    LIMIT 1
                    "
                );

            $notificationTypeStmt->execute();

            $notificationTypeId =
                $notificationTypeStmt->fetchColumn();


            if (
                $notificationTypeId
            ) {

                $audioStmt =
                    $pdo->prepare(
                        "
                        SELECT
                            id

                        FROM notification_audio

                        WHERE notification_type_id =
                            :type_id

                          AND is_active = 1

                        ORDER BY
                            sort_order ASC,
                            id ASC

                        LIMIT 1
                        "
                    );

                $audioStmt->execute(
                    [
                        ':type_id' =>
                            (int)
                            $notificationTypeId
                    ]
                );

                $audioId =
                    $audioStmt->fetchColumn();


                $notifyStmt =
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
                            audio_id
                        )
                        VALUES
                        (
                            :user_id,
                            :type_id,
                            :sender_id,
                            'New Connection',
                            'You are now connected with another LOVEMI member.',
                            'connection',
                            :connection_id,
                            :audio_id
                        )
                        "
                    );


                foreach (
                    [
                        [
                            $currentUserId,
                            $targetUserId
                        ],
                        [
                            $targetUserId,
                            $currentUserId
                        ]
                    ]
                    as $notify
                ) {

                    $notifyStmt->execute(
                        [

                            ':user_id' =>
                                $notify[0],

                            ':type_id' =>
                                (int)
                                $notificationTypeId,

                            ':sender_id' =>
                                $notify[1],

                            ':connection_id' =>
                                $connectionId,

                            ':audio_id' =>
                                $audioId
                                ?
                                (int)
                                $audioId
                                :
                                null

                        ]
                    );
                }
            }
        }
    }


    $pdo->commit();

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {
        $pdo->rollBack();
    }

    error_log(
        '[LOVEMI CREATE CONVERSATION TRANSACTION] ' .
        $e->getMessage()
    );

    chatCreateResponse(
        false,
        'Unable to create the conversation.',
        [
            'code' =>
                'CONVERSATION_CREATE_FAILED'
        ],
        500
    );
}

/* ============================================================
   RESPONSE
============================================================ */

chatCreateResponse(
    true,
    'Connection and conversation are ready.',
    [

        'connection_id' =>
            $connectionId,

        'conversation_id' =>
            $conversationId,

        'connected_user' => [

            'id' =>
                (int)
                $target['id'],

            'username' =>
                $target['username'],

            'full_names' =>
                $target['full_names'],

            'gender' =>
                $target['gender']

        ],

        'redirect' =>
            'messages.html?conversation_id='
            .
            $conversationId

    ]
);