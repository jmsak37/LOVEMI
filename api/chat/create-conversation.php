<?php

declare(strict_types=1);

require_once __DIR__ . '/../profile/_helper.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   RESPONSE
============================================================ */

function chatResponse(
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

    chatResponse(
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
   AUTH
============================================================ */

try {

    $viewerId =
        requireAuthenticatedUser();

} catch (
    Throwable $e
) {

    chatResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    )
    ?: '';


$input =
    json_decode(
        $raw,
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


$targetId =
    (int)(
        $input['user_id']
        ??
        $input['target_user_id']
        ??
        0
    );


if (
    $targetId <= 0
    ||
    $targetId === $viewerId
) {

    chatResponse(
        false,
        'Invalid chat member.',
        [
            'code' =>
                'INVALID_TARGET'
        ],
        422
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        profileDb();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CREATE DB] '
        .
        $e->getMessage()
    );

    chatResponse(
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
   TARGET VALIDATION
============================================================ */

try {

    $targetStmt =
        $pdo->prepare(
            "
            SELECT

                id,

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


    $targetStmt->execute(
        [
            ':id' =>
                $targetId
        ]
    );


    $target =
        $targetStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT TARGET] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to verify the chat member.',
        [
            'code' =>
                'TARGET_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$target
    ||
    (int)(
        $target['is_active']
        ?? 0
    ) !== 1
    ||
    (int)(
        $target['is_suspended']
        ?? 0
    ) === 1
    ||
    (int)(
        $target['is_deleted']
        ?? 0
    ) === 1
) {

    chatResponse(
        false,
        'This member is no longer available.',
        [
            'code' =>
                'TARGET_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   CONNECTION
============================================================ */

try {

    $connection =
        profileGetConnection(
            $pdo,
            $viewerId,
            $targetId
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CONNECTION] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to verify the connection.',
        [
            'code' =>
                'CONNECTION_LOOKUP_FAILED'
        ],
        500
    );
}


$connectionStatus =
    strtolower(
        trim(
            (string)(
                $connection['status']
                ?? ''
            )
        )
    );


if (
    !in_array(
        $connectionStatus,
        [
            'accepted',
            'connected',
            'active'
        ],
        true
    )
) {

    chatResponse(
        false,
        'You must be connected with this member before starting chat.',
        [
            'code' =>
                'CONNECTION_REQUIRED',

            'connection_status' =>
                $connectionStatus !== ''
                    ? $connectionStatus
                    : null
        ],
        403
    );
}


$connectionId =
    (int)(
        $connection['id']
        ?? 0
    );


/* ============================================================
   PREMIUM
============================================================ */

/*
 * LOVEMI RULE:
 *
 * Viewer Premium OR Target Premium
 * = Chat is allowed.
 *
 * Only when BOTH are without active Premium
 * is chat blocked.
 */

try {

    $viewerPremium =
        profileHasPremium(
            $pdo,
            $viewerId
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT VIEWER PREMIUM] '
        .
        $e->getMessage()
    );

    $viewerPremium =
        false;
}


try {

    $targetPremium =
        profileHasPremium(
            $pdo,
            $targetId
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT TARGET PREMIUM] '
        .
        $e->getMessage()
    );

    $targetPremium =
        false;
}


$chatAllowed =
    $viewerPremium
    ||
    $targetPremium;


if (
    !$chatAllowed
) {

    chatResponse(
        false,
        'Messaging is paused because neither connected member currently has active LOVEMI Premium.',
        [
            'code' =>
                'PREMIUM_REQUIRED',

            'current_user_premium' =>
                false,

            'other_user_premium' =>
                false,

            'premium_access' =>
                [
                    'can_send' =>
                        false,

                    'current_user_premium' =>
                        false,

                    'other_user_premium' =>
                        false
                ]
        ],
        403
    );
}


/* ============================================================
   CONVERSATION ACCESS CODE TABLE
============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS conversation_access_codes
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            conversation_id BIGINT UNSIGNED NOT NULL,

            access_code CHAR(64) NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_used_at DATETIME NULL,

            PRIMARY KEY (id),

            UNIQUE KEY uq_conversation_access_code
                (access_code),

            UNIQUE KEY uq_conversation_access_conversation
                (conversation_id)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT ACCESS TABLE] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to prepare chat access.',
        [
            'code' =>
                'CHAT_ACCESS_TABLE_FAILED'
        ],
        500
    );
}


/* ============================================================
   FIND EXISTING CONVERSATION
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                connection_id,

                user_one_id,

                user_two_id,

                status

            FROM conversations

            WHERE

                user_low_id =
                    LEAST(
                        :viewer_a,
                        :target_a
                    )

              AND

                user_high_id =
                    GREATEST(
                        :viewer_b,
                        :target_b
                    )

            LIMIT 1
            "
        );


    $conversationStmt->execute(
        [
            ':viewer_a' =>
                $viewerId,

            ':target_a' =>
                $targetId,

            ':viewer_b' =>
                $viewerId,

            ':target_b' =>
                $targetId
        ]
    );


    $conversation =
        $conversationStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CONVERSATION LOOKUP] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to find the conversation.',
        [
            'code' =>
                'CONVERSATION_LOOKUP_FAILED'
        ],
        500
    );
}


/* ============================================================
   CREATE CONVERSATION WHEN MISSING
============================================================ */

$conversationId =
    0;


if (
    $conversation
) {

    $conversationId =
        (int)(
            $conversation['id']
            ?? 0
        );

} else {

    try {

        $pdo->beginTransaction();


        /*
         * Insert conversation.
         */
        $insert =
            $pdo->prepare(
                "
                INSERT INTO conversations
                (
                    connection_id,

                    user_one_id,

                    user_two_id,

                    status,

                    created_at,

                    updated_at

                )
                VALUES
                (
                    :connection_id,

                    :user_one_id,

                    :user_two_id,

                    'active',

                    CURRENT_TIMESTAMP,

                    CURRENT_TIMESTAMP
                )
                "
            );


        $insert->execute(
            [
                ':connection_id' =>
                    $connectionId > 0
                        ? $connectionId
                        : null,

                ':user_one_id' =>
                    $viewerId,

                ':user_two_id' =>
                    $targetId
            ]
        );


        $conversationId =
            (int)
            $pdo->lastInsertId();


        $pdo->commit();

    } catch (
        Throwable $e
    ) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        /*
         * Another request may have created the same
         * conversation at almost the same time.
         *
         * Try the pair again before failing.
         */
        try {

            $retry =
                $pdo->prepare(
                    "
                    SELECT

                        id,

                        connection_id,

                        user_one_id,

                        user_two_id,

                        status

                    FROM conversations

                    WHERE

                        user_low_id =
                            LEAST(
                                :viewer_a,
                                :target_a
                            )

                      AND

                        user_high_id =
                            GREATEST(
                                :viewer_b,
                                :target_b
                            )

                    LIMIT 1
                    "
                );


            $retry->execute(
                [
                    ':viewer_a' =>
                        $viewerId,

                    ':target_a' =>
                        $targetId,

                    ':viewer_b' =>
                        $viewerId,

                    ':target_b' =>
                        $targetId
                ]
            );


            $retryConversation =
                $retry->fetch(
                    PDO::FETCH_ASSOC
                );


            if (
                $retryConversation
            ) {

                $conversationId =
                    (int)(
                        $retryConversation['id']
                        ?? 0
                    );

            }

        } catch (
            Throwable $retryError
        ) {

            error_log(
                '[LOVEMI CHAT CONVERSATION RETRY] '
                .
                $retryError->getMessage()
            );
        }
    }
}


if (
    $conversationId <= 0
) {

    chatResponse(
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
   RESTORE ACTIVE STATUS
============================================================ */

try {

    $activateConversation =
        $pdo->prepare(
            "
            UPDATE conversations

            SET

                connection_id =
                    :connection_id,

                status =
                    'active',

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE id =
                :conversation_id

            LIMIT 1
            "
        );


    $activateConversation->execute(
        [
            ':connection_id' =>
                $connectionId > 0
                    ? $connectionId
                    : null,

            ':conversation_id' =>
                $conversationId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT ACTIVATE] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   GET EXISTING CHAT CODE
============================================================ */

try {

    $codeStmt =
        $pdo->prepare(
            "
            SELECT access_code

            FROM conversation_access_codes

            WHERE conversation_id =
                :conversation_id

            LIMIT 1
            "
        );


    $codeStmt->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );


    $accessCode =
        (string)(
            $codeStmt->fetchColumn()
            ?: ''
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CODE LOOKUP] '
        .
        $e->getMessage()
    );

    chatResponse(
        false,
        'Unable to load the chat access code.',
        [
            'code' =>
                'CHAT_CODE_LOOKUP_FAILED'
        ],
        500
    );
}


/* ============================================================
   CREATE CHAT CODE IF MISSING
============================================================ */

if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $accessCode
    )
) {

    $accessCode =
        '';


    for (
        $attempt = 0;
        $attempt < 10;
        $attempt++
    ) {

        $candidate =
            bin2hex(
                random_bytes(
                    32
                )
            );


        try {

            $insertCode =
                $pdo->prepare(
                    "
                    INSERT INTO conversation_access_codes
                    (
                        conversation_id,

                        access_code,

                        created_at

                    )
                    VALUES
                    (
                        :conversation_id,

                        :access_code,

                        CURRENT_TIMESTAMP
                    )
                    "
                );


            $insertCode->execute(
                [
                    ':conversation_id' =>
                        $conversationId,

                    ':access_code' =>
                        $candidate
                ]
            );


            $accessCode =
                $candidate;


            break;

        } catch (
            PDOException $e
        ) {

            /*
             * The conversation may have received
             * a code from another request.
             */
            try {

                $retryCodeStmt =
                    $pdo->prepare(
                        "
                        SELECT access_code

                        FROM conversation_access_codes

                        WHERE conversation_id =
                            :conversation_id

                        LIMIT 1
                        "
                    );


                $retryCodeStmt->execute(
                    [
                        ':conversation_id' =>
                            $conversationId
                    ]
                );


                $retryCode =
                    (string)(
                        $retryCodeStmt->fetchColumn()
                        ?: ''
                    );


                if (
                    preg_match(
                        '/^[a-f0-9]{64}$/',
                        $retryCode
                    )
                ) {

                    $accessCode =
                        $retryCode;

                    break;
                }

            } catch (
                Throwable $ignored
            ) {

                /*
                 * Continue to next attempt.
                 */
            }
        }
    }
}


if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $accessCode
    )
) {

    chatResponse(
        false,
        'Unable to create the secure chat code.',
        [
            'code' =>
                'CHAT_CODE_ERROR'
        ],
        500
    );
}


/* ============================================================
   TOUCH CODE
============================================================ */

try {

    $touch =
        $pdo->prepare(
            "
            UPDATE conversation_access_codes

            SET last_used_at =
                CURRENT_TIMESTAMP

            WHERE conversation_id =
                :conversation_id

            LIMIT 1
            "
        );


    $touch->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT CODE TOUCH] '
        .
        $e->getMessage()
    );
}


/* ============================================================
   UPDATE CONVERSATION ACTIVITY
============================================================ */

try {

    $touchConversation =
        $pdo->prepare(
            "
            UPDATE conversations

            SET

                updated_at =
                    CURRENT_TIMESTAMP,

                status =
                    'active'

            WHERE id =
                :conversation_id

            LIMIT 1
            "
        );


    $touchConversation->execute(
        [
            ':conversation_id' =>
                $conversationId
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CHAT ACTIVITY] '
        .
        $e->getMessage()
    );
}


/* ============================================================
   FINAL RESPONSE
============================================================ */

/*
 * messages.html uses:
 *
 *     messages.html?chat=<chat_code>
 *
 * and api/chat/messages.php validates that the chat code
 * contains exactly 64 lowercase hexadecimal characters.
 *
 * Therefore return the same code at the top level and inside
 * the conversation object for compatibility.
 */

chatResponse(
    true,
    'Conversation is ready.',
    [

        'chat_code' =>
            $accessCode,

        'access_code' =>
            $accessCode,

        'conversation_code' =>
            $accessCode,

        'conversation_id' =>
            $conversationId,

        'connection_id' =>
            $connectionId > 0
                ? $connectionId
                : null,

        'premium_access' =>
            [

                'can_send' =>
                    true,

                'current_user_premium' =>
                    $viewerPremium,

                'other_user_premium' =>
                    $targetPremium,

                'rule' =>
                    'Either connected member having active LOVEMI Premium is enough to keep messaging active.'

            ],

        'conversation' =>
            [

                'id' =>
                    $conversationId,

                'connection_id' =>
                    $connectionId > 0
                        ? $connectionId
                        : null,

                'status' =>
                    'active',

                'chat_code' =>
                    $accessCode,

                'access_code' =>
                    $accessCode

            ]

    ]
);