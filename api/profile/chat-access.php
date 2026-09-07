<?php

declare(strict_types=1);

require_once __DIR__ . '/_helper.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
) {

    profileJsonResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


$userId =
    profileRequireAuth();


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


$input =
    is_array($input)
        ? $input
        : $_POST;


$targetId =
    (int)(
        $input['user_id']
        ?? $input['target_user_id']
        ?? 0
    );


if (
    $targetId <= 0
    || $targetId === $userId
) {

    profileJsonResponse(
        false,
        'Invalid member.',
        [
            'code' =>
                'INVALID_TARGET'
        ],
        422
    );
}


try {

    $pdo =
        profileDb();


    /*
     * =========================================================
     * TARGET ACCOUNT
     * =========================================================
     */
    $userStmt =
        $pdo->prepare(
            '
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
            '
        );


    $userStmt->execute([
        ':id' =>
            $targetId
    ]);


    $target =
        $userStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$target
        || (int)$target[
            'is_active'
        ] !== 1
        || (int)$target[
            'is_suspended'
        ] === 1
        || (int)$target[
            'is_deleted'
        ] === 1
    ) {

        profileJsonResponse(
            false,
            'This member is unavailable.',
            [
                'code' =>
                    'TARGET_UNAVAILABLE'
            ],
            403
        );
    }


    /*
     * =========================================================
     * CONNECTION
     * =========================================================
     */
    $connection =
        profileGetConnection(
            $pdo,
            $userId,
            $targetId
        );


    if (
        !profileIsConnected(
            $connection
        )
    ) {

        profileJsonResponse(
            false,
            'You must be connected before chat can open.',
            [
                'code' =>
                    'CONNECTION_REQUIRED',

                'connection_status' =>
                    $connection[
                        'status'
                    ]
                    ?? null
            ],
            403
        );
    }


    /*
     * =========================================================
     * PREMIUM
     * =========================================================
     *
     * IMPORTANT:
     *
     * Viewer Premium OR target Premium = allowed.
     *
     * Both without Premium = blocked.
     */
    $viewerPremium =
        profileHasPremium(
            $pdo,
            $userId
        );


    $targetPremium =
        profileHasPremium(
            $pdo,
            $targetId
        );


    if (
        !$viewerPremium
        && !$targetPremium
    ) {

        profileJsonResponse(
            false,
            'At least one member of this connection must have active LOVEMI Premium to chat.',
            [
                'code' =>
                    'PREMIUM_REQUIRED',

                'viewer_has_premium' =>
                    false,

                'profile_has_premium' =>
                    false
            ],
            402
        );
    }


    /*
     * =========================================================
     * EXISTING CONVERSATION
     * =========================================================
     */
    $conversationStmt =
        $pdo->prepare(
            '
            SELECT
                id,
                connection_id,
                status

            FROM conversations

            WHERE user_low_id =
                  LEAST(
                      :user_a,
                      :user_b
                  )

              AND user_high_id =
                  GREATEST(
                      :user_c,
                      :user_d
                  )

            ORDER BY id DESC

            LIMIT 1
            '
        );


    $conversationStmt->execute([
        ':user_a' =>
            $userId,

        ':user_b' =>
            $targetId,

        ':user_c' =>
            $userId,

        ':user_d' =>
            $targetId
    ]);


    $conversation =
        $conversationStmt->fetch(
            PDO::FETCH_ASSOC
        );


    $conversationId =
        $conversation
            ? (int)$conversation['id']
            : 0;


    /*
     * =========================================================
     * CREATE IF MISSING
     * =========================================================
     */
    if (
        $conversationId <= 0
    ) {

        $insert =
            $pdo->prepare(
                '
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
                    \'active\',
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )
                '
            );


        $insert->execute([
            ':connection_id' =>
                (int)$connection['id'],

            ':user_one_id' =>
                $userId,

            ':user_two_id' =>
                $targetId
        ]);


        $conversationId =
            (int)$pdo->lastInsertId();

    } else {

        $update =
            $pdo->prepare(
                '
                UPDATE conversations

                SET
                    status = \'active\',
                    connection_id = :connection_id,
                    updated_at = CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                '
            );


        $update->execute([
            ':connection_id' =>
                (int)$connection['id'],

            ':id' =>
                $conversationId
        ]);
    }


    /*
     * =========================================================
     * SUCCESS
     * =========================================================
     */
    profileJsonResponse(
        true,
        'Chat access granted.',
        [

            'conversation_id' =>
                $conversationId,

            'connection_id' =>
                (int)$connection['id'],

            'connected' =>
                true,

            'viewer_has_premium' =>
                $viewerPremium,

            'profile_has_premium' =>
                $targetPremium,

            'redirect' =>
                'messages.html?conversation_id='
                .
                rawurlencode(
                    (string)$conversationId
                )
        ]
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI PROFILE CHAT ACCESS] '
        . $e->getMessage()
        . ' | FILE='
        . $e->getFile()
        . ' | LINE='
        . $e->getLine()
    );


    profileJsonResponse(
        false,
        'Unable to open chat.',
        [
            'code' =>
                'CHAT_ACCESS_ERROR'
        ],
        500
    );
}