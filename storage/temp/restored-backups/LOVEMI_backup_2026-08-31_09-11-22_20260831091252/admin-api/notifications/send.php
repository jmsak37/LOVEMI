<?php

declare(strict_types=1);

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


function notificationsSendResponse(
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


/* =========================================================
   METHOD
========================================================= */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    notificationsSendResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* =========================================================
   SESSION
========================================================= */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
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


/* =========================================================
   DATABASE
========================================================= */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    notificationsSendResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   ADMIN
========================================================= */

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

    notificationsSendResponse(
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


try {

    $auth =
        $pdo->prepare(
            "
            SELECT
                u.id

            FROM users u

            INNER JOIN roles r
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
                    'notifications.manage'

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

        notificationsSendResponse(
            false,
            'You do not have permission to send notifications.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    notificationsSendResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* =========================================================
   INPUT
========================================================= */

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
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


/* =========================================================
   RESEND EXISTING
========================================================= */

$existingId =
    (int)(
        $input['notification_id']
        ??
        0
    );


if (
    $existingId > 0
) {

    try {

        $pdo->beginTransaction();


        $sourceStmt =
            $pdo->prepare(
                "
                SELECT

                    user_id,

                    notification_type_id,

                    sender_id,

                    title,

                    message,

                    reference_type,

                    reference_id,

                    audio_id

                FROM notifications

                WHERE
                    id =
                    :notification_id

                LIMIT 1

                FOR UPDATE
                "
            );


        $sourceStmt->execute(
            [
                ':notification_id' =>
                    $existingId
            ]
        );


        $source =
            $sourceStmt->fetch();


        if (
            !$source
        ) {

            throw new RuntimeException(
                'The notification to resend was not found.'
            );

        }


        $insert =
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
                    is_read
                )
                VALUES
                (
                    :user_id,
                    :notification_type_id,
                    :sender_id,
                    :title,
                    :message,
                    :reference_type,
                    :reference_id,
                    :audio_id,
                    0
                )
                "
            );


        $insert->execute(
            [

                ':user_id' =>
                    (int)
                    $source['user_id'],

                ':notification_type_id' =>
                    $source['notification_type_id'],

                ':sender_id' =>
                    $adminId,

                ':title' =>
                    $source['title'],

                ':message' =>
                    $source['message'],

                ':reference_type' =>
                    $source['reference_type'],

                ':reference_id' =>
                    $source['reference_id'],

                ':audio_id' =>
                    $source['audio_id']

            ]
        );


        $newId =
            (int)
            $pdo->lastInsertId();


        try {

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
                        'admin_resend_notification',
                        'notification',
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
                        $newId,

                    ':old_values' =>
                        json_encode(
                            [
                                'source_notification_id' =>
                                    $existingId
                            ],
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':new_values' =>
                        json_encode(
                            $source,
                            JSON_UNESCAPED_UNICODE
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

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI NOTIFICATION RESEND AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        $pdo->commit();


        notificationsSendResponse(
            true,
            'Notification sent again successfully.',
            [

                'notification_id' =>
                    $newId,

                'source_notification_id' =>
                    $existingId

            ]
        );

    } catch (
        Throwable $e
    ) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        notificationsSendResponse(
            false,
            $e->getMessage(),
            [],
            422
        );

    }

}


/* =========================================================
   NEW SEND
========================================================= */

$userId =
    !empty(
        $input['user_id']
    )
        ?
        (int)
        $input['user_id']
        :
        0;


$broadcast =
    !empty(
        $input['broadcast']
    )
    ||
    (
        isset(
            $input['user_id']
        )
        &&
        $input['user_id'] === null
    );


$notificationTypeId =
    (int)(
        $input['notification_type_id']
        ??
        0
    );


$audioId =
    !empty(
        $input['audio_id']
    )
        ?
        (int)
        $input['audio_id']
        :
        null;


$title =
    trim(
        (string)(
            $input['title']
            ??
            ''
        )
    );


$message =
    trim(
        (string)(
            $input['message']
            ??
            ''
        )
    );


$referenceType =
    trim(
        (string)(
            $input['reference_type']
            ??
            ''
        )
    );


$referenceId =
    !empty(
        $input['reference_id']
    )
        ?
        (int)
        $input['reference_id']
        :
        null;


/* =========================================================
   VALIDATION
========================================================= */

if (
    !$broadcast
    &&
    $userId <= 0
) {

    notificationsSendResponse(
        false,
        'Select a recipient or enable broadcast.',
        [],
        422
    );

}


if (
    $notificationTypeId <= 0
) {

    notificationsSendResponse(
        false,
        'A valid notification type is required.',
        [],
        422
    );

}


if (
    $title === ''
    ||
    mb_strlen($title) > 180
) {

    notificationsSendResponse(
        false,
        'A valid notification title is required.',
        [],
        422
    );

}


if (
    $message === ''
) {

    notificationsSendResponse(
        false,
        'Notification message is required.',
        [],
        422
    );

}


if (
    mb_strlen($referenceType) > 50
) {

    notificationsSendResponse(
        false,
        'Reference type is too long.',
        [],
        422
    );

}


/* =========================================================
   VALIDATE TYPE / AUDIO
========================================================= */

try {

    $typeStmt =
        $pdo->prepare(
            "
            SELECT
                id

            FROM notification_types

            WHERE
                id =
                    :type_id

            LIMIT 1
            "
        );


    $typeStmt->execute(
        [
            ':type_id' =>
                $notificationTypeId
        ]
    );


    if (
        !$typeStmt->fetch()
    ) {

        notificationsSendResponse(
            false,
            'Notification type was not found.',
            [],
            404
        );

    }


    if (
        $audioId !== null
    ) {

        $audioStmt =
            $pdo->prepare(
                "
                SELECT
                    id

                FROM notification_audio

                WHERE

                    id =
                        :audio_id

                    AND is_active =
                        1

                LIMIT 1
                "
            );


        $audioStmt->execute(
            [
                ':audio_id' =>
                    $audioId
            ]
        );


        if (
            !$audioStmt->fetch()
        ) {

            notificationsSendResponse(
                false,
                'Selected audio is unavailable.',
                [],
                422
            );

        }

    }

} catch (
    Throwable $e
) {

    notificationsSendResponse(
        false,
        'Unable to validate notification data.',
        [],
        500
    );

}


/* =========================================================
   BROADCAST
========================================================= */

if (
    $broadcast
) {

    try {

        /*
         * This performs a direct database broadcast.
         * Only active, non-suspended, non-deleted accounts receive it.
         */

        $insert =
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
                    is_read
                )

                SELECT

                    u.id,

                    :notification_type_id,

                    :sender_id,

                    :title,

                    :message,

                    :reference_type,

                    :reference_id,

                    :audio_id,

                    0

                FROM users u

                WHERE

                    u.is_active =
                        1

                    AND u.is_suspended =
                        0

                    AND u.is_deleted =
                        0
                "
            );


        $insert->execute(
            [

                ':notification_type_id' =>
                    $notificationTypeId,

                ':sender_id' =>
                    $adminId,

                ':title' =>
                    $title,

                ':message' =>
                    $message,

                ':reference_type' =>
                    $referenceType !== ''
                        ?
                        $referenceType
                        :
                        null,

                ':reference_id' =>
                    $referenceId,

                ':audio_id' =>
                    $audioId

            ]
        );


        $recipientCount =
            $insert->rowCount();


        try {

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
                        'admin_broadcast_notification',
                        'notification',
                        NULL,
                        NULL,
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

                    ':new_values' =>
                        json_encode(
                            [

                                'recipient_count' =>
                                    $recipientCount,

                                'notification_type_id' =>
                                    $notificationTypeId,

                                'title' =>
                                    $title,

                                'message' =>
                                    $message,

                                'audio_id' =>
                                    $audioId

                            ],
                            JSON_UNESCAPED_UNICODE
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

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI NOTIFICATION BROADCAST AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        notificationsSendResponse(
            true,
            'Broadcast notification sent successfully.',
            [

                'broadcast' =>
                    true,

                'recipient_count' =>
                    $recipientCount

            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI NOTIFICATION BROADCAST] '
            .
            $e->getMessage()
        );


        notificationsSendResponse(
            false,
            'The broadcast notification could not be sent.',
            [],
            500
        );

    }

}


/* =========================================================
   SINGLE RECIPIENT SEND
========================================================= */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT
                id

            FROM users

            WHERE

                id =
                    :user_id

                AND is_deleted =
                    0

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    if (
        !$userStmt->fetch()
    ) {

        notificationsSendResponse(
            false,
            'Recipient account was not found.',
            [],
            404
        );

    }


    $insert =
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
                is_read
            )
            VALUES
            (
                :user_id,
                :notification_type_id,
                :sender_id,
                :title,
                :message,
                :reference_type,
                :reference_id,
                :audio_id,
                0
            )
            "
        );


    $insert->execute(
        [

            ':user_id' =>
                $userId,

            ':notification_type_id' =>
                $notificationTypeId,

            ':sender_id' =>
                $adminId,

            ':title' =>
                $title,

            ':message' =>
                $message,

            ':reference_type' =>
                $referenceType !== ''
                    ?
                    $referenceType
                    :
                    null,

            ':reference_id' =>
                $referenceId,

            ':audio_id' =>
                $audioId

        ]
    );


    $notificationId =
        (int)
        $pdo->lastInsertId();


    try {

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
                    'admin_send_notification',
                    'notification',
                    :entity_id,
                    NULL,
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
                    $notificationId,

                ':new_values' =>
                    json_encode(
                        [

                            'recipient_user_id' =>
                                $userId,

                            'notification_type_id' =>
                                $notificationTypeId,

                            'audio_id' =>
                                $audioId,

                            'title' =>
                                $title,

                            'message' =>
                                $message

                        ],
                        JSON_UNESCAPED_UNICODE
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

    } catch (
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI NOTIFICATION SEND AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    notificationsSendResponse(
        true,
        'Notification sent successfully.',
        [

            'notification_id' =>
                $notificationId,

            'recipient_id' =>
                $userId

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATION SEND] '
        .
        $e->getMessage()
    );


    notificationsSendResponse(
        false,
        'The notification could not be sent.',
        [],
        500
    );

}