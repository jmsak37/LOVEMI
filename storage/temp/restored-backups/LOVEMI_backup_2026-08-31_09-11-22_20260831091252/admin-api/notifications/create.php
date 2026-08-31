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


/* =========================================================
   RESPONSE
========================================================= */

function notificationsCreateResponse(
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

    notificationsCreateResponse(
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

    notificationsCreateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* =========================================================
   ADMIN AUTH
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

    notificationsCreateResponse(
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

        notificationsCreateResponse(
            false,
            'You do not have permission to create notifications.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    notificationsCreateResponse(
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


$userId =
    (int)(
        $input['user_id']
        ??
        0
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
    $userId <= 0
) {

    notificationsCreateResponse(
        false,
        'A valid recipient is required.',
        [],
        422
    );

}


if (
    $notificationTypeId <= 0
) {

    notificationsCreateResponse(
        false,
        'A valid notification type is required.',
        [],
        422
    );

}


if (
    $title === ''
) {

    notificationsCreateResponse(
        false,
        'Notification title is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $title
    )
    >
    180
) {

    notificationsCreateResponse(
        false,
        'Notification title is too long.',
        [],
        422
    );

}


if (
    $message === ''
) {

    notificationsCreateResponse(
        false,
        'Notification message is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $referenceType
    )
    >
    50
) {

    notificationsCreateResponse(
        false,
        'Reference type is too long.',
        [],
        422
    );

}


/* =========================================================
   VALIDATE USER / TYPE / AUDIO
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

        notificationsCreateResponse(
            false,
            'Recipient account was not found.',
            [],
            404
        );

    }


    $typeStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                name,
                sound_enabled

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


    $type =
        $typeStmt->fetch();


    if (
        !$type
    ) {

        notificationsCreateResponse(
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

            notificationsCreateResponse(
                false,
                'Selected notification audio is not available.',
                [],
                422
            );

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATION CREATE VALIDATION] '
        .
        $e->getMessage()
    );


    notificationsCreateResponse(
        false,
        'Unable to validate notification data.',
        [],
        500
    );

}


/* =========================================================
   INSERT
========================================================= */

try {

    $stmt =
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


    $stmt->execute(
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


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATION CREATE] '
        .
        $e->getMessage()
    );


    notificationsCreateResponse(
        false,
        'The notification could not be created.',
        [],
        500
    );

}


/* =========================================================
   AUDIT
========================================================= */

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
                'admin_create_notification',
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
                            $message,

                        'reference_type' =>
                            $referenceType,

                        'reference_id' =>
                            $referenceId

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
    Throwable $e
) {

    error_log(
        '[LOVEMI NOTIFICATION CREATE AUDIT] '
        .
        $e->getMessage()
    );

}


/* =========================================================
   RESPONSE
========================================================= */

notificationsCreateResponse(
    true,
    'Notification created and sent successfully.',
    [

        'notification_id' =>
            $notificationId,

        'recipient_id' =>
            $userId

    ]
);