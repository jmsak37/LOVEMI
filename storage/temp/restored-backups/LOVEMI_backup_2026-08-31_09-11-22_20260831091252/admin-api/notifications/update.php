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


function notificationsUpdateResponse(
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

    notificationsUpdateResponse(
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
   DB
========================================================= */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    notificationsUpdateResponse(
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

    notificationsUpdateResponse(
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

        notificationsUpdateResponse(
            false,
            'You do not have permission to update notifications.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    notificationsUpdateResponse(
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


$notificationId =
    (int)(
        $input['notification_id']
        ??
        0
    );


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
   VALIDATE
========================================================= */

if (
    $notificationId <= 0
) {

    notificationsUpdateResponse(
        false,
        'A valid notification ID is required.',
        [],
        422
    );

}


if (
    $userId <= 0
) {

    notificationsUpdateResponse(
        false,
        'A valid recipient is required.',
        [],
        422
    );

}


if (
    $notificationTypeId <= 0
) {

    notificationsUpdateResponse(
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

    notificationsUpdateResponse(
        false,
        'A valid notification title is required.',
        [],
        422
    );

}


if (
    $message === ''
) {

    notificationsUpdateResponse(
        false,
        'Notification message is required.',
        [],
        422
    );

}


if (
    mb_strlen($referenceType) > 50
) {

    notificationsUpdateResponse(
        false,
        'Reference type is too long.',
        [],
        422
    );

}


/* =========================================================
   TRANSACTION
========================================================= */

try {

    $pdo->beginTransaction();


    $oldStmt =
        $pdo->prepare(
            "
            SELECT *

            FROM notifications

            WHERE
                id =
                    :notification_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $oldStmt->execute(
        [
            ':notification_id' =>
                $notificationId
        ]
    );


    $old =
        $oldStmt->fetch();


    if (
        !$old
    ) {

        throw new RuntimeException(
            'Notification not found.'
        );

    }


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

        throw new RuntimeException(
            'Recipient account was not found.'
        );

    }


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

        throw new RuntimeException(
            'Notification type was not found.'
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

            throw new RuntimeException(
                'Selected audio is unavailable.'
            );

        }

    }


    $update =
        $pdo->prepare(
            "
            UPDATE notifications

            SET

                user_id =
                    :user_id,

                notification_type_id =
                    :notification_type_id,

                sender_id =
                    COALESCE(
                        sender_id,
                        :sender_id
                    ),

                title =
                    :title,

                message =
                    :message,

                reference_type =
                    :reference_type,

                reference_id =
                    :reference_id,

                audio_id =
                    :audio_id

            WHERE
                id =
                    :notification_id

            LIMIT 1
            "
        );


    $update->execute(
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
                $audioId,

            ':notification_id' =>
                $notificationId

        ]
    );


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
                    'admin_update_notification',
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
                    $notificationId,

                ':old_values' =>
                    json_encode(
                        $old,
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [

                            'user_id' =>
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
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI NOTIFICATION UPDATE AUDIT] '
            .
            $auditError->getMessage()
        );

    }


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    notificationsUpdateResponse(
        false,
        $e->getMessage(),
        [],
        422
    );

}


notificationsUpdateResponse(
    true,
    'Notification updated successfully.',
    [

        'notification_id' =>
            $notificationId

    ]
);