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


function notificationsDeleteResponse(
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

    notificationsDeleteResponse(
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

    notificationsDeleteResponse(
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

    notificationsDeleteResponse(
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

        notificationsDeleteResponse(
            false,
            'You do not have permission to delete notifications.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    notificationsDeleteResponse(
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


if (
    $notificationId <= 0
) {

    notificationsDeleteResponse(
        false,
        'A valid notification ID is required.',
        [],
        422
    );

}


/* =========================================================
   DELETE
========================================================= */

try {

    $pdo->beginTransaction();


    $stmt =
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


    $stmt->execute(
        [
            ':notification_id' =>
                $notificationId
        ]
    );


    $old =
        $stmt->fetch();


    if (
        !$old
    ) {

        throw new RuntimeException(
            'Notification not found.'
        );

    }


    $delete =
        $pdo->prepare(
            "
            DELETE FROM notifications

            WHERE
                id =
                    :notification_id

            LIMIT 1
            "
        );


    $delete->execute(
        [
            ':notification_id' =>
                $notificationId
        ]
    );


    if (
        $delete->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The notification could not be deleted.'
        );

    }


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
                    'admin_delete_notification',
                    'notification',
                    :entity_id,
                    :old_values,
                    NULL,
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
            '[LOVEMI NOTIFICATION DELETE AUDIT] '
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


    notificationsDeleteResponse(
        false,
        $e->getMessage(),
        [],
        422
    );

}


notificationsDeleteResponse(
    true,
    'Notification deleted successfully.',
    [

        'notification_id' =>
            $notificationId

    ]
);