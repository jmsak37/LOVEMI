<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - RESOLVE REPORT
|--------------------------------------------------------------------------
*/

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

ini_set(
    'display_errors',
    '0'
);


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

function resolveResponse(
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


/*
|--------------------------------------------------------------------------
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    resolveResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array($input)
) {

    $input =
        $_POST;

}


$reportId =
    (int)(
        $input['report_id']
        ??
        0
    );


$status =
    strtolower(
        trim(
            (string)(
                $input['status']
                ??
                'resolved'
            )
        )
    );


$resolution =
    trim(
        (string)(
            $input['resolution']
            ??
            ''
        )
    );


/*
|--------------------------------------------------------------------------
| VALIDATION
|--------------------------------------------------------------------------
*/

if (
    $reportId <= 0
) {

    resolveResponse(
        false,
        'A valid report ID is required.',
        [],
        422
    );

}


$allowedStatuses = [
    'resolved',
    'rejected',
    'dismissed'
];


if (
    !in_array(
        $status,
        $allowedStatuses,
        true
    )
) {

    resolveResponse(
        false,
        'Invalid resolution status.',
        [],
        422
    );

}


if (
    $resolution === ''
) {

    resolveResponse(
        false,
        'A resolution note is required.',
        [],
        422
    );

}


if (
    mb_strlen(
        $resolution
    )
    >
    5000
) {

    resolveResponse(
        false,
        'The resolution note is too long.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    resolveResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

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

    resolveResponse(
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


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'reports.manage'

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

        resolveResponse(
            false,
            'You do not have permission to resolve reports.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    resolveResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| RESOLVE
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                status,

                reported_user_id,

                post_id,

                message_id,

                reason

            FROM reports

            WHERE
                id = :report_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':report_id' =>
                $reportId
        ]
    );


    $report =
        $stmt->fetch();


    if (
        !$report
    ) {

        throw new RuntimeException(
            'Report not found.'
        );

    }


    $oldStatus =
        strtolower(
            (string)
            $report['status']
        );


    if (
        in_array(
            $oldStatus,
            [
                'resolved',
                'rejected',
                'dismissed'
            ],
            true
        )
    ) {

        throw new RuntimeException(
            'This report is already closed.'
        );

    }


    $update =
        $pdo->prepare(
            "
            UPDATE reports

            SET

                status =
                    :status,

                reviewed_by =
                    :reviewed_by,

                reviewed_at =
                    CURRENT_TIMESTAMP,

                resolution =
                    :resolution

            WHERE
                id = :report_id

            LIMIT 1
            "
        );


    $update->execute(
        [

            ':status' =>
                $status,

            ':reviewed_by' =>
                $adminId,

            ':resolution' =>
                $resolution,

            ':report_id' =>
                $reportId

        ]
    );


    /*
    |--------------------------------------------------------------------------
    | Notify reporter
    |--------------------------------------------------------------------------
    */

    try {

        $notificationType =
            $pdo->prepare(
                "
                SELECT id

                FROM notification_types

                WHERE slug =
                    'system'

                LIMIT 1
                "
            );


        $notificationType->execute();


        $notificationTypeId =
            $notificationType->fetchColumn()
            ?:
            null;


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
                    reference_id
                )
                SELECT

                    r.reporter_id,

                    :notification_type_id,

                    :sender_id,

                    'Report Update',

                    :message,

                    'report',

                    r.id

                FROM reports r

                WHERE r.id = :report_id

                LIMIT 1
                "
            );


        $notification->execute(
            [

                ':notification_type_id' =>
                    $notificationTypeId,

                ':sender_id' =>
                    $adminId,

                ':message' =>
                    'Your report #'
                    .
                    $reportId
                    .
                    ' has been '
                    .
                    $status
                    .
                    '.',

                ':report_id' =>
                    $reportId

            ]
        );

    } catch (
        Throwable $notificationError
    ) {

        /*
         * Do not fail the report resolution if the optional
         * notification cannot be created.
         */

        error_log(
            '[LOVEMI REPORT NOTIFICATION] '
            .
            $notificationError->getMessage()
        );

    }


    /*
    |--------------------------------------------------------------------------
    | Audit
    |--------------------------------------------------------------------------
    */

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
                'admin_resolve_report',
                'report',
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
                $reportId,

            ':old_values' =>
                json_encode(
                    [
                        'status' =>
                            $oldStatus
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':new_values' =>
                json_encode(
                    [
                        'status' =>
                            $status,

                        'resolution' =>
                            $resolution,

                        'reviewed_by' =>
                            $adminId
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


    $pdo->commit();

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI RESOLVE REPORT] '
        .
        $e->getMessage()
    );


    resolveResponse(
        false,
        $e->getMessage(),
        [],
        409
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

resolveResponse(
    true,
    'Report has been '
    .
    $status
    .
    ' successfully.',
    [

        'report_id' =>
            $reportId,

        'status' =>
            $status,

        'reviewed_by' =>
            $adminId,

        'resolution' =>
            $resolution

    ]
);