<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - GET REPORT
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

function reportGetResponse(
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
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    reportGetResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| AUTHENTICATION
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

    reportGetResponse(
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

        reportGetResponse(
            false,
            'You do not have permission to view reports.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    reportGetResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| REPORT ID
|--------------------------------------------------------------------------
*/

$reportId =
    (int)(
        $_GET['id']
        ??
        0
    );


if (
    $reportId <= 0
) {

    reportGetResponse(
        false,
        'A valid report ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| REPORT
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                r.id,

                r.reporter_id,

                r.reported_user_id,

                r.post_id,

                r.message_id,

                r.reason,

                r.description,

                r.status,

                r.reviewed_by,

                r.reviewed_at,

                r.resolution,

                r.created_at,

                reporter.username
                    AS reporter_username,

                reporter.full_names
                    AS reporter_full_names,

                reporter.email
                    AS reporter_email,

                reported.username
                    AS reported_username,

                reported.full_names
                    AS reported_full_names,

                reported.email
                    AS reported_email,

                reviewer.username
                    AS reviewed_by_username,

                reviewer.full_names
                    AS reviewed_by_name,

                p.content
                    AS post_content,

                p.approval_status
                    AS post_approval_status,

                p.created_at
                    AS post_created_at,

                msg.message_text,

                msg.message_type,

                msg.created_at
                    AS message_created_at

            FROM reports r

            INNER JOIN users reporter
                ON reporter.id =
                    r.reporter_id

            LEFT JOIN users reported
                ON reported.id =
                    r.reported_user_id

            LEFT JOIN users reviewer
                ON reviewer.id =
                    r.reviewed_by

            LEFT JOIN posts p
                ON p.id =
                    r.post_id

            LEFT JOIN messages msg
                ON msg.id =
                    r.message_id

            WHERE
                r.id = :report_id

            LIMIT 1
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

} catch (
    Throwable $e
) {

    reportGetResponse(
        false,
        'Unable to load report details.',
        [],
        500
    );

}


if (
    !$report
) {

    reportGetResponse(
        false,
        'Report not found.',
        [],
        404
    );

}


/*
|--------------------------------------------------------------------------
| AVATARS
|--------------------------------------------------------------------------
*/

$reporterAvatar =
    null;


$reportedAvatar =
    null;


try {

    $avatarStmt =
        $pdo->prepare(
            "
            SELECT

                user_id,

                file_path

            FROM photos

            WHERE

                photo_type = 'profile'

                AND is_primary = 1

                AND approval_status = 'approved'

                AND user_id IN (
                    :reporter_id,
                    :reported_id
                )

            ORDER BY
                id DESC
            "
        );


    $avatarStmt->execute(
        [
            ':reporter_id' =>
                (int)
                $report['reporter_id'],

            ':reported_id' =>
                (int)(
                    $report['reported_user_id']
                    ??
                    0
                )
        ]
    );


    foreach (
        $avatarStmt->fetchAll()
        as $photo
    ) {

        if (
            (int)$photo['user_id']
            ===
            (int)$report['reporter_id']
        ) {

            $reporterAvatar =
                $photo['file_path'];

        }


        if (
            !empty(
                $report['reported_user_id']
            )
            &&
            (int)$photo['user_id']
            ===
            (int)$report['reported_user_id']
        ) {

            $reportedAvatar =
                $photo['file_path'];

        }

    }

} catch (
    Throwable $e
) {

    /*
     * Avatar is optional.
     */

}


$report[
    'reporter_avatar'
] =
    $reporterAvatar;


$report[
    'reported_avatar'
] =
    $reportedAvatar;


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

reportGetResponse(
    true,
    'Report loaded successfully.',
    [
        'report' =>
            $report
    ]
);