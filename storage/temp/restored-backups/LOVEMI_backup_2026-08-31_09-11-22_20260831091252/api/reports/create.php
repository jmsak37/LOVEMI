<?php
/**
 * ============================================================
 * LOVEMI - CREATE REPORT API
 * ============================================================
 *
 * Creates a report against:
 *
 *   - another user
 *   - a post
 *   - a message
 *
 * Only the authenticated user can create a report as himself.
 *
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function reportCreateResponse(
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

    reportCreateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;


if ($userId <= 0) {

    reportCreateResponse(
        false,
        'Please log in before submitting a report.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' =>
                'login.html?return=reports.html'
        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$rawInput =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string) $rawInput,
        true
    );


if (
    !is_array($input)
) {

    $input = $_POST;

}


$reportedUserId =
    isset($input['reported_user_id'])
        ?
        (int)
        $input['reported_user_id']
        :
        0;


$postId =
    isset($input['post_id'])
        ?
        (int)
        $input['post_id']
        :
        0;


$messageId =
    isset($input['message_id'])
        ?
        (int)
        $input['message_id']
        :
        0;


$reason =
    trim(
        (string)
        (
            $input['reason']
            ??
            ''
        )
    );


$description =
    trim(
        (string)
        (
            $input['description']
            ??
            ''
        )
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    $reportedUserId <= 0
    &&
    $postId <= 0
    &&
    $messageId <= 0
) {

    reportCreateResponse(
        false,
        'Select the user, post or message you want to report.',
        [
            'code' =>
                'REPORT_TARGET_REQUIRED'
        ],
        422
    );
}


if (
    $reason === ''
) {

    reportCreateResponse(
        false,
        'Please select a report reason.',
        [
            'code' =>
                'REASON_REQUIRED'
        ],
        422
    );
}


/*
 * Keep reason length inside database limit.
 */

if (
    mb_strlen(
        $reason
    )
    >
    100
) {

    reportCreateResponse(
        false,
        'The report reason is too long.',
        [
            'code' =>
                'REASON_TOO_LONG'
        ],
        422
    );
}


/*
 * Description is optional.
 */

if (
    mb_strlen(
        $description
    )
    >
    5000
) {

    reportCreateResponse(
        false,
        'The report description is too long.',
        [
            'code' =>
                'DESCRIPTION_TOO_LONG'
        ],
        422
    );
}


/* ============================================================
   SELF REPORT PROTECTION
============================================================ */

if (
    $reportedUserId > 0
    &&
    $reportedUserId === $userId
) {

    reportCreateResponse(
        false,
        'You cannot report your own account.',
        [
            'code' =>
                'SELF_REPORT_NOT_ALLOWED'
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
        '[LOVEMI REPORT CREATE DB] '
        .
        $e->getMessage()
    );


    reportCreateResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   VERIFY TARGET USER
============================================================ */

if (
    $reportedUserId > 0
) {

    try {

        $userStmt =
            $pdo->prepare(
                "
                SELECT
                    id

                FROM users

                WHERE id = :id

                LIMIT 1
                "
            );


        $userStmt->execute(
            [
                ':id' =>
                    $reportedUserId
            ]
        );


        $exists =
            $userStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI REPORT USER TARGET] '
            .
            $e->getMessage()
        );


        reportCreateResponse(
            false,
            'Unable to verify the reported user.',
            [],
            500
        );
    }


    if (
        !$exists
    ) {

        reportCreateResponse(
            false,
            'The reported user does not exist.',
            [
                'code' =>
                    'REPORTED_USER_NOT_FOUND'
            ],
            404
        );
    }

}


/* ============================================================
   VERIFY POST
============================================================ */

if (
    $postId > 0
) {

    try {

        $postStmt =
            $pdo->prepare(
                "
                SELECT
                    id

                FROM posts

                WHERE id = :id

                LIMIT 1
                "
            );


        $postStmt->execute(
            [
                ':id' =>
                    $postId
            ]
        );


        $exists =
            $postStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI REPORT POST TARGET] '
            .
            $e->getMessage()
        );


        reportCreateResponse(
            false,
            'Unable to verify the reported post.',
            [],
            500
        );
    }


    if (
        !$exists
    ) {

        reportCreateResponse(
            false,
            'The reported post does not exist.',
            [
                'code' =>
                    'POST_NOT_FOUND'
            ],
            404
        );
    }

}


/* ============================================================
   VERIFY MESSAGE
============================================================ */

if (
    $messageId > 0
) {

    try {

        /*
         * Only allow a user to report a message that belongs to
         * a conversation the user participates in.
         */

        $messageStmt =
            $pdo->prepare(
                "
                SELECT
                    m.id

                FROM messages m

                INNER JOIN conversations c
                    ON c.id = m.conversation_id

                WHERE m.id = :message_id

                  AND
                  (
                      c.user_one_id = :user_id_one
                      OR
                      c.user_two_id = :user_id_two
                  )

                LIMIT 1
                "
            );


        $messageStmt->execute(
            [

                ':message_id' =>
                    $messageId,

                ':user_id_one' =>
                    $userId,

                ':user_id_two' =>
                    $userId

            ]
        );


        $exists =
            $messageStmt->fetchColumn();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI REPORT MESSAGE TARGET] '
            .
            $e->getMessage()
        );


        reportCreateResponse(
            false,
            'Unable to verify the reported message.',
            [],
            500
        );
    }


    if (
        !$exists
    ) {

        reportCreateResponse(
            false,
            'The reported message could not be found.',
            [
                'code' =>
                    'MESSAGE_NOT_FOUND'
            ],
            404
        );
    }

}


/* ============================================================
   DUPLICATE CHECK
============================================================ */

try {

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT
                id

            FROM reports

            WHERE reporter_id = :reporter_id

              AND COALESCE(
                    reported_user_id,
                    0
                  )
                  =
                  COALESCE(
                    :reported_user_id,
                    0
                  )

              AND COALESCE(
                    post_id,
                    0
                  )
                  =
                  COALESCE(
                    :post_id,
                    0
                  )

              AND COALESCE(
                    message_id,
                    0
                  )
                  =
                  COALESCE(
                    :message_id,
                    0
                  )

              AND status IN
                  (
                    'pending',
                    'reviewing',
                    'open'
                  )

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':reporter_id' =>
                $userId,

            ':reported_user_id' =>
                $reportedUserId > 0
                    ? $reportedUserId
                    : null,

            ':post_id' =>
                $postId > 0
                    ? $postId
                    : null,

            ':message_id' =>
                $messageId > 0
                    ? $messageId
                    : null

        ]
    );


    $duplicate =
        $duplicateStmt->fetch();

} catch (Throwable $e) {

    /*
     * Duplicate protection is secondary. Continue if query fails.
     */

    error_log(
        '[LOVEMI REPORT DUPLICATE CHECK] '
        .
        $e->getMessage()
    );

    $duplicate =
        false;

}


if (
    $duplicate
) {

    reportCreateResponse(
        true,
        'You already submitted a report for this item.',
        [
            'code' =>
                'REPORT_ALREADY_EXISTS',

            'report_id' =>
                (int)
                $duplicate['id']
        ]
    );
}


/* ============================================================
   CREATE REPORT
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO reports
            (
                reporter_id,
                reported_user_id,
                post_id,
                message_id,
                reason,
                description,
                status
            )
            VALUES
            (
                :reporter_id,
                :reported_user_id,
                :post_id,
                :message_id,
                :reason,
                :description,
                'pending'
            )
            "
        );


    $stmt->execute(
        [

            ':reporter_id' =>
                $userId,

            ':reported_user_id' =>
                $reportedUserId > 0
                    ?
                    $reportedUserId
                    :
                    null,

            ':post_id' =>
                $postId > 0
                    ?
                    $postId
                    :
                    null,

            ':message_id' =>
                $messageId > 0
                    ?
                    $messageId
                    :
                    null,

            ':reason' =>
                $reason,

            ':description' =>
                $description !== ''
                    ?
                    $description
                    :
                    null

        ]
    );


    $reportId =
        (int)
        $pdo->lastInsertId();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REPORT INSERT] '
        .
        $e->getMessage()
    );


    reportCreateResponse(
        false,
        'Unable to submit your report.',
        [
            'code' =>
                'REPORT_CREATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   AUDIT
============================================================ */

try {

    $auditStmt =
        $pdo->prepare(
            "
            INSERT INTO audit_logs
            (
                user_id,
                action,
                entity_type,
                entity_id,
                new_values,
                ip_address,
                user_agent
            )
            VALUES
            (
                :user_id,
                'report_created',
                'report',
                :entity_id,
                :new_values,
                :ip_address,
                :user_agent
            )
            "
        );


    $auditStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':entity_id' =>
                $reportId,

            ':new_values' =>
                json_encode(
                    [
                        'reported_user_id' =>
                            $reportedUserId ?: null,

                        'post_id' =>
                            $postId ?: null,

                        'message_id' =>
                            $messageId ?: null,

                        'reason' =>
                            $reason,

                        'status' =>
                            'pending'
                    ],
                    JSON_UNESCAPED_UNICODE
                ),

            ':ip_address' =>
                $_SERVER['REMOTE_ADDR']
                ??
                null,

            ':user_agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ??
                null

        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REPORT AUDIT] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

reportCreateResponse(
    true,
    'Your report has been submitted for review.',
    [

        'report_id' =>
            $reportId,

        'status' =>
            'pending',

        'redirect' =>
            'reports.html'

    ],
    201
);