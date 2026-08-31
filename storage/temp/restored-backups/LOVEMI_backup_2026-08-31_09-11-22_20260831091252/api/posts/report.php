<?php

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

function reportResponse(
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

    reportResponse(
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

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
        $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    reportResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html'
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
    );


$input =
    json_decode(
        (string)
        $raw,
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


$postId =
    (int)
    (
        $input['post_id']
        ??
        0
    );


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
    $postId <= 0
) {

    reportResponse(
        false,
        'Post ID is required.',
        [
            'code' =>
                'POST_ID_REQUIRED'
        ],
        422
    );
}


$allowedReasons = [

    'Inappropriate content',
    'Harassment',
    'Spam',
    'Fake account',
    'Scam or fraud',
    'Copyright',
    'Other'

];


if (
    $reason === ''
) {

    reportResponse(
        false,
        'Please select a report reason.',
        [
            'code' =>
                'REASON_REQUIRED'
        ],
        422
    );
}


if (
    !in_array(
        $reason,
        $allowedReasons,
        true
    )
) {

    reportResponse(
        false,
        'Invalid report reason.',
        [
            'code' =>
                'INVALID_REASON',

            'allowed_reasons' =>
                $allowedReasons

        ],
        422
    );
}


if (
    mb_strlen(
        $description
    )
    >
    3000
) {

    reportResponse(
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
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT DB] '
        .
        $e->getMessage()
    );


    reportResponse(
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
   LOAD POST
============================================================ */

try {

    $postStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                user_id,
                visibility,
                approval_status,
                deleted_at

            FROM posts

            WHERE id =
                :post_id

            LIMIT 1
            "
        );


    $postStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $postStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT POST LOOKUP] '
        .
        $e->getMessage()
    );


    reportResponse(
        false,
        'Unable to load the post.',
        [
            'code' =>
                'POST_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$post
) {

    reportResponse(
        false,
        'Post not found.',
        [
            'code' =>
                'POST_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $post['user_id']
    ===
    $userId
) {

    reportResponse(
        false,
        'You cannot report your own post.',
        [
            'code' =>
                'SELF_REPORT_NOT_ALLOWED'
        ],
        422
    );
}


/* ============================================================
   VERIFY OWNER ACCOUNT
============================================================ */

try {

    $ownerStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id =
                :user_id

            LIMIT 1
            "
        );


    $ownerStmt->execute(
        [
            ':user_id' =>
                (int)
                $post['user_id']
        ]
    );


    $owner =
        $ownerStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT OWNER] '
        .
        $e->getMessage()
    );


    reportResponse(
        false,
        'Unable to verify the post owner.',
        [
            'code' =>
                'OWNER_CHECK_FAILED'
        ],
        500
    );
}


/* ============================================================
   DUPLICATE RECENT REPORT CHECK
============================================================ */

try {

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM reports

            WHERE reporter_id =
                  :reporter_id

              AND post_id =
                  :post_id

              AND status IN
                  (
                      'pending',
                      'reviewing'
                  )

            ORDER BY
                id DESC

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':reporter_id' =>
                $userId,

            ':post_id' =>
                $postId

        ]
    );


    $existingReportId =
        $duplicateStmt->fetchColumn();

} catch (
    Throwable $e
) {

    $existingReportId =
        null;

}


if (
    $existingReportId
) {

    reportResponse(
        true,
        'You have already reported this post and it is awaiting review.',
        [

            'report_id' =>
                (int)
                $existingReportId,

            'already_reported' =>
                true

        ]
    );
}


/* ============================================================
   INSERT REPORT
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
                NULL,
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
                (int)
                $post['user_id'],

            ':post_id' =>
                $postId,

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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT INSERT] '
        .
        $e->getMessage()
    );


    reportResponse(
        false,
        'Unable to submit your report.',
        [
            'code' =>
                'REPORT_CREATION_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

reportResponse(
    true,
    'Your report has been submitted to the LOVEMI moderation team.',
    [

        'report_id' =>
            $reportId,

        'post_id' =>
            $postId,

        'status' =>
            'pending'

    ],
    201
);