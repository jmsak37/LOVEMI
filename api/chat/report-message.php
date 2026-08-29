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

function reportMessageResponse(
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

    reportMessageResponse(
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

    reportMessageResponse(
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


$messageId =
    (int)
    (
        $input['message_id']
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


if (
    $messageId <= 0
) {

    reportMessageResponse(
        false,
        'Message ID is required.',
        [
            'code' =>
                'MESSAGE_ID_REQUIRED'
        ],
        422
    );
}


if (
    $reason === ''
) {

    reportMessageResponse(
        false,
        'Please select a report reason.',
        [
            'code' =>
                'REASON_REQUIRED'
        ],
        422
    );
}


$allowedReasons = [

    'Harassment',
    'Spam',
    'Scam or fraud',
    'Inappropriate content',
    'Threatening content',
    'Other'

];


if (
    !in_array(
        $reason,
        $allowedReasons,
        true
    )
) {

    reportMessageResponse(
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

    reportMessageResponse(
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
        '[LOVEMI REPORT MESSAGE DB] '
        .
        $e->getMessage()
    );


    reportMessageResponse(
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
   LOAD MESSAGE
============================================================ */

try {

    $messageStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                conversation_id,
                sender_id,
                receiver_id,
                message_type,
                created_at

            FROM messages

            WHERE id =
                :message_id

            LIMIT 1
            "
        );


    $messageStmt->execute(
        [
            ':message_id' =>
                $messageId
        ]
    );


    $message =
        $messageStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REPORT MESSAGE QUERY] '
        .
        $e->getMessage()
    );


    reportMessageResponse(
        false,
        'Unable to load the message.',
        [
            'code' =>
                'MESSAGE_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$message
) {

    reportMessageResponse(
        false,
        'Message not found.',
        [
            'code' =>
                'MESSAGE_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   PARTICIPANT CHECK
============================================================ */

$isParticipant =
    (
        (int)
        $message['sender_id']
        ===
        $userId
    )
    ||
    (
        (int)
        $message['receiver_id']
        ===
        $userId
    );


if (
    !$isParticipant
) {

    reportMessageResponse(
        false,
        'You cannot report a message outside your conversation.',
        [
            'code' =>
                'NOT_MESSAGE_PARTICIPANT'
        ],
        403
    );
}


/*
|--------------------------------------------------------------------------
| Do not allow a user to report a message they somehow sent themselves
|--------------------------------------------------------------------------
*/

if (
    (int)
    $message['sender_id']
    ===
    $userId
) {

    reportMessageResponse(
        false,
        'You cannot report your own message.',
        [
            'code' =>
                'SELF_REPORT_NOT_ALLOWED'
        ],
        422
    );
}


/* ============================================================
   DUPLICATE REPORT CHECK
============================================================ */

try {

    $duplicateStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM reports

            WHERE reporter_id =
                  :reporter_id

              AND message_id =
                  :message_id

              AND status IN
                  (
                      'pending',
                      'reviewing'
                  )

            LIMIT 1
            "
        );


    $duplicateStmt->execute(
        [

            ':reporter_id' =>
                $userId,

            ':message_id' =>
                $messageId

        ]
    );


    $existing =
        $duplicateStmt->fetchColumn();

} catch (
    Throwable $e
) {

    $existing =
        null;

}


if (
    $existing
) {

    reportMessageResponse(
        true,
        'You have already reported this message.',
        [

            'report_id' =>
                (int)
                $existing,

            'already_reported' =>
                true

        ]
    );
}


/* ============================================================
   INSERT REPORT
============================================================ */

try {

    $reportStmt =
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
                NULL,
                :message_id,
                :reason,
                :description,
                'pending'
            )
            "
        );


    $reportStmt->execute(
        [

            ':reporter_id' =>
                $userId,

            ':reported_user_id' =>
                (int)
                $message['sender_id'],

            ':message_id' =>
                $messageId,

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
        '[LOVEMI REPORT MESSAGE INSERT] '
        .
        $e->getMessage()
    );


    reportMessageResponse(
        false,
        'Unable to submit the message report.',
        [
            'code' =>
                'MESSAGE_REPORT_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

reportMessageResponse(
    true,
    'Message reported successfully.',
    [

        'report_id' =>
            $reportId,

        'message_id' =>
            $messageId,

        'status' =>
            'pending'

    ],
    201
);