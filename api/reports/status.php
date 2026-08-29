<?php
/**
 * ============================================================
 * LOVEMI - REPORT STATUS API
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';


header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function reportStatusResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'GET'
) {

    reportStatusResponse(
        false,
        'Only GET requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );

}


/* ============================================================
   USER
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    reportStatusResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=reports.html'
        ],
        401
    );

}


/* ============================================================
   REPORT ID
============================================================ */

$reportId =
    isset(
        $_GET['report_id']
    )
        ?
        (int)
        $_GET['report_id']
        :
        0;


if (
    $reportId <= 0
) {

    reportStatusResponse(
        false,
        'Report ID is required.',
        [
            'code' =>
                'REPORT_ID_REQUIRED'
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
        '[LOVEMI REPORT STATUS DB] '
        .
        $e->getMessage()
    );


    reportStatusResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   LOAD REPORT
============================================================ */

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

                reported.username
                    AS reported_username,

                reported.full_names
                    AS reported_full_names

            FROM reports r

            LEFT JOIN users reported
                ON reported.id =
                   r.reported_user_id

            WHERE r.id = :report_id

              AND r.reporter_id = :user_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [

            ':report_id' =>
                $reportId,

            ':user_id' =>
                $userId

        ]
    );


    $report =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REPORT STATUS QUERY] '
        .
        $e->getMessage()
    );


    reportStatusResponse(
        false,
        'Unable to load the report.',
        [],
        500
    );

}


if (
    !$report
) {

    reportStatusResponse(
        false,
        'Report not found.',
        [
            'code' =>
                'REPORT_NOT_FOUND'
        ],
        404
    );

}


/* ============================================================
   RESPONSE
============================================================ */

reportStatusResponse(
    true,
    'Report status loaded successfully.',
    [

        'report' => [

            'id' =>
                (int)
                $report['id'],

            'target' => [

                'reported_user_id' =>
                    $report['reported_user_id'] !== null
                        ?
                        (int)
                        $report['reported_user_id']
                        :
                        null,

                'reported_username' =>
                    $report['reported_username'],

                'reported_full_names' =>
                    $report['reported_full_names'],

                'post_id' =>
                    $report['post_id'] !== null
                        ?
                        (int)
                        $report['post_id']
                        :
                        null,

                'message_id' =>
                    $report['message_id'] !== null
                        ?
                        (int)
                        $report['message_id']
                        :
                        null

            ],

            'reason' =>
                $report['reason'],

            'description' =>
                $report['description'],

            'status' =>
                $report['status'],

            'review' => [

                'reviewed_by' =>
                    $report['reviewed_by'] !== null
                        ?
                        (int)
                        $report['reviewed_by']
                        :
                        null,

                'reviewed_at' =>
                    $report['reviewed_at'],

                'resolution' =>
                    $report['resolution']

            ],

            'created_at' =>
                $report['created_at']

        ]

    ]
);