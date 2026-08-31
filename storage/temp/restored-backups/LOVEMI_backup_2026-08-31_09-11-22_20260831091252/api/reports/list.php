<?php
/**
 * ============================================================
 * LOVEMI - USER REPORTS LIST API
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


function reportsListResponse(
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

    reportsListResponse(
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

    reportsListResponse(
        false,
        'Please log in to view your reports.',
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
   PAGINATION
============================================================ */

$limit =
    isset($_GET['limit'])
        ?
        (int)
        $_GET['limit']
        :
        20;


$offset =
    isset($_GET['offset'])
        ?
        (int)
        $_GET['offset']
        :
        0;


$limit =
    max(
        1,
        min(
            100,
            $limit
        )
    );


$offset =
    max(
        0,
        $offset
    );


$statusFilter =
    trim(
        (string)
        (
            $_GET['status']
            ??
            ''
        )
    );


$allowedStatuses = [

    'pending',
    'reviewing',
    'resolved',
    'rejected',
    'dismissed',
    'closed',
    'open'

];


if (
    $statusFilter !== ''
    &&
    !in_array(
        strtolower(
            $statusFilter
        ),
        $allowedStatuses,
        true
    )
) {

    $statusFilter =
        '';

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REPORT LIST DB] '
        .
        $e->getMessage()
    );


    reportsListResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   WHERE
============================================================ */

$where =
    'r.reporter_id = :user_id';


$params = [

    ':user_id' =>
        $userId

];


if (
    $statusFilter !== ''
) {

    $where .=
        ' AND r.status = :status';


    $params[':status'] =
        strtolower(
            $statusFilter
        );

}


/* ============================================================
   QUERY
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

            WHERE {$where}

            ORDER BY
                r.created_at DESC,
                r.id DESC

            LIMIT {$limit}

            OFFSET {$offset}
            "
        );


    $stmt->execute(
        $params
    );


    $rows =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI REPORT LIST QUERY] '
        .
        $e->getMessage()
    );


    reportsListResponse(
        false,
        'Unable to load your reports.',
        [
            'code' =>
                'REPORT_LIST_FAILED'
        ],
        500
    );

}


/* ============================================================
   TOTAL
============================================================ */

try {

    $countSql =
        "
        SELECT COUNT(*)

        FROM reports r

        WHERE {$where}
        ";


    $countStmt =
        $pdo->prepare(
            $countSql
        );


    $countStmt->execute(
        $params
    );


    $total =
        (int)
        $countStmt->fetchColumn();

} catch (Throwable $e) {

    $total =
        count(
            $rows
        );

}


/* ============================================================
   FORMAT
============================================================ */

$reports =
    [];


foreach (
    $rows
    as $row
) {

    $reports[] = [

        'id' =>
            (int)
            $row['id'],

        'target' => [

            'reported_user_id' =>
                $row['reported_user_id'] !== null
                    ?
                    (int)
                    $row['reported_user_id']
                    :
                    null,

            'reported_username' =>
                $row['reported_username'],

            'reported_full_names' =>
                $row['reported_full_names'],

            'post_id' =>
                $row['post_id'] !== null
                    ?
                    (int)
                    $row['post_id']
                    :
                    null,

            'message_id' =>
                $row['message_id'] !== null
                    ?
                    (int)
                    $row['message_id']
                    :
                    null

        ],

        'reason' =>
            (string)
            $row['reason'],

        'description' =>
            $row['description'],

        'status' =>
            (string)
            $row['status'],

        'review' => [

            'reviewed_by' =>
                $row['reviewed_by'] !== null
                    ?
                    (int)
                    $row['reviewed_by']
                    :
                    null,

            'reviewed_at' =>
                $row['reviewed_at'],

            'resolution' =>
                $row['resolution']

        ],

        'created_at' =>
            $row['created_at']

    ];

}


/* ============================================================
   RESPONSE
============================================================ */

reportsListResponse(
    true,
    'Reports loaded successfully.',
    [

        'reports' =>
            $reports,

        'pagination' => [

            'total' =>
                $total,

            'limit' =>
                $limit,

            'offset' =>
                $offset,

            'has_more' =>
                (
                    $offset
                    +
                    count(
                        $reports
                    )
                )
                <
                $total

        ]

    ]
);