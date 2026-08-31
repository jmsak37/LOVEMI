<?php
/**
 * ============================================================
 * LOVEMI - PENDING CONNECTIONS API
 * ============================================================
 *
 * GET:
 *
 *   api/connections/pending.php
 *
 * Returns:
 *   incoming  -> people who requested connection with you
 *   outgoing  -> requests you sent that are still pending
 *
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


/* ============================================================
   RESPONSE
============================================================ */

function pendingResponse(
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
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {

    pendingResponse(
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
   AUTHENTICATION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    pendingResponse(
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
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PENDING CONNECTIONS DB] ' .
        $e->getMessage()
    );

    pendingResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}


/* ============================================================
   INCOMING REQUESTS
============================================================ */

try {

    $incomingStmt =
        $pdo->prepare(
            "
            SELECT

                c.id AS connection_id,

                c.user_id,
                c.connected_user_id,
                c.initiated_by,

                c.status,
                c.connected_at,
                c.created_at,
                c.updated_at,

                u.id AS requester_id,
                u.username AS requester_username,
                u.full_names AS requester_full_names,
                u.gender AS requester_gender,

                p.display_name AS requester_display_name,
                p.bio AS requester_bio,
                p.city AS requester_city,
                p.relationship_status AS requester_relationship_status

            FROM connections c

            INNER JOIN users u
                ON u.id =
                   c.user_id

            LEFT JOIN profiles p
                ON p.user_id =
                   u.id

            WHERE c.connected_user_id =
                  :user_id

              AND c.status =
                  'pending'

              AND c.user_id <>
                  :same_user

              AND u.is_deleted = 0

              AND u.is_active = 1

              AND u.is_suspended = 0

            ORDER BY
                c.created_at DESC,
                c.id DESC
            "
        );

    $incomingStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':same_user' =>
                $userId

        ]
    );

    $incomingRows =
        $incomingStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PENDING INCOMING] ' .
        $e->getMessage()
    );

    pendingResponse(
        false,
        'Unable to load incoming connection requests.',
        [
            'code' =>
                'INCOMING_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   OUTGOING REQUESTS
============================================================ */

try {

    $outgoingStmt =
        $pdo->prepare(
            "
            SELECT

                c.id AS connection_id,

                c.user_id,
                c.connected_user_id,
                c.initiated_by,

                c.status,
                c.connected_at,
                c.created_at,
                c.updated_at,

                u.id AS recipient_id,
                u.username AS recipient_username,
                u.full_names AS recipient_full_names,
                u.gender AS recipient_gender,

                p.display_name AS recipient_display_name,
                p.bio AS recipient_bio,
                p.city AS recipient_city,
                p.relationship_status AS recipient_relationship_status

            FROM connections c

            INNER JOIN users u
                ON u.id =
                   c.connected_user_id

            LEFT JOIN profiles p
                ON p.user_id =
                   u.id

            WHERE c.user_id =
                  :user_id

              AND c.initiated_by =
                  :initiated_by

              AND c.status =
                  'pending'

              AND c.connected_user_id <>
                  :same_user

              AND u.is_deleted = 0

              AND u.is_active = 1

              AND u.is_suspended = 0

            ORDER BY
                c.created_at DESC,
                c.id DESC
            "
        );

    $outgoingStmt->execute(
        [

            ':user_id' =>
                $userId,

            ':initiated_by' =>
                $userId,

            ':same_user' =>
                $userId

        ]
    );

    $outgoingRows =
        $outgoingStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PENDING OUTGOING] ' .
        $e->getMessage()
    );

    pendingResponse(
        false,
        'Unable to load outgoing connection requests.',
        [
            'code' =>
                'OUTGOING_QUERY_FAILED'
        ],
        500
    );
}


/* ============================================================
   FORMAT INCOMING
============================================================ */

$incoming = [];

foreach (
    $incomingRows
    as $row
) {

    $incoming[] = [

        'connection_id' =>
            (int)
            $row['connection_id'],

        'status' =>
            $row['status'],

        'created_at' =>
            $row['created_at'],

        'user' => [

            'id' =>
                (int)
                $row['requester_id'],

            'username' =>
                $row['requester_username'],

            'full_names' =>
                $row['requester_full_names'],

            'display_name' =>
                $row['requester_display_name']
                ??
                $row['requester_full_names'],

            'gender' =>
                $row['requester_gender'],

            'bio' =>
                $row['requester_bio'],

            'city' =>
                $row['requester_city'],

            'relationship_status' =>
                $row['requester_relationship_status']

        ]

    ];
}


/* ============================================================
   FORMAT OUTGOING
============================================================ */

$outgoing = [];

foreach (
    $outgoingRows
    as $row
) {

    $outgoing[] = [

        'connection_id' =>
            (int)
            $row['connection_id'],

        'status' =>
            $row['status'],

        'created_at' =>
            $row['created_at'],

        'user' => [

            'id' =>
                (int)
                $row['recipient_id'],

            'username' =>
                $row['recipient_username'],

            'full_names' =>
                $row['recipient_full_names'],

            'display_name' =>
                $row['recipient_display_name']
                ??
                $row['recipient_full_names'],

            'gender' =>
                $row['recipient_gender'],

            'bio' =>
                $row['recipient_bio'],

            'city' =>
                $row['recipient_city'],

            'relationship_status' =>
                $row['recipient_relationship_status']

        ]

    ];
}


/* ============================================================
   COUNTS
============================================================ */

pendingResponse(
    true,
    'Pending connections loaded successfully.',
    [

        'incoming' =>
            $incoming,

        'outgoing' =>
            $outgoing,

        'counts' => [

            'incoming' =>
                count($incoming),

            'outgoing' =>
                count($outgoing),

            'total' =>
                count($incoming)
                +
                count($outgoing)

        ]

    ]
);