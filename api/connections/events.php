<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function eventsResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    eventsResponse(
        false,
        'Only GET requests are allowed.',
        [],
        405
    );

}

$currentUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($currentUserId <= 0) {

    eventsResponse(
        false,
        'Please log in first.',
        [],
        401
    );

}

$afterId =
    max(
        0,
        (int)(
            $_GET['after']
            ??
            0
        )
    );

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION EVENTS DB] '
        .
        $e->getMessage()
    );

    eventsResponse(
        false,
        'Database connection failed.',
        [
            'events' => []
        ],
        500
    );

}

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                n.id,

                n.title,

                n.message,

                n.reference_type,

                n.reference_id,

                n.sender_id,

                n.created_at,

                na.file_name,

                na.file_path

            FROM notifications n

            LEFT JOIN notification_audio na

                ON na.id = n.audio_id

            WHERE

                n.user_id = :user_id

                AND n.id > :after_id

                AND n.reference_type IN
                (
                    'connection_request',
                    'connection_accepted'
                )

            ORDER BY

                n.id ASC

            LIMIT 50
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $currentUserId,

            ':after_id' =>
                $afterId
        ]
    );


    $rows =
        $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION EVENTS QUERY] '
        .
        $e->getMessage()
    );

    eventsResponse(
        false,
        'Unable to load connection events.',
        [
            'events' => []
        ],
        500
    );

}

$events = [];

foreach (
    $rows as $row
) {

    $referenceType =
        strtolower(
            (string)
            $row['reference_type']
        );


    $eventType =
        $referenceType ===
        'connection_accepted'
            ?
            'connection_accepted'
            :
            'connection_request';


    $soundFile =
        $eventType ===
        'connection_accepted'
            ?
            'notification14.mp3'
            :
            'notification12.mp3';


    $soundPath =
        !empty(
            $row['file_path']
        )
            ?
            (string)
            $row['file_path']
            :
            'assets/audio/'
            .
            $soundFile;


    $events[] = [

        'id' =>
            (int)
            $row['id'],

        'event_type' =>
            $eventType,

        'title' =>
            (string)
            $row['title'],

        'message' =>
            (string)
            $row['message'],

        'reference_id' =>
            $row['reference_id'] !== null
                ?
                (int)
                $row['reference_id']
                :
                null,

        'sender_id' =>
            $row['sender_id'] !== null
                ?
                (int)
                $row['sender_id']
                :
                null,

        'sound_file' =>
            $soundFile,

        'sound_path' =>
            $soundPath,

        'created_at' =>
            (string)
            $row['created_at']

    ];

}

eventsResponse(
    true,
    'Connection events loaded.',
    [

        'count' =>
            count($events),

        'events' =>
            $events

    ]
);