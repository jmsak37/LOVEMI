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

function detailResponse(
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

    detailResponse(
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

    detailResponse(
        false,
        'Please log in first.',
        [],
        401
    );

}

$targetUserId =
    isset($_GET['user_id'])
        ? (int) $_GET['user_id']
        : 0;

if ($targetUserId <= 0) {

    detailResponse(
        false,
        'Invalid member.',
        [],
        422
    );

}

if (
    $targetUserId ===
    $currentUserId
) {

    detailResponse(
        false,
        'This endpoint is for another member.',
        [],
        422
    );

}

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION DETAIL DB] '
        .
        $e->getMessage()
    );

    detailResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ACCEPTED CONNECTION CHECK
============================================================ */

try {

    $connectionStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                connected_user_id,

                initiated_by,

                status,

                connected_at

            FROM connections

            WHERE

                (
                    (
                        user_id = :current_user_one

                        AND

                        connected_user_id = :target_user_one
                    )

                    OR

                    (
                        user_id = :target_user_two

                        AND

                        connected_user_id = :current_user_two
                    )
                )

                AND status IN
                    (
                        'accepted',
                        'connected'
                    )

            ORDER BY id DESC

            LIMIT 1
            "
        );

    $connectionStmt->execute(
        [
            ':current_user_one' =>
                $currentUserId,

            ':target_user_one' =>
                $targetUserId,

            ':target_user_two' =>
                $targetUserId,

            ':current_user_two' =>
                $currentUserId
        ]
    );

    $connection =
        $connectionStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION DETAIL CHECK] '
        .
        $e->getMessage()
    );

    detailResponse(
        false,
        'Unable to verify the connection.',
        [],
        500
    );

}

$isConnected =
    (bool)
    $connection;


$showWhatsapp =
    isset(
        $_GET['whatsapp']
    )
    &&
    $_GET['whatsapp'] === '1';


/* ============================================================
   LOAD PERSON
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.gender,

                u.date_of_birth,

                u.phone_number,

                u.phone_e164,

                u.phone_verified,

                u.email_verified,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                c.name AS country_name,

                c.iso2 AS country_iso2,

                p.display_name,

                p.bio,

                p.city,

                p.relationship_status,

                p.looking_for,

                p.interests,

                p.profile_visibility,

                p.show_online_status,

                p.allow_messages,

                (
                    SELECT
                        ph.file_path

                    FROM photos ph

                    WHERE ph.user_id = u.id

                      AND ph.photo_type = 'profile'

                      AND ph.approval_status = 'approved'

                      AND ph.is_primary = 1

                    ORDER BY
                        ph.uploaded_at DESC,
                        ph.id DESC

                    LIMIT 1

                ) AS profile_photo_primary,

                (
                    SELECT
                        ph2.file_path

                    FROM photos ph2

                    WHERE ph2.user_id = u.id

                      AND ph2.photo_type = 'profile'

                      AND ph2.approval_status = 'approved'

                    ORDER BY
                        ph2.is_primary DESC,
                        ph2.uploaded_at DESC,
                        ph2.id DESC

                    LIMIT 1

                ) AS profile_photo_fallback,

                CASE

                    WHEN EXISTS
                    (
                        SELECT 1

                        FROM user_presence up

                        WHERE
                            up.user_id = u.id

                            AND up.is_online = 1
                    )

                    THEN 1

                    WHEN EXISTS
                    (
                        SELECT 1

                        FROM user_sessions us

                        WHERE
                            us.user_id = u.id

                            AND us.revoked_at IS NULL

                            AND us.expires_at >
                                CURRENT_TIMESTAMP

                            AND us.last_activity_at >=
                                DATE_SUB(
                                    CURRENT_TIMESTAMP,
                                    INTERVAL 10 MINUTE
                                )
                    )

                    THEN 1

                    ELSE 0

                END AS is_online

            FROM users u

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE
                u.id = :user_id

            LIMIT 1
            "
        );

    $stmt->execute(
        [
            ':user_id' =>
                $targetUserId
        ]
    );

    $user =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CONNECTION DETAIL USER] '
        .
        $e->getMessage()
    );

    detailResponse(
        false,
        'Unable to load member details.',
        [],
        500
    );

}

if (
    !$user
) {

    detailResponse(
        false,
        'Member not found.',
        [],
        404
    );

}

$profilePhoto =
    !empty(
        $user['profile_photo_primary']
    )
        ?
        $user['profile_photo_primary']
        :
        (
            !empty(
                $user['profile_photo_fallback']
            )
                ?
                $user['profile_photo_fallback']
                :
                null
        );


$age =
    null;


if (
    !empty(
        $user['date_of_birth']
    )
) {

    try {

        $dob =
            new DateTime(
                (string)
                $user['date_of_birth']
            );

        $today =
            new DateTime();

        $age =
            $dob->diff(
                $today
            )->y;

    } catch (
        Throwable $e
    ) {

        $age =
            null;

    }

}


/* ============================================================
   NO PRIVATE PHONE UNLESS CONNECTED
============================================================ */

$phoneE164 =
    null;

$whatsappNumber =
    null;

$whatsappDisplay =
    null;


if (
    $isConnected
) {

    /*
     * Prefer verified/e164 number.
     */

    $sourceNumber =
        trim(
            (string)(
                $user['phone_e164']
                ||
                $user['phone_number']
                ||
                ''
            )
        );


    if (
        $sourceNumber !== ''
    ) {

        $digits =
            preg_replace(
                '/\D+/',
                '',
                $sourceNumber
            );


        /*
         * Generic cleanup for Kenya values accidentally
         * stored as +2540XXXXXXXXX.
         */

        if (
            is_string($digits)
            &&
            str_starts_with(
                $digits,
                '2540'
            )
        ) {

            $digits =
                '254'
                .
                substr(
                    $digits,
                    4
                );

        }


        if (
            is_string($digits)
            &&
            strlen($digits) >= 8
        ) {

            $phoneE164 =
                '+'
                .
                $digits;

            $whatsappNumber =
                $digits;

            $whatsappDisplay =
                $phoneE164;

        }

    }

}


/* ============================================================
   WHATSAPP REQUEST REQUIRES CONNECTION
============================================================ */

if (
    $showWhatsapp
    &&
    !$isConnected
) {

    detailResponse(
        false,
        'WhatsApp is available only after the connection is accepted.',
        [
            'code' =>
                'CONNECTION_REQUIRED'
        ],
        403
    );

}


detailResponse(
    true,
    'Member details loaded successfully.',
    [

        'user' => [

            'id' =>
                (int)
                $user['id'],

            'username' =>
                (string)
                $user['username'],

            'full_name' =>
                (string)
                $user['full_names'],

            'gender' =>
                (string)
                $user['gender'],

            'date_of_birth' =>
                $user['date_of_birth'],

            'age' =>
                $age,

            'country_name' =>
                $user['country_name'] !== null
                    ?
                    (string)
                    $user['country_name']
                    :
                    null,

            'country_iso2' =>
                $user['country_iso2'] !== null
                    ?
                    strtoupper(
                        (string)
                        $user['country_iso2']
                    )
                    :
                    null,

            'city' =>
                $user['city'] !== null
                    ?
                    (string)
                    $user['city']
                    :
                    null,

            'bio' =>
                $user['bio'] !== null
                    ?
                    (string)
                    $user['bio']
                    :
                    null,

            'relationship_status' =>
                $user['relationship_status'],

            'looking_for' =>
                $user['looking_for'],

            'interests' =>
                $user['interests'],

            'profile_photo' =>
                $profilePhoto,

            'photo_url' =>
                $profilePhoto,

            'is_online' =>
                (bool)
                $user['is_online'],

            'allow_messages' =>
                (bool)
                $user['allow_messages'],

            'connection_id' =>
                $connection
                    ?
                    (int)
                    $connection['id']
                    :
                    null,

            'connection_status' =>
                $connection
                    ?
                    (string)
                    $connection['status']
                    :
                    null,

            'connected_at' =>
                $connection
                    ?
                    $connection['connected_at']
                    :
                    null,

            'whatsapp_display' =>
                $isConnected
                    ?
                    $whatsappDisplay
                    :
                    null,

            'whatsapp_number' =>
                $isConnected
                    ?
                    $whatsappNumber
                    :
                    null,

            'whatsapp_available' =>
                $isConnected
                &&
                $whatsappNumber !== null

        ]

    ]
);