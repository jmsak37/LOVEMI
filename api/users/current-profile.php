<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

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


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function currentProfileResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        array_merge(
            [
                'success' =>
                    $success,

                'message' =>
                    $message
            ],
            $extra
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    currentProfileResponse(
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
   AUTH
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

    currentProfileResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
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
        '[LOVEMI CURRENT PROFILE DB] '
        .
        $e->getMessage()
    );


    currentProfileResponse(
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
   LOAD USER PROFILE PHOTO
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

                c.name AS country_name,

                (
                    SELECT
                        p.file_path

                    FROM photos p

                    WHERE

                        p.user_id =
                            u.id

                      AND p.photo_type =
                            'profile'

                      AND p.approval_status =
                            'approved'

                      AND p.is_primary =
                            1

                    ORDER BY
                        p.uploaded_at DESC,
                        p.id DESC

                    LIMIT 1

                ) AS profile_photo

            FROM users u

            LEFT JOIN countries c
                ON c.id =
                    u.country_id

            WHERE

                u.id =
                    :user_id

              AND u.is_active =
                    1

              AND u.is_suspended =
                    0

              AND u.is_deleted =
                    0

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CURRENT PROFILE QUERY] '
        .
        $e->getMessage()
    );


    currentProfileResponse(
        false,
        'Unable to load your profile.',
        [
            'code' =>
                'PROFILE_QUERY_ERROR'
        ],
        500
    );

}


if (!$user) {

    currentProfileResponse(
        false,
        'Your profile could not be found.',
        [
            'code' =>
                'PROFILE_NOT_FOUND'
        ],
        404
    );

}


/*
 * If the user has no current primary photo,
 * use the newest approved profile photo.
 */

$profilePhoto =
    $user['profile_photo'];


/* ============================================================
   FALLBACK PHOTO
============================================================ */

if (
    !$profilePhoto
) {

    try {

        $fallback =
            $pdo->prepare(
                "
                SELECT

                    file_path

                FROM photos

                WHERE

                    user_id =
                        :user_id

                  AND photo_type =
                        'profile'

                  AND approval_status =
                        'approved'

                ORDER BY

                    is_primary DESC,

                    uploaded_at DESC,

                    id DESC

                LIMIT 1
                "
            );


        $fallback->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $profilePhoto =
            $fallback->fetchColumn()
            ?:
            null;

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI CURRENT PROFILE FALLBACK] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   RESPONSE
============================================================ */

currentProfileResponse(
    true,
    'Current profile loaded successfully.',
    [

        'profile' =>
            [

                'user_id' =>
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

                'country_name' =>
                    $user['country_name']
                    !==
                    null
                        ?
                        (string)
                        $user['country_name']
                        :
                        null,

                'profile_photo' =>
                    $profilePhoto
                    !==
                    null
                        ?
                        (string)
                        $profilePhoto
                        :
                        null,

                'photo_url' =>
                    $profilePhoto
                    !==
                    null
                        ?
                        (string)
                        $profilePhoto
                        :
                        null

            ]

    ]
);