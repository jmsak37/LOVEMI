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

function privacyResponse(
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
    &&
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'PUT'
) {

    privacyResponse(
        false,
        'Only POST or PUT requests are allowed.',
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

    privacyResponse(
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


/* ============================================================
   FIELDS
============================================================ */

$hasVisibility =
    array_key_exists(
        'profile_visibility',
        $input
    );


$hasOnline =
    array_key_exists(
        'show_online_status',
        $input
    );


$hasMessages =
    array_key_exists(
        'allow_messages',
        $input
    );


if (
    !$hasVisibility
    &&
    !$hasOnline
    &&
    !$hasMessages
) {

    privacyResponse(
        false,
        'No privacy settings were supplied.',
        [
            'code' =>
                'NO_SETTINGS'
        ],
        422
    );
}


/* ============================================================
   VALIDATE VISIBILITY
============================================================ */

$visibility =
    null;


if (
    $hasVisibility
) {

    $visibility =
        strtolower(
            trim(
                (string)
                $input[
                    'profile_visibility'
                ]
            )
        );


    $allowedVisibility = [

        'public',
        'connections',
        'private'

    ];


    if (
        !in_array(
            $visibility,
            $allowedVisibility,
            true
        )
    ) {

        privacyResponse(
            false,
            'Invalid profile visibility.',
            [

                'code' =>
                    'INVALID_PROFILE_VISIBILITY',

                'allowed' =>
                    $allowedVisibility

            ],
            422
        );
    }

}


/* ============================================================
   BOOLEAN NORMALIZATION
============================================================ */

function privacyBoolean(
    mixed $value,
    string $field
): int {

    if (
        is_bool(
            $value
        )
    ) {

        return $value
            ? 1
            : 0;

    }


    if (
        is_int(
            $value
        )
        ||
        is_float(
            $value
        )
    ) {

        if (
            (int)
            $value === 0
        ) {

            return 0;

        }

        if (
            (int)
            $value === 1
        ) {

            return 1;

        }

    }


    if (
        is_string(
            $value
        )
    ) {

        $normalized =
            strtolower(
                trim(
                    $value
                )
            );


        if (
            in_array(
                $normalized,
                [
                    '0',
                    'false',
                    'no',
                    'off'
                ],
                true
            )
        ) {

            return 0;

        }


        if (
            in_array(
                $normalized,
                [
                    '1',
                    'true',
                    'yes',
                    'on'
                ],
                true
            )
        ) {

            return 1;

        }

    }


    privacyResponse(
        false,
        "Invalid value for {$field}. Use 0 or 1.",
        [
            'code' =>
                'INVALID_BOOLEAN',

            'field' =>
                $field

        ],
        422
    );
}


$showOnline =
    null;


if (
    $hasOnline
) {

    $showOnline =
        privacyBoolean(
            $input[
                'show_online_status'
            ],
            'show_online_status'
        );

}


$allowMessages =
    null;


if (
    $hasMessages
) {

    $allowMessages =
        privacyBoolean(
            $input[
                'allow_messages'
            ],
            'allow_messages'
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
        '[LOVEMI UPDATE PRIVACY DB] '
        .
        $e->getMessage()
    );


    privacyResponse(
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
   VERIFY USER
============================================================ */

try {

    $userStmt =
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


    $userStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PRIVACY USER] '
        .
        $e->getMessage()
    );


    privacyResponse(
        false,
        'Unable to verify your account.',
        [
            'code' =>
                'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (
    !$user
) {

    privacyResponse(
        false,
        'Account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)
    $user['is_deleted']
    ===
    1
) {

    privacyResponse(
        false,
        'This account has been deleted.',
        [
            'code' =>
                'ACCOUNT_DELETED'
        ],
        403
    );
}


if (
    (int)
    $user['is_suspended']
    ===
    1
) {

    privacyResponse(
        false,
        'This account is suspended.',
        [
            'code' =>
                'ACCOUNT_SUSPENDED'
        ],
        403
    );
}


if (
    (int)
    $user['is_active']
    !==
    1
) {

    privacyResponse(
        false,
        'This account is inactive.',
        [
            'code' =>
                'ACCOUNT_INACTIVE'
        ],
        403
    );
}


/* ============================================================
   BUILD UPDATE
============================================================ */

$updates =
    [];


$params =
    [
        ':user_id' =>
            $userId
    ];


if (
    $hasVisibility
) {

    $updates[] =
        "profile_visibility = :profile_visibility";


    $params[
        ':profile_visibility'
    ] =
        $visibility;

}


if (
    $hasOnline
) {

    $updates[] =
        "show_online_status = :show_online_status";


    $params[
        ':show_online_status'
    ] =
        $showOnline;

}


if (
    $hasMessages
) {

    $updates[] =
        "allow_messages = :allow_messages";


    $params[
        ':allow_messages'
    ] =
        $allowMessages;

}


/* ============================================================
   UPDATE
============================================================ */

try {

    /*
     * The registration trigger creates the profile row.
     * This INSERT...ON DUPLICATE KEY UPDATE protects legacy
     * accounts that might not have a profile row.
     */

    $ensureStmt =
        $pdo->prepare(
            "
            INSERT INTO profiles
            (
                user_id
            )
            VALUES
            (
                :ensure_user_id
            )

            ON DUPLICATE KEY UPDATE
                user_id = user_id
            "
        );


    $ensureStmt->execute(
        [
            ':ensure_user_id' =>
                $userId
        ]
    );


    $sql =
        "
        UPDATE profiles

        SET
            "
        .
        implode(
            ",\n",
            $updates
        )
        .
        "

        WHERE user_id =
            :user_id

        LIMIT 1
        ";


    $stmt =
        $pdo->prepare(
            $sql
        );


    $stmt->execute(
        $params
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE PRIVACY] '
        .
        $e->getMessage()
    );


    privacyResponse(
        false,
        'Unable to save your privacy settings.',
        [
            'code' =>
                'PRIVACY_UPDATE_FAILED'
        ],
        500
    );
}


/* ============================================================
   READ BACK
============================================================ */

try {

    $readStmt =
        $pdo->prepare(
            "
            SELECT

                profile_visibility,
                show_online_status,
                allow_messages,
                updated_at

            FROM profiles

            WHERE user_id =
                :user_id

            LIMIT 1
            "
        );


    $readStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $saved =
        $readStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PRIVACY READBACK] '
        .
        $e->getMessage()
    );


    privacyResponse(
        true,
        'Privacy settings were saved.',
        [
            'saved' =>
                false
        ]
    );
}


/* ============================================================
   RESPONSE
============================================================ */

privacyResponse(
    true,
    'Your privacy settings have been saved successfully.',
    [

        'privacy' => [

            'profile_visibility' =>
                $saved[
                    'profile_visibility'
                ],

            'show_online_status' =>
                (int)
                $saved[
                    'show_online_status'
                ],

            'allow_messages' =>
                (int)
                $saved[
                    'allow_messages'
                ],

            'updated_at' =>
                $saved[
                    'updated_at'
                ]

        ]

    ]
);