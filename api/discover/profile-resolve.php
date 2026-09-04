<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/profile-code.php';


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


function resolveResponse(
    bool $success,
    string $message,
    array $data = [],
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
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    resolveResponse(
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
   SESSION
============================================================ */

if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();
}


$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    resolveResponse(
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
   CODE
============================================================ */

$profileCode =
    trim(
        (string)(
            $_GET['code']
            ??
            ''
        )
    );


if (
    $profileCode === ''
) {

    resolveResponse(
        false,
        'A profile code is required.',
        [
            'code' =>
                'PROFILE_CODE_REQUIRED'
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
        '[LOVEMI RESOLVE DB] '
        .
        $e->getMessage()
    );


    resolveResponse(
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
   CODE HASH
============================================================ */

$codeHash =
    hash(
        'sha256',
        $profileCode
    );


/* ============================================================
   LOOKUP
============================================================ */

$stmt =
    $pdo->prepare(
        "
        SELECT

            id,
            user_id,
            code_hash,
            encrypted_payload,
            version

        FROM profile_codes

        WHERE code_hash = :code_hash

        LIMIT 1
        "
    );


$stmt->execute(
    [
        ':code_hash' =>
            $codeHash
    ]
);


$row =
    $stmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !$row
) {

    resolveResponse(
        false,
        'The profile code is invalid.',
        [
            'code' =>
                'PROFILE_CODE_INVALID'
        ],
        404
    );
}


/* ============================================================
   DECRYPT
============================================================ */

$payload =
    lovemiDecryptProfilePayload(
        (string)$row['encrypted_payload']
    );


if (
    $payload === false
) {

    resolveResponse(
        false,
        'The profile code is invalid.',
        [
            'code' =>
                'PROFILE_CODE_DECRYPT_FAILED'
        ],
        404
    );
}


/* ============================================================
   VERSION
============================================================ */

$version =
    isset(
        $payload['version']
    )
        ?
        (int)$payload['version']
        :
        0;


if (
    $version !==
    LOVEMI_PROFILE_CODE_VERSION
) {

    resolveResponse(
        false,
        'The profile code is from an unsupported configuration.',
        [
            'code' =>
                'PROFILE_CODE_VERSION_INVALID'
        ],
        404
    );
}


/* ============================================================
   USER ID
============================================================ */

$userId =
    isset(
        $payload['user_id']
    )
        ?
        (int)$payload['user_id']
        :
        0;


if (
    $userId <= 0
) {

    resolveResponse(
        false,
        'The profile code does not contain a valid member.',
        [
            'code' =>
                'INVALID_PROFILE_ID'
        ],
        404
    );
}


/*
 * Protect against a modified encrypted payload.
 *
 * The encrypted payload must also contain the same public code
 * that was hashed for the database lookup.
 */

$payloadCode =
    (string)(
        $payload['code']
        ??
        ''
    );


if (
    $payloadCode === ''
    ||
    !hash_equals(
        $profileCode,
        $payloadCode
    )
) {

    resolveResponse(
        false,
        'The profile code is invalid.',
        [
            'code' =>
                'PROFILE_CODE_MISMATCH'
        ],
        404
    );
}


/*
 * Make sure the encrypted payload and the DB row identify the
 * exact same member.
 */

if (
    (int)$row['user_id']
    !==
    $userId
) {

    resolveResponse(
        false,
        'The profile code is invalid.',
        [
            'code' =>
                'PROFILE_CODE_USER_MISMATCH'
        ],
        404
    );
}


/* ============================================================
   TARGET MEMBER
============================================================ */

$stmt =
    $pdo->prepare(
        "
        SELECT

            u.id,
            u.account_status,
            u.email_verified,
            u.is_active,
            u.is_suspended,
            u.is_deleted,

            p.profile_visibility

        FROM users u

        LEFT JOIN profiles p
            ON p.user_id = u.id

        WHERE u.id = :user_id

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
    $stmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !$user
) {

    resolveResponse(
        false,
        'The requested profile could not be found.',
        [
            'code' =>
                'PROFILE_NOT_FOUND'
        ],
        404
    );
}


if (
    (int)$user['is_active'] !== 1
    ||
    (int)$user['is_suspended'] === 1
    ||
    (int)$user['is_deleted'] === 1
) {

    resolveResponse(
        false,
        'This profile is currently unavailable.',
        [
            'code' =>
                'PROFILE_UNAVAILABLE'
        ],
        403
    );
}


if (
    strtolower(
        trim(
            (string)$user['account_status']
        )
    )
    !==
    'approved'
) {

    resolveResponse(
        false,
        'This profile is not approved.',
        [
            'code' =>
                'PROFILE_NOT_APPROVED'
        ],
        403
    );
}


if (
    strtolower(
        trim(
            (string)(
                $user['profile_visibility']
                ??
                'public'
            )
        )
    )
    !==
    'public'
) {

    resolveResponse(
        false,
        'This profile is not public.',
        [
            'code' =>
                'PROFILE_NOT_PUBLIC'
        ],
        403
    );
}


/* ============================================================
   SUCCESS
============================================================ */

resolveResponse(
    true,
    'Profile code verified successfully.',
    [
        'user_id' =>
            $userId,

        'is_owner' =>
            $currentUserId === $userId,

        'code_valid' =>
            true
    ]
);