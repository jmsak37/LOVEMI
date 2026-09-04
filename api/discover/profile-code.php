<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/profile-code.php';


/* ============================================================
   HEADERS
============================================================ */

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


/* ============================================================
   RESPONSE
============================================================ */

function profileCodeResponse(
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

    profileCodeResponse(
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
   TARGET USER
============================================================ */

$targetUserId =
    isset(
        $_GET['user_id']
    )
        ?
        (int)
        $_GET['user_id']
        :
        0;


if (
    $targetUserId <= 0
) {

    profileCodeResponse(
        false,
        'A valid member is required.',
        [
            'code' =>
                'INVALID_USER_ID'
        ],
        422
    );
}


/*
 * Do not generate a Discover code for own profile.
 */
if (
    $targetUserId ===
    $currentUserId
) {

    profileCodeResponse(
        false,
        'Use your normal Profile link for your own profile.',
        [
            'code' =>
                'OWN_PROFILE'
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
        '[LOVEMI PROFILE CODE DB] '
        .
        $e->getMessage()
    );


    profileCodeResponse(
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
   TARGET PROFILE
============================================================ */

try {

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
                $targetUserId
        ]
    );


    $user =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE CODE USER] '
        .
        $e->getMessage()
    );


    profileCodeResponse(
        false,
        'Unable to verify this member.',
        [
            'code' =>
                'USER_QUERY_FAILED'
        ],
        500
    );
}


if (
    !$user
) {

    profileCodeResponse(
        false,
        'The requested member was not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   MEMBER VALIDATION
============================================================ */

if (
    (int)$user['is_active'] !== 1
    ||
    (int)$user['is_suspended'] === 1
    ||
    (int)$user['is_deleted'] === 1
) {

    profileCodeResponse(
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

    profileCodeResponse(
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

    profileCodeResponse(
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
   GENERATE PUBLIC CODE
============================================================ */

/*
 * The public code itself is random.
 *
 * Example:
 *
 *     4C1fK0... 
 *
 * There is no user ID inside the URL.
 */

$profileCode =
    lovemiBase64UrlEncode(
        random_bytes(
            32
        )
    );


/*
 * Hash used as the database lookup key.
 *
 * The original public code is never stored in plaintext.
 */

$codeHash =
    hash(
        'sha256',
        $profileCode
    );


/* ============================================================
   ENCRYPTED PAYLOAD
============================================================ */

$payload = [

    'version' =>
        LOVEMI_PROFILE_CODE_VERSION,

    'user_id' =>
        $targetUserId,

    'code' =>
        $profileCode,

    'created_at' =>
        gmdate(
            'Y-m-d H:i:s'
        ),

    'nonce' =>
        bin2hex(
            random_bytes(
                16
            )
        )

];


try {

    $encryptedPayload =
        lovemiEncryptProfilePayload(
            $payload
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE CODE ENCRYPT] '
        .
        $e->getMessage()
    );


    profileCodeResponse(
        false,
        'Unable to create a secure profile code.',
        [
            'code' =>
                'ENCRYPTION_ERROR'
        ],
        500
    );
}


/* ============================================================
   SAVE CODE
============================================================ */

try {

    /*
     * profile_codes.user_id is UNIQUE.
     *
     * Each new Discover click gives the member a fresh code.
     *
     * The browser receives only the public random code.
     *
     * The database stores the ID/code relationship.
     */

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO profile_codes
            (
                user_id,
                code_hash,
                encrypted_payload,
                version,
                created_at,
                updated_at
            )

            VALUES
            (
                :user_id,
                :code_hash,
                :encrypted_payload,
                :version,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP
            )

            ON DUPLICATE KEY UPDATE

                code_hash =
                    VALUES(code_hash),

                encrypted_payload =
                    VALUES(encrypted_payload),

                version =
                    VALUES(version),

                updated_at =
                    CURRENT_TIMESTAMP
            "
        );


    $stmt->execute(
        [
            ':user_id' =>
                $targetUserId,

            ':code_hash' =>
                $codeHash,

            ':encrypted_payload' =>
                $encryptedPayload,

            ':version' =>
                LOVEMI_PROFILE_CODE_VERSION
        ]
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE CODE SAVE] '
        .
        $e->getMessage()
    );


    profileCodeResponse(
        false,
        'The secure profile code could not be saved.',
        [
            'code' =>
                'PROFILE_CODE_SAVE_ERROR'
        ],
        500
    );
}


/* ============================================================
   SUCCESS
============================================================ */

profileCodeResponse(
    true,
    'Secure profile code created successfully.',
    [
        'profile_code' =>
            $profileCode,

        'version' =>
            LOVEMI_PROFILE_CODE_VERSION
    ]
);