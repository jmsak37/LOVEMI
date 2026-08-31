<?php
/**
 * ============================================================
 * LOVEMI - VERIFY PHONE
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function verifyPhoneResponse(
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
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    exit;
}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    verifyPhoneResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$data =
    json_decode(
        $raw ?: '{}',
        true
    );


if (!is_array($data)) {
    $data = [];
}


$userId =
    isset($data['user_id'])
        ? (int) $data['user_id']
        : 0;


$code =
    preg_replace(
        '/[^0-9]/',
        '',
        (string) (
            $data['code']
            ?? ''
        )
    );


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI VERIFY PHONE DB ERROR] '
        . $e->getMessage()
    );

    verifyPhoneResponse(
        false,
        'Phone verification is temporarily unavailable.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER
============================================================ */

$userStmt =
    $pdo->prepare(
        "
        SELECT

            id,
            full_names,
            email,
            phone_e164,
            email_verified,
            phone_verified,
            account_status,
            is_active,
            is_suspended,
            is_deleted

        FROM users

        WHERE id = :user_id

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


if (!$user) {

    verifyPhoneResponse(
        false,
        'The account could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   SAFE ACCOUNT
============================================================ */

function safePhoneVerificationAccount(
    array $user
): array {

    $phone =
        (string)
        ($user['phone_e164'] ?? '');


    return [

        'id' =>
            (int)
            $user['id'],

        'full_name' =>
            (string)
            $user['full_names'],

        'email' =>
            (string)
            $user['email'],

        'phone_last4' =>
            strlen($phone) >= 4
                ? substr($phone, -4)
                : null

    ];
}


/* ============================================================
   STATUS REQUEST
============================================================ */

if ($code === '') {

    verifyPhoneResponse(
        true,
        'Verification status loaded.',
        [
            'email_verified' =>
                (bool)
                $user['email_verified'],

            'phone_verified' =>
                (bool)
                $user['phone_verified'],

            'account_completed' =>
                (
                    (bool)
                    $user['email_verified']
                    &&
                    (bool)
                    $user['phone_verified']
                    &&
                    $user['account_status']
                        === 'approved'
                ),

            'account' =>
                safePhoneVerificationAccount(
                    $user
                )
        ]
    );
}


/* ============================================================
   CODE FORMAT
============================================================ */

if (
    !preg_match(
        '/^\d{6}$/',
        $code
    )
) {

    verifyPhoneResponse(
        false,
        'Enter the 6-digit phone verification code.',
        [
            'code' =>
                'INVALID_CODE_FORMAT'
        ],
        422
    );
}


/* ============================================================
   ALREADY VERIFIED
============================================================ */

if (
    (bool)
    $user['phone_verified']
) {

    verifyPhoneResponse(
        true,
        'Your phone is already verified.',
        [
            'email_verified' =>
                (bool)
                $user['email_verified'],

            'phone_verified' =>
                true,

            'account' =>
                safePhoneVerificationAccount(
                    $user
                )
        ]
    );
}


/* ============================================================
   LATEST PHONE CODE
============================================================ */

$verificationStmt =
    $pdo->prepare(
        "
        SELECT

            id,
            code_hash,
            attempt_count,
            expires_at,
            verified_at,
            blocked_at

        FROM verifications

        WHERE user_id =
            :user_id

          AND verification_type =
            'phone_registration'

        ORDER BY id DESC

        LIMIT 1
        "
    );


$verificationStmt->execute(
    [
        ':user_id' =>
            $userId
    ]
);


$verification =
    $verificationStmt->fetch();


if (!$verification) {

    verifyPhoneResponse(
        false,
        'No phone verification code is available. Please request a new code.',
        [
            'code' =>
                'NO_CODE'
        ],
        422
    );
}


/* ============================================================
   BLOCKED
============================================================ */

if (
    $verification['blocked_at'] !== null
) {

    verifyPhoneResponse(
        false,
        'This verification attempt has been blocked. Request a new code.',
        [
            'code' =>
                'CODE_BLOCKED'
        ],
        429
    );
}


/* ============================================================
   ALREADY VERIFIED CODE
============================================================ */

if (
    $verification['verified_at'] !== null
) {

    verifyPhoneResponse(
        true,
        'Your phone is already verified.',
        [
            'email_verified' =>
                (bool)
                $user['email_verified'],

            'phone_verified' =>
                true,

            'account' =>
                safePhoneVerificationAccount(
                    $user
                )
        ]
    );
}


/* ============================================================
   EXPIRATION
============================================================ */

$expires =
    strtotime(
        (string)
        $verification['expires_at']
    );


if (
    $expires === false
    ||
    $expires <= time()
) {

    verifyPhoneResponse(
        false,
        'This phone verification code has expired. Please request a new code.',
        [
            'code' =>
                'CODE_EXPIRED'
        ],
        422
    );
}


/* ============================================================
   ATTEMPTS
============================================================ */

$attempts =
    (int)
    $verification['attempt_count'];


$maxAttempts =
    5;


if (
    $attempts >= $maxAttempts
) {

    $blockStmt =
        $pdo->prepare(
            "
            UPDATE verifications

            SET blocked_at =
                CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $blockStmt->execute(
        [
            ':id' =>
                (int)
                $verification['id']
        ]
    );


    verifyPhoneResponse(
        false,
        'Too many incorrect attempts. Please request a new code.',
        [
            'code' =>
                'TOO_MANY_ATTEMPTS'
        ],
        429
    );
}


/* ============================================================
   HASH CHECK
============================================================ */

$submittedHash =
    hash(
        'sha256',
        $code
    );


if (
    !hash_equals(
        (string)
        $verification['code_hash'],
        $submittedHash
    )
) {

    $newAttemptCount =
        $attempts + 1;


    $updateAttempt =
        $pdo->prepare(
            "
            UPDATE verifications

            SET attempt_count =
                :attempt_count

            WHERE id = :id

            LIMIT 1
            "
        );


    $updateAttempt->execute(
        [
            ':attempt_count' =>
                $newAttemptCount,

            ':id' =>
                (int)
                $verification['id']
        ]
    );


    if (
        $newAttemptCount >=
        $maxAttempts
    ) {

        $blockStmt =
            $pdo->prepare(
                "
                UPDATE verifications

                SET blocked_at =
                    CURRENT_TIMESTAMP

                WHERE id = :id

                LIMIT 1
                "
            );


        $blockStmt->execute(
            [
                ':id' =>
                    (int)
                    $verification['id']
            ]
        );


        verifyPhoneResponse(
            false,
            'Too many incorrect attempts. Please request a new code.',
            [
                'code' =>
                    'TOO_MANY_ATTEMPTS'
            ],
            429
        );
    }


    verifyPhoneResponse(
        false,
        'The phone verification code is incorrect.',
        [
            'code' =>
                'INCORRECT_CODE',

            'attempts_remaining' =>
                max(
                    0,
                    $maxAttempts -
                    $newAttemptCount
                )
        ],
        422
    );
}


/* ============================================================
   VERIFY PHONE
============================================================ */

try {

    $pdo->beginTransaction();


    $verifyCode =
        $pdo->prepare(
            "
            UPDATE verifications

            SET verified_at =
                CURRENT_TIMESTAMP

            WHERE id = :id

            LIMIT 1
            "
        );


    $verifyCode->execute(
        [
            ':id' =>
                (int)
                $verification['id']
        ]
    );


    $userUpdate =
        $pdo->prepare(
            "
            UPDATE users

            SET phone_verified = TRUE

            WHERE id = :user_id

            LIMIT 1
            "
        );


    $userUpdate->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
     * Only approve after BOTH email and phone are verified.
     */

    $completionStmt =
        $pdo->prepare(
            "
            UPDATE users

            SET account_status =
                CASE
                    WHEN email_verified = TRUE
                     AND phone_verified = TRUE
                    THEN 'approved'
                    ELSE account_status
                END

            WHERE id = :user_id

            LIMIT 1
            "
        );


    $completionStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    $pdo->commit();


} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }


    error_log(
        '[LOVEMI VERIFY PHONE TRANSACTION ERROR] '
        . $e->getMessage()
    );


    verifyPhoneResponse(
        false,
        'Unable to complete phone verification.',
        [
            'code' =>
                'VERIFICATION_ERROR'
        ],
        500
    );
}


/* ============================================================
   FINAL STATUS
============================================================ */

$finalStmt =
    $pdo->prepare(
        "
        SELECT

            full_names,
            email,
            phone_e164,
            email_verified,
            phone_verified,
            account_status

        FROM users

        WHERE id = :user_id

        LIMIT 1
        "
    );


$finalStmt->execute(
    [
        ':user_id' =>
            $userId
    ]
);


$final =
    $finalStmt->fetch();


$complete =
    (
        (bool)
        $final['email_verified']

        &&

        (bool)
        $final['phone_verified']

        &&

        $final['account_status']
            === 'approved'
    );


verifyPhoneResponse(
    true,
    $complete
        ? 'Phone verified. Your LOVEMI account is now fully verified.'
        : 'Phone verified successfully. Please verify your email.',
    [
        'email_verified' =>
            (bool)
            $final['email_verified'],

        'phone_verified' =>
            (bool)
            $final['phone_verified'],

        'account_completed' =>
            $complete,

        'account' =>
            safePhoneVerificationAccount(
                array_merge(
                    $final,
                    [
                        'id' =>
                            $userId
                    ]
                )
            )
    ]
);