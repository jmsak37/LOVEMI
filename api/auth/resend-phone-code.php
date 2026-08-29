<?php
/**
 * ============================================================
 * LOVEMI - RESEND PHONE VERIFICATION CODE
 * ============================================================
 *
 * NOTE:
 * This file generates and stores the SMS code.
 *
 * Actual SMS delivery requires an SMS provider.
 * Do not pretend delivery succeeded if no provider is configured.
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function resendPhoneResponse(
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

    resendPhoneResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
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
        ? (int)
          $data['user_id']
        : 0;


if (
    $userId <= 0
) {

    resendPhoneResponse(
        false,
        'Invalid account.',
        [
            'code' =>
                'INVALID_USER'
        ],
        422
    );
}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI RESEND PHONE DB ERROR] '
        . $e->getMessage()
    );

    resendPhoneResponse(
        false,
        'Phone verification is temporarily unavailable.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   USER
============================================================ */

$stmt =
    $pdo->prepare(
        "
        SELECT

            id,
            full_names,
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


$stmt->execute(
    [
        ':user_id' =>
            $userId
    ]
);


$user =
    $stmt->fetch();


if (!$user) {

    resendPhoneResponse(
        false,
        'Account not found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );
}


/* ============================================================
   ALREADY VERIFIED
============================================================ */

if (
    (bool)
    $user['phone_verified']
) {

    resendPhoneResponse(
        false,
        'Your phone is already verified.',
        [
            'code' =>
                'ALREADY_VERIFIED'
        ],
        409
    );
}


/* ============================================================
   ACCOUNT CHECK
============================================================ */

if (
    (bool) $user['is_deleted']
    ||
    (bool) $user['is_suspended']
    ||
    !(bool) $user['is_active']
) {

    resendPhoneResponse(
        false,
        'This account is not available.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}


/* ============================================================
   RATE LIMIT
============================================================ */

$recentStmt =
    $pdo->prepare(
        "
        SELECT id

        FROM verifications

        WHERE user_id = :user_id

          AND verification_type =
              'phone_registration'

          AND created_at >
              DATE_SUB(
                  CURRENT_TIMESTAMP,
                  INTERVAL 60 SECOND
              )

        ORDER BY id DESC

        LIMIT 1
        "
    );


$recentStmt->execute(
    [
        ':user_id' =>
            $userId
    ]
);


if (
    $recentStmt->fetch()
) {

    resendPhoneResponse(
        false,
        'Please wait at least 60 seconds before requesting another phone code.',
        [
            'code' =>
                'RESEND_TOO_SOON'
        ],
        429
    );
}


/* ============================================================
   INVALIDATE OLD CODES
============================================================ */

try {

    $pdo->beginTransaction();


    $invalidateStmt =
        $pdo->prepare(
            "
            UPDATE verifications

            SET
                blocked_at =
                    CURRENT_TIMESTAMP

            WHERE user_id =
                :user_id

              AND verification_type =
                  'phone_registration'

              AND verified_at IS NULL

              AND blocked_at IS NULL
            "
        );


    $invalidateStmt->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /* ========================================================
       GENERATE NEW CODE
    ======================================================== */

    $code =
        str_pad(
            (string)
            random_int(
                0,
                999999
            ),
            6,
            '0',
            STR_PAD_LEFT
        );


    $codeHash =
        hash(
            'sha256',
            $code
        );


    $expiresAt =
        date(
            'Y-m-d H:i:s',
            time() + 10 * 60
        );


    $insertStmt =
        $pdo->prepare(
            "
            INSERT INTO verifications
            (
                user_id,
                phone_e164,
                verification_type,
                code_hash,
                attempt_count,
                send_count,
                expires_at
            )
            VALUES
            (
                :user_id,
                :phone_e164,
                'phone_registration',
                :code_hash,
                0,
                1,
                :expires_at
            )
            "
        );


    $insertStmt->execute(
        [
            ':user_id' =>
                $userId,

            ':phone_e164' =>
                $user['phone_e164'],

            ':code_hash' =>
                $codeHash,

            ':expires_at' =>
                $expiresAt
        ]
    );


    $pdo->commit();


} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }


    error_log(
        '[LOVEMI RESEND PHONE TRANSACTION ERROR] '
        . $e->getMessage()
    );


    resendPhoneResponse(
        false,
        'Unable to generate a new phone verification code.',
        [
            'code' =>
                'CODE_GENERATION_ERROR'
        ],
        500
    );
}


/* ============================================================
   SMS DELIVERY CONFIGURATION
============================================================ */

/*
 * We deliberately do not fake SMS delivery.
 *
 * When we create:
 *
 * services/sms/sms-service.php
 *
 * this endpoint can call it here.
 */

$smsEnabled =
    getenv(
        'LOVEMI_SMS_ENABLED'
    );


$smsEnabled =
    is_string($smsEnabled)
    &&
    in_array(
        strtolower(
            trim($smsEnabled)
        ),
        [
            '1',
            'true',
            'yes',
            'on'
        ],
        true
    );


if (!$smsEnabled) {

    /*
     * The code exists in the DB, but the server does not have
     * an SMS provider configured.
     */

    error_log(
        '[LOVEMI SMS DELIVERY NOT CONFIGURED] '
        . 'Verification code generated for user ID '
        . $userId
        . '. Configure an SMS provider before production.'
    );


    resendPhoneResponse(
        false,
        'The phone verification code was created, but SMS delivery is not configured on this server.',
        [
            'code' =>
                'SMS_DELIVERY_NOT_CONFIGURED'
        ],
        503
    );
}


/* ============================================================
   PLACEHOLDER FOR SMS PROVIDER
============================================================ */

/*
 * We intentionally stop here until an actual SMS provider is
 * configured.
 *
 * Example providers can later be connected through:
 *
 * services/sms/sms-service.php
 *
 * That service should expose something such as:
 *
 * sendSms($user['phone_e164'], $message)
 *
 * without exposing the verification code elsewhere.
 */


/* ============================================================
   DEFAULT FAILURE
============================================================ */

resendPhoneResponse(
    false,
    'SMS delivery service is not configured.',
    [
        'code' =>
            'SMS_PROVIDER_REQUIRED'
    ],
    503
);