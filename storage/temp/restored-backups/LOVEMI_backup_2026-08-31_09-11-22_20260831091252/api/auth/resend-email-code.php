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


function resendEmailResponse(
    bool $success,
    string $message,
    array $extra = [],
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
            $extra
        ),
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    exit;
}


if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'POST'
) {

    resendEmailResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


$data =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
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

    resendEmailResponse(
        false,
        'Invalid account.',
        [],
        422
    );

}


try {

    $pdo =
        db();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,
                full_names,
                email,
                email_verified,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $user =
        $stmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI RESEND EMAIL DB ERROR] '
        . $e->getMessage()
    );


    resendEmailResponse(
        false,
        'Unable to resend the verification code.',
        [],
        500
    );

}


if (!$user) {

    resendEmailResponse(
        false,
        'Account not found.',
        [],
        404
    );

}


if (
    (bool)
    $user['email_verified']
) {

    resendEmailResponse(
        false,
        'Your email is already verified.',
        [],
        409
    );

}


if (
    !(bool) $user['is_active']
    ||
    (bool) $user['is_suspended']
    ||
    (bool) $user['is_deleted']
) {

    resendEmailResponse(
        false,
        'This account is unavailable.',
        [],
        403
    );

}


/* ============================================================
   RATE LIMIT
============================================================ */

$recent =
    $pdo->prepare(
        "
        SELECT id

        FROM verifications

        WHERE user_id = :user_id

          AND verification_type =
              'email_registration'

          AND created_at >
              DATE_SUB(
                  CURRENT_TIMESTAMP,
                  INTERVAL 60 SECOND
              )

        ORDER BY id DESC

        LIMIT 1
        "
    );


$recent->execute(
    [
        ':user_id' =>
            $userId
    ]
);


if (
    $recent->fetch()
) {

    resendEmailResponse(
        false,
        'Please wait 60 seconds before requesting another code.',
        [
            'code' =>
                'RESEND_TOO_SOON'
        ],
        429
    );

}


/* ============================================================
   CREATE NEW CODE
============================================================ */

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
        time() + 600
    );


try {

    $pdo->beginTransaction();


    /*
     * Invalidate old verification codes.
     */

    $invalidate =
        $pdo->prepare(
            "
            UPDATE verifications

            SET blocked_at =
                CURRENT_TIMESTAMP

            WHERE user_id = :user_id

              AND verification_type =
                  'email_registration'

              AND verified_at IS NULL

              AND blocked_at IS NULL
            "
        );


    $invalidate->execute(
        [
            ':user_id' =>
                $userId
        ]
    );


    /*
     * Save only hash.
     */

    $insert =
        $pdo->prepare(
            "
            INSERT INTO verifications
            (
                user_id,
                email,
                verification_type,
                code_hash,
                attempt_count,
                send_count,
                expires_at
            )
            VALUES
            (
                :user_id,
                :email,
                'email_registration',
                :code_hash,
                0,
                1,
                :expires_at
            )
            "
        );


    $insert->execute(
        [
            ':user_id' =>
                $userId,

            ':email' =>
                $user['email'],

            ':code_hash' =>
                $codeHash,

            ':expires_at' =>
                $expiresAt
        ]
    );


    $pdo->commit();


} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI RESEND EMAIL TRANSACTION ERROR] '
        . $e->getMessage()
    );


    resendEmailResponse(
        false,
        'Unable to create another verification code.',
        [],
        500
    );

}


/* ============================================================
   SEND EMAIL
============================================================ */

try {

    require_once
        __DIR__
        . '/../../services/email/email-service.php';


    $sent =
        sendLovemiVerificationEmail(
            $user['email'],
            $user['full_names'],
            $code
        );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI EMAIL DELIVERY ERROR] '
        . $e->getMessage()
    );


    $sent =
        false;

}


if (!$sent) {

    resendEmailResponse(
        false,
        'The verification email could not be delivered. Please check your email configuration.',
        [
            'code' =>
                'EMAIL_DELIVERY_FAILED'
        ],
        503
    );

}


resendEmailResponse(
    true,
    'A new verification code has been sent to your email.',
    [
        'code' =>
            'EMAIL_CODE_SENT',

        'expires_in_seconds' =>
            600
    ]
);