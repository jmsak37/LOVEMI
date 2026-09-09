<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI SUPPORT TICKET 2FA VERIFICATION
|--------------------------------------------------------------------------
|
| File:
| C:\xampp\htdocs\LOVEMI\api\auth\mi-verify-2fa.php
|
| This endpoint is ONLY for opening a support ticket.
|
| Required:
|   - valid logged-in LOVEMI session
|   - valid support ticket token
|   - ticket must belong to logged-in account
|   - support email verification must already be complete
|   - Google Authenticator code must be valid
|
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../config/app.php';
require_once __DIR__ . '/../support/feedback/common.php';


/* ============================================================
   GOOGLE AUTHENTICATOR
============================================================ */

$autoload =
    __DIR__
    . '/google-authenticator/vendor/autoload.php';


if (!is_file($autoload)) {

    $autoload =
        __DIR__
        . '/vendor/autoload.php';

}


if (!is_file($autoload)) {

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    http_response_code(500);

    echo json_encode(
        [
            'success' => false,
            'message' =>
                'Google Authenticator library is not installed.',
            'code' =>
                'AUTHENTICATOR_LIBRARY_MISSING'
        ],
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;

}


require_once $autoload;

use Sonata\GoogleAuthenticator\GoogleAuthenticator;


/* ============================================================
   SESSION
============================================================ */

if (
    session_status() !==
    PHP_SESSION_ACTIVE
) {

    $isHttps =
        !empty($_SERVER['HTTPS'])
        &&
        strtolower(
            (string)$_SERVER['HTTPS']
        ) !==
        'off';


    session_set_cookie_params(
        [
            'lifetime' => 0,
            'path' => '/',
            'secure' => $isHttps,
            'httponly' => true,
            'samesite' => 'Lax'
        ]
    );


    session_start();

}


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

header(
    'X-Content-Type-Options: nosniff'
);


/* ============================================================
   RESPONSE
============================================================ */

function miOut(
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
   INPUT
============================================================ */

function miInput(): array
{

    $raw =
        file_get_contents(
            'php://input'
        )
        ?: '';


    if (
        trim($raw) !== ''
    ) {

        $json =
            json_decode(
                $raw,
                true
            );


        if (
            is_array($json)
        ) {

            return $json;

        }

    }


    return $_POST;

}


/* ============================================================
   CALLBACK
============================================================ */

function miSafeCallback(
    string $callback
): string {

    $callback =
        trim(
            $callback
        );


    if (
        $callback === ''
    ) {

        return '';


    }


    if (
        preg_match(
            '#^(https?:)?//#i',
            $callback
        )
    ) {

        return '';

    }


    if (
        str_contains(
            $callback,
            "\r"
        )
        ||
        str_contains(
            $callback,
            "\n"
        )
    ) {

        return '';

    }


    if (
        !str_starts_with(
            $callback,
            'Support-Ticket-Feedback.html'
        )
        &&
        !str_starts_with(
            $callback,
            '/LOVEMI/Support-Ticket-Feedback.html'
        )
    ) {

        return '';

    }


    return ltrim(
        $callback,
        '/'
    );

}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    miOut(
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

$input =
    miInput();


$token =
    trim(
        (string)(
            $input['token']
            ??
            ''
        )
    );


$code =
    preg_replace(
        '/\D/',
        '',
        (string)(
            $input['code']
            ??
            ''
        )
    );


$callback =
    miSafeCallback(
        (string)(
            $input['callback']
            ??
            ''
        )
    );


if (
    !preg_match(
        '/^\d{6}$/',
        $code
    )
) {

    miOut(
        false,
        'Enter the current six-digit Google Authenticator code.',
        [
            'code' =>
                'INVALID_2FA_CODE_FORMAT'
        ],
        422
    );

}


if (
    $token === ''
) {

    miOut(
        false,
        'The secure support ticket token is missing.',
        [
            'code' =>
                'SUPPORT_TOKEN_REQUIRED'
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


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    /*
     * Make sure support tables/columns exist.
     */
    fb_schema(
        $pdo
    );


    /* ========================================================
       CURRENT PHP SESSION
    ======================================================== */

    $uid =
        (int)(
            $_SESSION['lovemi_user_id']
            ??
            0
        );


    $sessionToken =
        trim(
            (string)(
                $_SESSION['lovemi_session_token']
                ??
                ''
            )
        );


    if (
        $uid <= 0
        ||
        $sessionToken === ''
    ) {

        miOut(
            false,
            'Please sign in to the LOVEMI account that owns this support ticket.',
            [
                'code' =>
                    'LOGIN_REQUIRED',

                'redirect' =>
                    'login.html?redirect='
                    .
                    rawurlencode(
                        'Support-Ticket-Feedback.html?token='
                        .
                        $token
                    )
            ],
            401
        );

    }


    /* ========================================================
       VERIFY DATABASE SESSION
    ======================================================== */

    $sessionStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                user_id,
                two_factor_passed,
                expires_at,
                revoked_at

            FROM user_sessions

            WHERE
                user_id = :user_id

                AND
                session_token_hash = :session_hash

            LIMIT 1
            "
        );


    $sessionStmt->execute(
        [
            ':user_id' =>
                $uid,

            ':session_hash' =>
                hash(
                    'sha256',
                    $sessionToken
                )
        ]
    );


    $session =
        $sessionStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$session
    ) {

        miOut(
            false,
            'Your LOVEMI login session could not be verified.',
            [
                'code' =>
                    'LOGIN_SESSION_INVALID'
            ],
            401
        );

    }


    if (
        !empty(
            $session['revoked_at']
        )
    ) {

        miOut(
            false,
            'Your LOVEMI login session has been revoked. Please sign in again.',
            [
                'code' =>
                    'LOGIN_SESSION_REVOKED'
            ],
            401
        );

    }


    if (
        !empty(
            $session['expires_at']
        )
        &&
        strtotime(
            (string)$session['expires_at']
        ) < time()
    ) {

        miOut(
            false,
            'Your LOVEMI login session has expired. Please sign in again.',
            [
                'code' =>
                    'LOGIN_SESSION_EXPIRED'
            ],
            401
        );

    }


    /* ========================================================
       FIND SUPPORT TICKET
    ======================================================== */

    $ticketStmt =
        $pdo->prepare(
            "
            SELECT

                a.id AS access_id,

                a.ticket_id,

                a.access_type,

                a.email_code_hash,

                a.email_code_expires_at,

                a.two_factor_attempts,

                a.two_factor_locked_until,

                t.user_id,

                t.status,

                t.subject,

                t.email

            FROM support_ticket_access a

            INNER JOIN support_tickets t
                ON t.id = a.ticket_id

            WHERE
                a.token_hash = :token_hash

            LIMIT 1
            "
        );


    $ticketStmt->execute(
        [
            ':token_hash' =>
                hash(
                    'sha256',
                    $token
                )
        ]
    );


    $ticket =
        $ticketStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$ticket
    ) {

        miOut(
            false,
            'This support ticket link is invalid or has expired.',
            [
                'code' =>
                    'INVALID_SUPPORT_LINK'
            ],
            404
        );

    }


    /* ========================================================
       ONLY ACCOUNT TICKETS
    ======================================================== */

    if (
        (string)$ticket['access_type']
        !==
        'account'
    ) {

        miOut(
            false,
            'This support ticket does not require account 2FA.',
            [
                'code' =>
                    'GUEST_TICKET'
            ],
            409
        );

    }


    /* ========================================================
       TICKET MUST BELONG TO CURRENT ACCOUNT
    ======================================================== */

    if (
        (int)$ticket['user_id']
        !==
        $uid
    ) {

        miOut(
            false,
            'This support ticket belongs to a different LOVEMI account.',
            [
                'code' =>
                    'SUPPORT_ACCOUNT_MISMATCH'
            ],
            403
        );

    }


    /* ========================================================
       CLOSED TICKET
    ======================================================== */

    if (
        strtolower(
            (string)$ticket['status']
        )
        ===
        'closed'
    ) {

        miOut(
            false,
            'This support conversation is already closed.',
            [
                'code' =>
                    'TICKET_CLOSED'
            ],
            409
        );

    }


    /* ========================================================
       EMAIL VERIFICATION REQUIRED
    ======================================================== */

    $accessId =
        (int)$ticket['access_id'];


    if (
        !fb_email_ok(
            $accessId
        )
    ) {

        miOut(
            false,
            'Complete the support email verification first.',
            [
                'code' =>
                    'EMAIL_VERIFICATION_REQUIRED'
            ],
            403
        );

    }


    /* ========================================================
       VERIFY USER ACCOUNT
    ======================================================== */

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                email,

                full_names,

                email_verified,

                is_active,

                is_suspended,

                is_deleted,

                two_factor_enabled,

                two_factor_secret_encrypted

            FROM users

            WHERE id = :id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':id' =>
                $uid
        ]
    );


    $user =
        $userStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$user
    ) {

        miOut(
            false,
            'The LOVEMI account could not be found.',
            [
                'code' =>
                    'USER_NOT_FOUND'
            ],
            404
        );

    }


    if (
        (int)$user['is_deleted'] === 1
        ||
        (int)$user['is_suspended'] === 1
        ||
        (int)$user['is_active'] !== 1
    ) {

        miOut(
            false,
            'This LOVEMI account is currently unavailable.',
            [
                'code' =>
                    'ACCOUNT_UNAVAILABLE'
            ],
            403
        );

    }


    if (
        (int)$user['email_verified'] !== 1
    ) {

        miOut(
            false,
            'Your LOVEMI account email must be verified first.',
            [
                'code' =>
                    'EMAIL_NOT_VERIFIED'
            ],
            403
        );

    }


    /* ========================================================
       2FA CONFIGURATION
    ======================================================== */

    if (
        (int)$user['two_factor_enabled'] !== 1
        ||
        trim(
            (string)$user[
                'two_factor_secret_encrypted'
            ]
        ) === ''
    ) {

        miOut(
            false,
            'Google Authenticator is not configured for this LOVEMI account.',
            [
                'code' =>
                    '2FA_NOT_CONFIGURED'
            ],
            409
        );

    }


    /* ========================================================
       RATE LIMIT
    ======================================================== */

    $lockedUntil =
        !empty(
            $ticket[
                'two_factor_locked_until'
            ]
        )
            ? strtotime(
                (string)$ticket[
                    'two_factor_locked_until'
                ]
            )
            : 0;


    if (
        $lockedUntil > time()
    ) {

        miOut(
            false,
            '2FA verification is temporarily locked because of repeated incorrect codes.',
            [
                'code' =>
                    '2FA_LOCKED',

                'retry_after' =>
                    $lockedUntil - time()
            ],
            429
        );

    }


    $attempts =
        (int)$ticket[
            'two_factor_attempts'
        ];


    if (
        $attempts >= 5
    ) {

        $pdo->prepare(
            "
            UPDATE support_ticket_access

            SET
                two_factor_locked_until =
                    DATE_ADD(
                        CURRENT_TIMESTAMP,
                        INTERVAL 15 MINUTE
                    )

            WHERE
                id = :id

            LIMIT 1
            "
        )->execute(
            [
                ':id' =>
                    $accessId
            ]
        );


        miOut(
            false,
            'Too many incorrect 2FA attempts. Verification is locked for 15 minutes.',
            [
                'code' =>
                    '2FA_LOCKED',

                'retry_after' =>
                    900
            ],
            429
        );

    }


    /* ========================================================
       DECRYPT AUTHENTICATOR SECRET
    ======================================================== */

    $encryptedSecret =
        trim(
            (string)$user[
                'two_factor_secret_encrypted'
            ]
        );


    $parts =
        explode(
            ':',
            $encryptedSecret,
            2
        );


    if (
        count($parts) !== 2
    ) {

        miOut(
            false,
            'The authenticator configuration is invalid.',
            [
                'code' =>
                    '2FA_SECRET_INVALID'
            ],
            500
        );

    }


    $iv =
        base64_decode(
            $parts[0],
            true
        );


    $encrypted =
        base64_decode(
            $parts[1],
            true
        );


    if (
        $iv === false
        ||
        $encrypted === false
        ||
        strlen($iv) !== 16
    ) {

        miOut(
            false,
            'The authenticator configuration could not be read.',
            [
                'code' =>
                    '2FA_SECRET_INVALID'
            ],
            500
        );

    }


    $secret =
        openssl_decrypt(
            $encrypted,
            'aes-256-cbc',
            getApplicationEncryptionKey(),
            OPENSSL_RAW_DATA,
            $iv
        );


    if (
        $secret === false
        ||
        trim(
            $secret
        ) === ''
    ) {

        miOut(
            false,
            'The authenticator configuration could not be decrypted.',
            [
                'code' =>
                    '2FA_SECRET_DECRYPT_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       GOOGLE AUTHENTICATOR
    ======================================================== */

    try {

        $google =
            new GoogleAuthenticator();


        /*
         * Allow a small amount of clock drift.
         *
         * This helps when the phone and XAMPP computer are
         * a little out of sync.
         */

        $valid =
            $google->checkCode(
                $secret,
                $code,
                2
            );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI SUPPORT 2FA CHECK] '
            .
            $e->getMessage()
        );


        miOut(
            false,
            'Unable to verify the Google Authenticator code right now.',
            [
                'code' =>
                    '2FA_CHECK_FAILED'
            ],
            500
        );

    }


    /* ========================================================
       INVALID CODE
    ======================================================== */

    if (
        !$valid
    ) {

        $newAttempts =
            $attempts + 1;


        if (
            $newAttempts >= 5
        ) {

            $pdo->prepare(
                "
                UPDATE support_ticket_access

                SET
                    two_factor_attempts = :attempts,

                    two_factor_locked_until =
                        DATE_ADD(
                            CURRENT_TIMESTAMP,
                            INTERVAL 15 MINUTE
                        )

                WHERE
                    id = :id

                LIMIT 1
                "
            )->execute(
                [
                    ':attempts' =>
                        $newAttempts,

                    ':id' =>
                        $accessId
                ]
            );


            miOut(
                false,
                'Too many incorrect 2FA attempts. Verification is locked for 15 minutes.',
                [
                    'code' =>
                        '2FA_LOCKED',

                    'attempts_remaining' =>
                        0,

                    'retry_after' =>
                        900
                ],
                422
            );

        }


        $pdo->prepare(
            "
            UPDATE support_ticket_access

            SET
                two_factor_attempts = :attempts

            WHERE
                id = :id

            LIMIT 1
            "
        )->execute(
            [
                ':attempts' =>
                    $newAttempts,

                ':id' =>
                    $accessId
            ]
        );


        miOut(
            false,
            'The Google Authenticator code is incorrect or expired.',
            [
                'code' =>
                    'INVALID_2FA_CODE',

                'attempts_remaining' =>
                    max(
                        0,
                        5 - $newAttempts
                    )
            ],
            422
        );

    }


    /* ========================================================
       SUCCESS
    ======================================================== */

    /*
     * Bind this verification to BOTH:
     *
     * 1. support access record
     * 2. current authenticated user
     */

    if (
        !isset(
            $_SESSION[
                'lovemi_support_email_verified'
            ]
        )
    ) {

        $_SESSION[
            'lovemi_support_email_verified'
        ] = [];

    }


    if (
        !isset(
            $_SESSION[
                'lovemi_support_2fa_verified'
            ]
        )
    ) {

        $_SESSION[
            'lovemi_support_2fa_verified'
        ] = [];

    }


    if (
        !isset(
            $_SESSION[
                'lovemi_support_2fa_ticket_id'
            ]
        )
    ) {

        $_SESSION[
            'lovemi_support_2fa_ticket_id'
        ] = [];

    }


    /*
     * 30 minute support authorization.
     */

    $_SESSION[
        'lovemi_support_2fa_verified'
    ][
        $accessId
    ] =
        time() + 1800;


    $_SESSION[
        'lovemi_support_2fa_ticket_id'
    ][
        $accessId
    ] =
        (int)$ticket['ticket_id'];


    $_SESSION[
        'lovemi_support_2fa_user_id'
    ][
        $accessId
    ] =
        $uid;


    /*
     * Reset failed attempts.
     */

    $pdo->prepare(
        "
        UPDATE support_ticket_access

        SET
            two_factor_attempts = 0,
            two_factor_locked_until = NULL

        WHERE
            id = :id

        LIMIT 1
        "
    )->execute(
        [
            ':id' =>
                $accessId
        ]
    );


    /*
     * Touch active database session.
     */

    try {

        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE
                id = :session_id

                AND
                user_id = :user_id

            LIMIT 1
            "
        )->execute(
            [
                ':session_id' =>
                    (int)$session['id'],

                ':user_id' =>
                    $uid
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI SUPPORT SESSION TOUCH] '
            .
            $e->getMessage()
        );

    }


    /*
     * Force PHP to write the support authorization
     * before the response is returned.
     */

    session_write_close();


    $redirect =
        'Support-Ticket-Feedback.html'
        .
        '?token='
        .
        rawurlencode(
            $token
        );


    miOut(
        true,
        'Two-step verification successful. Opening your support conversation.',
        [
            'access_granted' =>
                true,

            'ticket_id' =>
                (int)$ticket[
                    'ticket_id'
                ],

            'redirect' =>
                $redirect
        ],
        200
    );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SUPPORT MI 2FA ERROR] '
        .
        $e->getMessage()
    );


    miOut(
        false,
        'Unable to verify your Google Authenticator code right now.',
        [
            'code' =>
                'SERVER_ERROR'
        ],
        500
    );

}