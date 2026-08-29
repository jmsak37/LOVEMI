<?php
/**
 * ============================================================
 * LOVEMI - GOOGLE AUTHENTICATOR VERIFICATION
 * ============================================================
 *
 * setup=true
 *     -> finish initial 2FA configuration
 *
 * setup=false
 *     -> complete login
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   LOAD FILES
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


require_once
    __DIR__
    . '/../../config/app.php';


$autoload =
    __DIR__
    . '/vendor/autoload.php';


if (
    !is_file($autoload)
) {

    http_response_code(500);


    header(
        'Content-Type: application/json; charset=utf-8'
    );


    echo json_encode(
        [
            'success' =>
                false,

            'message' =>
                'Google Authenticator library is not installed.'
        ]
    );


    exit;
}


require_once $autoload;


use Sonata\GoogleAuthenticator\GoogleAuthenticator;


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
   SESSION
============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' =>
            0,

        'path' =>
            '/',

        'secure' =>
            $isHttps,

        'httponly' =>
            true,

        'samesite' =>
            'Lax'
    ]
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

function verify2FAResponse(
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
        JSON_UNESCAPED_UNICODE
        |
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
    'POST'
) {

    verify2FAResponse(
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

$data =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data = [];

}


$code =
    preg_replace(
        '/[^0-9]/',
        '',
        (string)
        (
            $data['code']
            ??
            ''
        )
    );


$setup =
    filter_var(
        $data['setup']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


/* ============================================================
   CODE VALIDATION
============================================================ */

if (
    !preg_match(
        '/^\d{6}$/',
        $code
    )
) {

    verify2FAResponse(
        false,
        'Enter the current six-digit Google Authenticator code.',
        [
            'code' =>
                'INVALID_2FA_CODE_FORMAT'
        ],
        422
    );

}


/* ============================================================
   DETERMINE USER
============================================================ */

$setupUserId =
    isset(
        $_SESSION[
            'lovemi_2fa_setup_user_id'
        ]
    )
        ? (int)
          $_SESSION[
              'lovemi_2fa_setup_user_id'
          ]
        : 0;


$pendingUserId =
    isset(
        $_SESSION[
            'lovemi_2fa_pending_user_id'
        ]
    )
        ? (int)
          $_SESSION[
              'lovemi_2fa_pending_user_id'
          ]
        : 0;


$authenticatedUserId =
    isset(
        $_SESSION[
            'lovemi_user_id'
        ]
    )
        ? (int)
          $_SESSION[
              'lovemi_user_id'
          ]
        : 0;


if (
    $setup
) {

    $userId =
        $setupUserId;

} else {

    $userId =
        $pendingUserId
        >
        0
            ? $pendingUserId
            :
            $authenticatedUserId;

}


if (
    $userId <= 0
) {

    verify2FAResponse(
        false,
        'Your verification session has expired. Please start again.',
        [
            'code' =>
                '2FA_SESSION_EXPIRED'
        ],
        401
    );

}


/* ============================================================
   SETUP SESSION EXPIRY
============================================================ */

if (
    $setup
    &&
    $setupUserId > 0
) {

    $created =
        isset(
            $_SESSION[
                'lovemi_2fa_setup_created_at'
            ]
        )
            ? (int)
              $_SESSION[
                  'lovemi_2fa_setup_created_at'
              ]
            : 0;


    if (
        $created <= 0
        ||
        (
            time()
            -
            $created
        )
        >
        30 * 60
    ) {

        unset(
            $_SESSION[
                'lovemi_2fa_setup_user_id'
            ],
            $_SESSION[
                'lovemi_2fa_setup_created_at'
            ]
        );


        verify2FAResponse(
            false,
            'Your Google Authenticator setup session has expired. Please verify your email again.',
            [
                'code' =>
                    'SETUP_SESSION_EXPIRED'
            ],
            401
        );

    }

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.email_verified,

                u.account_status,

                u.two_factor_enabled,

                u.two_factor_secret_encrypted,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                r.slug AS role_slug

            FROM users u

            LEFT JOIN roles r
                ON r.id = u.role_id

            WHERE u.id =
                :user_id

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


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFY 2FA DB ERROR] '
        .
        $e->getMessage()
    );


    verify2FAResponse(
        false,
        'Unable to verify your authenticator.',
        [],
        500
    );

}


if (
    !$user
) {

    verify2FAResponse(
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
   ACCOUNT STATE
============================================================ */

if (
    (bool)
    $user['is_deleted']
    ||
    (bool)
    $user['is_suspended']
    ||
    !(bool)
    $user['is_active']
) {

    verify2FAResponse(
        false,
        'This account is currently unavailable.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );

}


/* ============================================================
   EMAIL
============================================================ */

if (
    !(bool)
    $user['email_verified']
) {

    verify2FAResponse(
        false,
        'Please verify your email first.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED'
        ],
        403
    );

}


/* ============================================================
   SECRET
============================================================ */

if (
    empty(
        $user['two_factor_secret_encrypted']
    )
) {

    verify2FAResponse(
        false,
        'Google Authenticator has not been configured yet.',
        [
            'code' =>
                '2FA_NOT_CONFIGURED'
        ],
        409
    );

}


/* ============================================================
   DECRYPT SECRET
============================================================ */

try {

    $parts =
        explode(
            ':',
            (string)
            $user['two_factor_secret_encrypted'],
            2
        );


    if (
        count($parts) !== 2
    ) {

        throw new RuntimeException(
            'Invalid encrypted secret.'
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
    ) {

        throw new RuntimeException(
            'Invalid encrypted data.'
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

        throw new RuntimeException(
            'Unable to decrypt secret.'
        );

    }


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI 2FA DECRYPTION ERROR] '
        .
        $e->getMessage()
    );


    verify2FAResponse(
        false,
        'Unable to access your authenticator configuration.',
        [],
        500
    );

}


/* ============================================================
   CHECK AUTHENTICATOR CODE
============================================================ */

try {

    $google =
        new GoogleAuthenticator();


    $valid =
        $google->checkCode(
            $secret,
            $code
        );


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI 2FA CHECK ERROR] '
        .
        $e->getMessage()
    );


    verify2FAResponse(
        false,
        'Unable to verify your authenticator code.',
        [],
        500
    );

}


if (
    !$valid
) {

    verify2FAResponse(
        false,
        'The Google Authenticator code is incorrect or expired.',
        [
            'code' =>
                'INVALID_2FA_CODE'
        ],
        422
    );

}


/* ============================================================
   SETUP MODE
============================================================ */

if (
    $setup
) {

    try {

        $pdo->beginTransaction();


        $update =
            $pdo->prepare(
                "
                UPDATE users

                SET

                    two_factor_enabled =
                        TRUE,

                    two_factor_verified_at =
                        CURRENT_TIMESTAMP

                WHERE id = :user_id

                LIMIT 1
                "
            );


        $update->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $pdo->commit();


    } catch (
        Throwable $e
    ) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        error_log(
            '[LOVEMI ENABLE 2FA ERROR] '
            .
            $e->getMessage()
        );


        verify2FAResponse(
            false,
            'Unable to enable Google Authenticator.',
            [],
            500
        );

    }


    unset(
        $_SESSION[
            'lovemi_2fa_setup_user_id'
        ],
        $_SESSION[
            'lovemi_2fa_setup_created_at'
        ]
    );


    verify2FAResponse(
        true,
        'Google Authenticator has been enabled successfully. Your account is now protected with two-step verification.',
        [
            'two_factor_enabled' =>
                true,

            'setup_completed' =>
                true,

            'redirect' =>
                'login.html'
        ]
    );

}


/* ============================================================
   LOGIN MODE
============================================================ */

$databaseSessionId =
    isset(
        $_SESSION[
            'lovemi_database_session_id'
        ]
    )
        ? (int)
          $_SESSION[
              'lovemi_database_session_id'
          ]
        : 0;


if (
    $databaseSessionId <= 0
) {

    verify2FAResponse(
        false,
        'Your login session could not be found. Please log in again.',
        [
            'code' =>
                'SESSION_NOT_FOUND'
        ],
        401
    );

}


/* ============================================================
   FINALIZE SESSION
============================================================ */

try {

    $pdo->beginTransaction();


    $sessionStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET

                two_factor_passed =
                    TRUE,

                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE id = :session_id

              AND user_id = :user_id

              AND revoked_at IS NULL

              AND expires_at >
                  CURRENT_TIMESTAMP

            LIMIT 1
            "
        );


    $sessionStmt->execute(
        [
            ':session_id' =>
                $databaseSessionId,

            ':user_id' =>
                $userId
        ]
    );


    if (
        $sessionStmt->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'SESSION_NOT_UPDATED'
        );

    }


    $userUpdate =
        $pdo->prepare(
            "
            UPDATE users

            SET last_seen_at =
                CURRENT_TIMESTAMP

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


    $pdo->commit();


} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI COMPLETE LOGIN 2FA ERROR] '
        .
        $e->getMessage()
    );


    verify2FAResponse(
        false,
        'Unable to complete your login.',
        [],
        500
    );

}


/* ============================================================
   SESSION
============================================================ */

$_SESSION[
    'lovemi_user_id'
] =
    $userId;


$_SESSION[
    'lovemi_role_slug'
] =
    strtolower(
        trim(
            (string)
            (
                $user['role_slug']
                ??
                ''
            )
        )
    );


unset(
    $_SESSION[
        'lovemi_2fa_pending_user_id'
    ]
);


/* ============================================================
   ADMIN / MEMBER DESTINATION
============================================================ */

$roleSlug =
    $_SESSION[
        'lovemi_role_slug'
    ];


$isAdmin =
    in_array(
        $roleSlug,
        [
            'admin',
            'administrator',
            'moderator',
            'support'
        ],
        true
    );


$redirect =
    $isAdmin
        ?
        'admin/dashboard.html'
        :
        'dashboard.html';


/* ============================================================
   RESPONSE
============================================================ */

verify2FAResponse(
    true,
    'Two-step verification successful. Welcome to LOVEMI.',
    [
        'authenticated' =>
            true,

        'two_factor_passed' =>
            true,

        'role' =>
            $roleSlug,

        'redirect' =>
            $redirect
    ]
);