<?php
/**
 * ============================================================
 * LOVEMI - LOGIN API
 * ============================================================
 *
 * LOGIN FLOW
 *
 * 1. Username/email + password
 * 2. Email must be verified
 * 3. Google Authenticator:
 *
 *      a. Not configured
 *         -> 2FA setup
 *
 *      b. Already configured
 *         -> 2FA code
 *
 * 4. Only after 2FA:
 *      -> fully authenticated session
 *
 * IMPORTANT:
 *
 * A password-verified session is NOT a fully authenticated
 * session.
 *
 * The session becomes authenticated only when:
 *
 * user_sessions.two_factor_passed = TRUE
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ . '/../../config/database.php';


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
   SESSION COOKIE SETTINGS
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


/* ============================================================
   START SESSION
============================================================ */

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

function loginResponse(
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
        |
        JSON_UNESCAPED_UNICODE
    );


    exit;
}


/* ============================================================
   REQUEST METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    loginResponse(
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
   JSON BODY
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


$data =
    json_decode(
        $rawBody ?: '{}',
        true
    );


if (
    !is_array($data)
) {

    $data = [];

}


/* ============================================================
   INPUT
============================================================ */

$identifier =
    trim(
        (string) (
            $data['identifier']
            ??
            ''
        )
    );


$password =
    (string) (
        $data['password']
        ??
        ''
    );


$remember =
    filter_var(
        $data['remember']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    $identifier === ''
    ||
    $password === ''
) {

    loginResponse(
        false,
        'Please enter your username/email and password.',
        [
            'code' =>
                'LOGIN_FIELDS_REQUIRED'
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


} catch (Throwable $e) {

    error_log(
        '[LOVEMI LOGIN DATABASE ERROR] '
        .
        $e->getMessage()
    );


    loginResponse(
        false,
        'The login service is temporarily unavailable.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   FIND USER
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.role_id,

                u.username,

                u.full_names,

                u.gender,

                u.email,

                u.country_id,

                u.password_hash,

                u.account_status,

                u.email_verified,

                u.is_active,

                u.is_suspended,

                u.is_deleted,

                u.two_factor_enabled,

                u.two_factor_secret_encrypted,

                r.slug AS role_slug,

                c.name AS country_name,

                c.iso2 AS country_iso2

            FROM users u

            LEFT JOIN roles r
                ON r.id = u.role_id

            LEFT JOIN countries c
                ON c.id = u.country_id

            WHERE

                LOWER(u.username) =
                    LOWER(:identifier_username)

                OR

                LOWER(u.email) =
                    LOWER(:identifier_email)

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':identifier_username' =>
                $identifier,

            ':identifier_email' =>
                $identifier
        ]
    );


    $user =
        $stmt->fetch();


} catch (Throwable $e) {

    error_log(
        '[LOVEMI LOGIN USER QUERY ERROR] '
        .
        $e->getMessage()
    );


    loginResponse(
        false,
        'Unable to process the login request.',
        [
            'code' =>
                'USER_QUERY_ERROR'
        ],
        500
    );

}


/* ============================================================
   INVALID USER
============================================================ */

if (
    !$user
) {

    loginResponse(
        false,
        'Invalid username/email or password.',
        [
            'code' =>
                'INVALID_CREDENTIALS'
        ],
        401
    );

}


/* ============================================================
   ACCOUNT DELETED
============================================================ */

if (
    (bool)
    $user['is_deleted']
) {

    loginResponse(
        false,
        'This account is no longer available.',
        [
            'code' =>
                'ACCOUNT_DELETED'
        ],
        403
    );

}


/* ============================================================
   ACCOUNT SUSPENDED
============================================================ */

if (
    !(bool)
    $user['is_active']
    ||
    (bool)
    $user['is_suspended']
    ||
    in_array(
        strtolower(
            (string)
            $user['account_status']
        ),
        [
            'suspended',
            'blocked',
            'disabled',
            'deleted'
        ],
        true
    )
) {

    loginResponse(
        false,
        'Your account is currently suspended or disabled.',
        [
            'code' =>
                'ACCOUNT_SUSPENDED'
        ],
        403
    );

}


/* ============================================================
   PASSWORD
============================================================ */

$passwordValid =
    password_verify(
        $password,
        (string)
        $user['password_hash']
    );


if (
    !$passwordValid
) {

    /*
     * Log failed login without exposing password details.
     */

    try {

        $logStmt =
            $pdo->prepare(
                "
                INSERT INTO login_logs
                (
                    user_id,
                    identifier,
                    login_status,
                    failure_reason,
                    ip_address,
                    user_agent
                )
                VALUES
                (
                    :user_id,
                    :identifier,
                    'failed',
                    'Invalid password',
                    :ip,
                    :agent
                )
                "
            );


        $logStmt->execute(
            [
                ':user_id' =>
                    (int)
                    $user['id'],

                ':identifier' =>
                    mb_substr(
                        $identifier,
                        0,
                        190
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR']
                    ??
                    null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT']
                    ??
                    null
            ]
        );


    } catch (Throwable $e) {

        error_log(
            '[LOVEMI LOGIN FAILED LOG ERROR] '
            .
            $e->getMessage()
        );

    }


    loginResponse(
        false,
        'Invalid username/email or password.',
        [
            'code' =>
                'INVALID_CREDENTIALS'
        ],
        401
    );

}


/* ============================================================
   PASSWORD REHASH
============================================================ */

if (
    password_needs_rehash(
        (string)
        $user['password_hash'],
        PASSWORD_DEFAULT
    )
) {

    try {

        $newHash =
            password_hash(
                $password,
                PASSWORD_DEFAULT
            );


        if (
            $newHash !== false
        ) {

            $rehash =
                $pdo->prepare(
                    "
                    UPDATE users

                    SET password_hash =
                        :password_hash

                    WHERE id =
                        :user_id

                    LIMIT 1
                    "
                );


            $rehash->execute(
                [
                    ':password_hash' =>
                        $newHash,

                    ':user_id' =>
                        (int)
                        $user['id']
                ]
            );

        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PASSWORD REHASH ERROR] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   EMAIL VERIFICATION CHECK
============================================================ */

if (
    !(bool)
    $user['email_verified']
) {

    loginResponse(
        false,
        'Your email has not been verified yet. Continue from the email verification step.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED',

            'user_id' =>
                (int)
                $user['id'],

            'redirect' =>
                'verify-account.html?user='
                .
                rawurlencode(
                    (string)
                    $user['id']
                )
        ],
        403
    );

}


/* ============================================================
   ACCOUNT STATUS CHECK
============================================================ */

if (
    strtolower(
        (string)
        $user['account_status']
    )
    !==
    'approved'
) {

    loginResponse(
        false,
        'Your account is not ready for login.',
        [
            'code' =>
                'ACCOUNT_NOT_APPROVED',

            'user_id' =>
                (int)
                $user['id'],

            'redirect' =>
                'verify-account.html?user='
                .
                rawurlencode(
                    (string)
                    $user['id']
                )
        ],
        403
    );

}


/* ============================================================
   SESSION FIXATION PROTECTION
============================================================ */

session_regenerate_id(
    true
);


/* ============================================================
   CREATE SECURE SESSION TOKEN
============================================================ */

try {

    $plainToken =
        bin2hex(
            random_bytes(
                32
            )
        );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI LOGIN RANDOM TOKEN ERROR] '
        .
        $e->getMessage()
    );


    loginResponse(
        false,
        'Unable to create a secure login session.',
        [
            'code' =>
                'SESSION_TOKEN_ERROR'
        ],
        500
    );

}


$sessionTokenHash =
    hash(
        'sha256',
        $plainToken
    );


/* ============================================================
   SESSION EXPIRY
============================================================ */

$sessionLifetime =
    $remember
        ?
        30 * 24 * 60 * 60
        :
        24 * 60 * 60;


$expiresAt =
    date(
        'Y-m-d H:i:s',
        time()
        +
        $sessionLifetime
    );


/* ============================================================
   CREATE PASSWORD-VERIFIED SESSION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Revoke previous sessions for this account.
     */

    $revoke =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET revoked_at =
                CURRENT_TIMESTAMP

            WHERE user_id =
                :user_id

              AND revoked_at IS NULL
            "
        );


    $revoke->execute(
        [
            ':user_id' =>
                (int)
                $user['id']
        ]
    );


    /*
     * IMPORTANT:
     *
     * two_factor_passed = FALSE
     *
     * Therefore this is not yet a full authenticated session.
     */

    $insert =
        $pdo->prepare(
            "
            INSERT INTO user_sessions
            (
                user_id,
                session_token_hash,
                ip_address,
                user_agent,
                created_at,
                last_activity_at,
                expires_at,
                two_factor_passed
            )
            VALUES
            (
                :user_id,
                :token_hash,
                :ip,
                :agent,
                CURRENT_TIMESTAMP,
                CURRENT_TIMESTAMP,
                :expires_at,
                FALSE
            )
            "
        );


    $insert->execute(
        [
            ':user_id' =>
                (int)
                $user['id'],

            ':token_hash' =>
                $sessionTokenHash,

            ':ip' =>
                $_SERVER['REMOTE_ADDR']
                ??
                null,

            ':agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ??
                null,

            ':expires_at' =>
                $expiresAt
        ]
    );


    $databaseSessionId =
        (int)
        $pdo->lastInsertId();


    /*
     * Log password acceptance.
     */

    $log =
        $pdo->prepare(
            "
            INSERT INTO login_logs
            (
                user_id,
                identifier,
                login_status,
                ip_address,
                user_agent
            )
            VALUES
            (
                :user_id,
                :identifier,
                'password_verified_2fa_pending',
                :ip,
                :agent
            )
            "
        );


    $log->execute(
        [
            ':user_id' =>
                (int)
                $user['id'],

            ':identifier' =>
                mb_substr(
                    $identifier,
                    0,
                    190
                ),

            ':ip' =>
                $_SERVER['REMOTE_ADDR']
                ??
                null,

            ':agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ??
                null
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
        '[LOVEMI LOGIN SESSION CREATION ERROR] '
        .
        $e->getMessage()
    );


    loginResponse(
        false,
        'Unable to create your login session.',
        [
            'code' =>
                'SESSION_CREATION_ERROR'
        ],
        500
    );

}


/* ============================================================
   SAVE PHP SESSION
============================================================ */

$_SESSION['lovemi_user_id'] =
    (int)
    $user['id'];


$_SESSION['lovemi_session_token'] =
    $plainToken;


$_SESSION['lovemi_database_session_id'] =
    $databaseSessionId;


$_SESSION['lovemi_2fa_pending_user_id'] =
    (int)
    $user['id'];


/* ============================================================
   SAVE ROLE FOR FINAL REDIRECTION
============================================================ */

$_SESSION['lovemi_role_slug'] =
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


/* ============================================================
   GOOGLE AUTHENTICATOR STATUS
============================================================ */

$twoFactorEnabled =
    (bool)
    $user['two_factor_enabled'];


$secretExists =
    !empty(
        $user['two_factor_secret_encrypted']
    );


/* ============================================================
   SAFETY CHECK
============================================================ */

if (
    $twoFactorEnabled
    &&
    !$secretExists
) {

    error_log(
        '[LOVEMI SECURITY] User '
        .
        (int)
        $user['id']
        .
        ' has 2FA enabled but no secret.'
    );


    loginResponse(
        false,
        'Your two-step verification configuration needs to be repaired. Please contact support.',
        [
            'code' =>
                '2FA_CONFIGURATION_ERROR'
        ],
        409
    );

}


/* ============================================================
   2FA ALREADY CONFIGURED
============================================================ */

if (
    $twoFactorEnabled
    &&
    $secretExists
) {

    loginResponse(
        true,
        'Password accepted. Enter your Google Authenticator code to complete login.',
        [
            'authenticated' =>
                false,

            'password_verified' =>
                true,

            'two_factor_required' =>
                true,

            'two_factor_enabled' =>
                true,

            'two_factor_passed' =>
                false,

            'code' =>
                'TWO_FACTOR_REQUIRED',

            'user_id' =>
                (int)
                $user['id'],

            'role' =>
                $_SESSION['lovemi_role_slug'],

            'redirect' =>
                'verify-account.html?step=login-2fa'
        ]
    );

}


/* ============================================================
   2FA SETUP REQUIRED
============================================================ */

loginResponse(
    true,
    'Password accepted. Complete Google Authenticator setup before entering LOVEMI.',
    [
        'authenticated' =>
            false,

        'password_verified' =>
            true,

        'two_factor_required' =>
            true,

        'two_factor_enabled' =>
            false,

        'two_factor_passed' =>
            false,

        'code' =>
            'TWO_FACTOR_SETUP_REQUIRED',

        'user_id' =>
            (int)
            $user['id'],

        'role' =>
            $_SESSION['lovemi_role_slug'],

        'redirect' =>
            'verify-account.html?step=2fa'
    ]
);