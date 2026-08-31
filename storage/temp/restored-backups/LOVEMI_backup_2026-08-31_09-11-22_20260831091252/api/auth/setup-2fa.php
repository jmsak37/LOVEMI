<?php
/**
 * ============================================================
 * LOVEMI - GOOGLE AUTHENTICATOR SETUP
 * ============================================================
 */

declare(strict_types=1);

/* ============================================================
   DATABASE
============================================================ */
require_once __DIR__ . '/../../config/database.php';

/* ============================================================
   RESPONSE HEADERS
============================================================ */
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

/* ============================================================
   START SESSION
============================================================ */
$isHttps =
    !empty($_SERVER['HTTPS'])
    && $_SERVER['HTTPS'] !== 'off';

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]);

    session_start();
}

/* ============================================================
   RESPONSE HELPER
============================================================ */
function setup2faResponse(
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
        JSON_UNESCAPED_UNICODE
        | JSON_UNESCAPED_SLASHES
    );

    exit;
}

/* ============================================================
   METHOD
============================================================ */
if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {
    setup2faResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

/* ============================================================
   REQUEST
============================================================ */
$input = json_decode(
    file_get_contents('php://input') ?: '{}',
    true
);

if (!is_array($input)) {
    $input = [];
}

$requestUserId =
    isset($input['user_id'])
        ? (int)$input['user_id']
        : 0;

/* ============================================================
   SERVER-SIDE USER IDENTIFICATION
============================================================ */

$setupUserId =
    isset($_SESSION['lovemi_2fa_setup_user_id'])
        ? (int)$_SESSION['lovemi_2fa_setup_user_id']
        : 0;

$setupCreatedAt =
    isset($_SESSION['lovemi_2fa_setup_created_at'])
        ? (int)$_SESSION['lovemi_2fa_setup_created_at']
        : 0;

$pendingUserId =
    isset($_SESSION['lovemi_2fa_pending_user_id'])
        ? (int)$_SESSION['lovemi_2fa_pending_user_id']
        : 0;

$normalUserId =
    isset($_SESSION['lovemi_user_id'])
        ? (int)$_SESSION['lovemi_user_id']
        : 0;

/* ============================================================
   TEMPORARY SETUP SESSION EXPIRY
============================================================ */

if ($setupUserId > 0) {

    if (
        $setupCreatedAt <= 0
        ||
        (time() - $setupCreatedAt) > (30 * 60)
    ) {

        unset(
            $_SESSION['lovemi_2fa_setup_user_id'],
            $_SESSION['lovemi_2fa_setup_created_at']
        );

        $setupUserId = 0;
    }
}

/* ============================================================
   CHOOSE EFFECTIVE USER
============================================================ */

$effectiveUserId =
    $setupUserId > 0
        ? $setupUserId
        : (
            $pendingUserId > 0
                ? $pendingUserId
                : $normalUserId
        );

if ($effectiveUserId <= 0) {

    setup2faResponse(
        false,
        'Your verification session has expired. Please verify your email again.',
        [
            'code' => 'SETUP_SESSION_REQUIRED'
        ],
        401
    );
}

/* ============================================================
   USER ID MUST MATCH SERVER SESSION
============================================================ */

if (
    $requestUserId > 0
    &&
    $requestUserId !== $effectiveUserId
) {

    setup2faResponse(
        false,
        'Invalid account setup request.',
        [
            'code' => 'USER_MISMATCH'
        ],
        403
    );
}

/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo = db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SETUP 2FA DB CONNECTION] '
        . $e->getMessage()
    );

    setup2faResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}

/* ============================================================
   USER
============================================================ */

try {

    $stmt = $pdo->prepare(
        "
        SELECT
            id,
            username,
            full_names,
            email,
            email_verified,
            account_status,
            two_factor_enabled,
            two_factor_secret_encrypted,
            is_active,
            is_suspended,
            is_deleted
        FROM users
        WHERE id = :id
        LIMIT 1
        "
    );

    $stmt->execute([
        ':id' => $effectiveUserId
    ]);

    $user = $stmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SETUP 2FA USER QUERY] '
        . $e->getMessage()
    );

    setup2faResponse(
        false,
        'Unable to load your account.',
        [
            'code' => 'USER_QUERY_ERROR'
        ],
        500
    );
}

if (!$user) {

    setup2faResponse(
        false,
        'Account not found.',
        [
            'code' => 'USER_NOT_FOUND'
        ],
        404
    );
}

/* ============================================================
   ACCOUNT VALIDATION
============================================================ */

if (
    (bool)$user['is_deleted']
    ||
    (bool)$user['is_suspended']
    ||
    !(bool)$user['is_active']
) {

    setup2faResponse(
        false,
        'This account is currently unavailable.',
        [
            'code' => 'ACCOUNT_UNAVAILABLE'
        ],
        403
    );
}

/* ============================================================
   EMAIL REQUIRED
============================================================ */

if (
    !(bool)$user['email_verified']
) {

    setup2faResponse(
        false,
        'Your email must be verified before Google Authenticator can be configured.',
        [
            'code' => 'EMAIL_NOT_VERIFIED'
        ],
        403
    );
}

/* ============================================================
   ALREADY ENABLED
============================================================ */

if (
    (bool)$user['two_factor_enabled']
) {

    unset(
        $_SESSION['lovemi_2fa_setup_user_id'],
        $_SESSION['lovemi_2fa_setup_created_at']
    );

    setup2faResponse(
        true,
        'Google Authenticator is already enabled.',
        [
            'already_configured' => true,
            'two_factor_enabled' => true
        ]
    );
}

/* ============================================================
   LOAD SONATA CLASSES DIRECTLY
============================================================ */

/*
 * Your folder tree shows this exact installation:
 *
 * api/auth/google-authenticator/src/
 *
 * and:
 *
 * api/auth/vendor/sonata-project/google-authenticator/src/
 *
 * We first try Composer.
 *
 * If Composer cannot load the classes, we explicitly include
 * the four Sonata source files needed by the package.
 */

$composerAutoload =
    __DIR__ . '/vendor/autoload.php';

if (is_file($composerAutoload)) {

    require_once $composerAutoload;
}


/* ============================================================
   MANUAL FALLBACK
============================================================ */

if (
    !class_exists(
        '\\Sonata\\GoogleAuthenticator\\GoogleAuthenticator'
    )
) {

    $sourceCandidates = [

        __DIR__
        . '/vendor/sonata-project/google-authenticator/src/',

        __DIR__
        . '/google-authenticator/src/'

    ];


    $sourceDirectory = null;


    foreach (
        $sourceCandidates
        as $candidate
    ) {

        if (
            is_file(
                $candidate
                . 'FixedBitNotation.php'
            )
            &&
            is_file(
                $candidate
                . 'GoogleAuthenticatorInterface.php'
            )
            &&
            is_file(
                $candidate
                . 'GoogleAuthenticator.php'
            )
            &&
            is_file(
                $candidate
                . 'GoogleQrUrl.php'
            )
        ) {

            $sourceDirectory =
                $candidate;

            break;
        }
    }


    if ($sourceDirectory === null) {

        setup2faResponse(
            false,
            'Google Authenticator library files were not found in the LOVEMI installation.',
            [
                'code' =>
                    'GOOGLE_AUTHENTICATOR_FILES_MISSING'
            ],
            500
        );
    }


    require_once
        $sourceDirectory
        . 'FixedBitNotation.php';


    require_once
        $sourceDirectory
        . 'GoogleAuthenticatorInterface.php';


    require_once
        $sourceDirectory
        . 'GoogleAuthenticator.php';


    require_once
        $sourceDirectory
        . 'GoogleQrUrl.php';
}


/* ============================================================
   CLASS CHECK
============================================================ */

if (
    !class_exists(
        '\\Sonata\\GoogleAuthenticator\\GoogleAuthenticator'
    )
    ||
    !class_exists(
        '\\Sonata\\GoogleAuthenticator\\GoogleQrUrl'
    )
) {

    setup2faResponse(
        false,
        'Google Authenticator classes could not be loaded.',
        [
            'code' =>
                'GOOGLE_AUTHENTICATOR_LOAD_ERROR'
        ],
        500
    );
}

use Sonata\GoogleAuthenticator\GoogleAuthenticator;
use Sonata\GoogleAuthenticator\GoogleQrUrl;


/* ============================================================
   AUTHENTICATOR
============================================================ */

try {

    $google =
        new GoogleAuthenticator();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI 2FA AUTHENTICATOR INIT] '
        . $e->getMessage()
    );

    setup2faResponse(
        false,
        'Google Authenticator could not be initialized.',
        [
            'code' => 'AUTHENTICATOR_INIT_ERROR'
        ],
        500
    );
}


/* ============================================================
   GET EXISTING SECRET
============================================================ */

$secret = null;


if (
    !empty(
        $user['two_factor_secret_encrypted']
    )
) {

    /*
     * Try the encrypted format first.
     *
     * Format:
     *
     * base64(iv):base64(ciphertext)
     */

    try {

        $parts =
            explode(
                ':',
                (string)
                $user['two_factor_secret_encrypted'],
                2
            );


        if (
            count($parts) === 2
        ) {

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
                $iv !== false
                &&
                $encrypted !== false
            ) {

                /*
                 * Use the application key only when configured.
                 */

                $applicationKey =
                    'LOVEMI_SecKey_#9k8v7x6z5w4y3m2n1p0q9r8s7t6u5v4w3x2y1z!';


                if (
                    is_string(
                        $applicationKey
                    )
                    &&
                    trim(
                        $applicationKey
                    ) !== ''
                ) {

                    $key =
                        hash(
                            'sha256',
                            $applicationKey,
                            true
                        );


                    $decrypted =
                        openssl_decrypt(
                            $encrypted,
                            'aes-256-cbc',
                            $key,
                            OPENSSL_RAW_DATA,
                            $iv
                        );


                    if (
                        is_string(
                            $decrypted
                        )
                        &&
                        trim(
                            $decrypted
                        ) !== ''
                    ) {

                        $secret =
                            trim(
                                $decrypted
                            );

                    }
                }
            }
        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI 2FA SECRET DECRYPT] '
            . $e->getMessage()
        );

        $secret = null;
    }
}


/* ============================================================
   CREATE SECRET
============================================================ */

if (
    !is_string($secret)
    ||
    trim($secret) === ''
) {

    try {

        $secret =
            $google->generateSecret();

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI 2FA SECRET GENERATION] '
            . $e->getMessage()
        );

        setup2faResponse(
            false,
            'Unable to generate a Google Authenticator secret.',
            [
                'code' =>
                    'SECRET_GENERATION_ERROR'
            ],
            500
        );
    }


    /* ========================================================
       ENCRYPT SECRET
    ===================================================== */

    try {

        $applicationKey =
            'LOVEMI_SecKey_#9k8v7x6z5w4y3m2n1p0q9r8s7t6u5v4w3x2y1z!';


        /*
         * For your local XAMPP installation we require the key
         * to be explicitly configured.
         */

        if (
            !is_string($applicationKey)
            ||
            trim($applicationKey) === ''
        ) {

            /*
             * IMPORTANT:
             *
             * Do NOT silently store a plaintext authenticator
             * secret.
             */

            setup2faResponse(
                false,
                'LOVEMI_APP_KEY is not configured. Add a secure application key before enabling two-step verification.',
                [
                    'code' =>
                        'APP_KEY_REQUIRED'
                ],
                500
            );
        }


        $key =
            hash(
                'sha256',
                $applicationKey,
                true
            );


        $iv =
            random_bytes(
                16
            );


        $encrypted =
            openssl_encrypt(
                $secret,
                'aes-256-cbc',
                $key,
                OPENSSL_RAW_DATA,
                $iv
            );


        if (
            $encrypted === false
        ) {

            throw new RuntimeException(
                'Secret encryption failed.'
            );
        }


        $storedSecret =
            base64_encode(
                $iv
            )
            . ':'
            .
            base64_encode(
                $encrypted
            );


        $save =
            $pdo->prepare(
                "
                UPDATE users

                SET
                    two_factor_secret_encrypted =
                        :secret,

                    two_factor_enabled =
                        FALSE,

                    two_factor_verified_at =
                        NULL

                WHERE id = :user_id

                LIMIT 1
                "
            );


        $save->execute(
            [
                ':secret' =>
                    $storedSecret,

                ':user_id' =>
                    $effectiveUserId
            ]
        );


    } catch (Throwable $e) {

        error_log(
            '[LOVEMI 2FA SECRET SAVE] '
            . $e->getMessage()
        );


        setup2faResponse(
            false,
            'Unable to securely prepare two-step verification.',
            [
                'code' =>
                    'SECRET_STORAGE_ERROR'
            ],
            500
        );
    }
}


/* ============================================================
   GENERATE REAL QR IMAGE URL
============================================================ */

try {

    /*
     * IMPORTANT:
     *
     * This generates the image URL itself.
     */

    $qrImageUrl =
        GoogleQrUrl::generate(
            (string)
            $user['username'],

            (string)
            $secret,

            'LOVEMI'
        );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI QR GENERATION] '
        . $e->getMessage()
    );


    setup2faResponse(
        false,
        'Unable to generate the Google Authenticator QR code.',
        [
            'code' =>
                'QR_GENERATION_ERROR'
        ],
        500
    );
}


/* ============================================================
   VALIDATE QR URL
============================================================ */

if (
    !is_string($qrImageUrl)
    ||
    trim($qrImageUrl) === ''
) {

    setup2faResponse(
        false,
        'Google Authenticator returned an empty QR code URL.',
        [
            'code' =>
                'EMPTY_QR_URL'
        ],
        500
    );
}


/* ============================================================
   REFRESH TEMPORARY SETUP SESSION
============================================================ */

$_SESSION[
    'lovemi_2fa_setup_user_id'
] =
    $effectiveUserId;


$_SESSION[
    'lovemi_2fa_setup_created_at'
] =
    time();


/* ============================================================
   RESPONSE
============================================================ */

setup2faResponse(
    true,
    'Google Authenticator setup is ready.',
    [
        'already_configured' =>
            false,

        'two_factor_enabled' =>
            false,

        'username' =>
            (string)
            $user['username'],

        'account_name' =>
            (string)
            $user['full_names'],

        'qr_url' =>
            $qrImageUrl,

        'manual_key' =>
            $secret
    ]
);