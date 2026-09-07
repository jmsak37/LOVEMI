<?php

/**
 * ============================================================
 * LOVEMI - LOGIN API
 * ============================================================
 *
 * NORMAL LOGIN
 *
 * 1. Username/email + password
 * 2. Email verification
 * 3. Account approval
 * 4. Create secure pending session
 * 5. Google Authenticator setup/code
 * 6. Full authentication
 *
 * GOOGLE LOGIN
 *
 * 1. Receive Google Identity Services ID token
 * 2. Validate LOVEMI Google CSRF token
 * 3. Verify token with Google
 * 4. Validate issuer, audience, subject, email and expiry
 * 5. Find account by Google subject
 * 6. If not linked, match verified email
 * 7. If no account exists, continue to registration.html
 * 8. Check account status
 * 9. Create secure pending LOVEMI session
 * 10. Continue through LOVEMI Google Authenticator security
 *
 * ADDITIONAL
 *
 * - Accepts JSON and application/x-www-form-urlencoded requests
 * - Stores browser device ID in user_sessions
 * - Preserves optional browser GPS data in PHP session until
 *   full authentication
 * - Supports Google Sign-In configuration endpoint
 * - Supports Google ID-token POST from Google Identity Services
 * - Returns JSON for fetch/AJAX requests
 * - Never exposes the Google Client Secret to the browser
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   REQUIRED FILES
============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   GOOGLE CONFIGURATION
============================================================ */

$googleConfigPath =
    __DIR__
    . '/../../config/google.php';


if (
    is_file(
        $googleConfigPath
    )
) {

    require_once $googleConfigPath;

}


/* ============================================================
   EMAIL SERVICE
============================================================ */

$emailServicePath =
    __DIR__
    . '/../../services/email/email-service.php';


if (
    is_file(
        $emailServicePath
    )
) {

    require_once $emailServicePath;

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


/* ============================================================
   TIMEZONE
============================================================ */

date_default_timezone_set(
    'Africa/Nairobi'
);


/* ============================================================
   HTTPS
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    strtolower(
        (string)(
            $_SERVER['HTTPS']
            ??
            ''
        )
    )
    !==
    'off';


/* ============================================================
   SESSION COOKIE
============================================================ */

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
   SESSION
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
   BASE URL
============================================================ */

function lovemiBaseUrl(): string
{
    $configured =
        trim(
            (string)(
                getenv(
                    'LOVEMI_APP_URL'
                )
                ?:
                ''
            )
        );


    if (
        $configured !== ''
    ) {

        return rtrim(
            $configured,
            '/'
        );

    }


    $https =
        !empty(
            $_SERVER['HTTPS']
        )
        &&
        strtolower(
            (string)(
                $_SERVER['HTTPS']
                ??
                ''
            )
        )
        !==
        'off';


    $scheme =
        $https
            ?
            'https'
            :
            'http';


    $host =
        trim(
            (string)(
                $_SERVER['HTTP_HOST']
                ??
                'localhost'
            )
        );


    $script =
        str_replace(
            '\\',
            '/',
            (string)(
                $_SERVER['SCRIPT_NAME']
                ??
                '/LOVEMI/api/auth/login.php'
            )
        );


    $basePath =
        preg_replace(
            '#/api/auth/login\.php$#',
            '',
            $script
        );


    if (
        !is_string(
            $basePath
        )
        ||
        $basePath === ''
    ) {

        $basePath =
            '/LOVEMI';

    }


    return
        $scheme
        .
        '://'
        .
        $host
        .
        rtrim(
            $basePath,
            '/'
        );
}


/* ============================================================
   READ REQUEST BODY
============================================================ */

function readLoginInput(): array
{
    $raw =
        file_get_contents(
            'php://input'
        );


    $contentType =
        strtolower(
            (string)(
                $_SERVER['CONTENT_TYPE']
                ??
                ''
            )
        );


    /* --------------------------------------------------------
       JSON
    -------------------------------------------------------- */

    if (
        str_contains(
            $contentType,
            'application/json'
        )
    ) {

        $decoded =
            json_decode(
                (string)$raw,
                true
            );


        if (
            is_array(
                $decoded
            )
        ) {

            return $decoded;

        }

    }


    /* --------------------------------------------------------
       FORM URL ENCODED / MULTIPART
    -------------------------------------------------------- */

    if (
        !empty(
            $_POST
        )
    ) {

        return $_POST;

    }


    /* --------------------------------------------------------
       FINAL JSON FALLBACK
    -------------------------------------------------------- */

    $decoded =
        json_decode(
            (string)$raw,
            true
        );


    return
        is_array(
            $decoded
        )
            ?
            $decoded
            :
            [];
}


/* ============================================================
   CLEAN DEVICE ID
============================================================ */

function cleanDeviceId(
    string $deviceId
): string {

    $deviceId =
        preg_replace(
            '/[^A-Za-z0-9._:-]/',
            '',
            trim(
                $deviceId
            )
        );


    if (
        !is_string(
            $deviceId
        )
    ) {

        return '';

    }


    return mb_substr(
        $deviceId,
        0,
        128
    );
}


/* ============================================================
   FLOAT INPUT
============================================================ */

function nullableFloat(
    mixed $value
): ?float {

    if (
        $value === null
        ||
        $value === ''
    ) {

        return null;

    }


    if (
        !is_numeric(
            $value
        )
    ) {

        return null;

    }


    return (float)$value;
}


/* ============================================================
   STORE PENDING LOCATION
============================================================ */

function storePendingLocation(
    array $input
): void {

    $latitude =
        nullableFloat(
            $input['latitude']
            ??
            null
        );


    $longitude =
        nullableFloat(
            $input['longitude']
            ??
            null
        );


    if (
        $latitude === null
        ||
        $longitude === null
    ) {

        unset(
            $_SESSION[
                'lovemi_pending_location'
            ]
        );

        return;

    }


    if (
        $latitude < -90
        ||
        $latitude > 90
        ||
        $longitude < -180
        ||
        $longitude > 180
    ) {

        unset(
            $_SESSION[
                'lovemi_pending_location'
            ]
        );

        return;

    }


    $accuracy =
        nullableFloat(
            $input['accuracy']
            ??
            null
        );


    $altitude =
        nullableFloat(
            $input['altitude']
            ??
            null
        );


    $heading =
        nullableFloat(
            $input['heading']
            ??
            null
        );


    $speed =
        nullableFloat(
            $input['speed']
            ??
            null
        );


    if (
        $accuracy !== null
        &&
        (
            $accuracy < 0
            ||
            $accuracy > 100000
        )
    ) {

        $accuracy =
            null;

    }


    if (
        $altitude !== null
        &&
        (
            $altitude < -2000
            ||
            $altitude > 100000
        )
    ) {

        $altitude =
            null;

    }


    if (
        $heading !== null
        &&
        (
            $heading < 0
            ||
            $heading > 360
        )
    ) {

        $heading =
            null;

    }


    if (
        $speed !== null
        &&
        (
            $speed < 0
            ||
            $speed > 1000
        )
    ) {

        $speed =
            null;

    }


    $_SESSION[
        'lovemi_pending_location'
    ] =
        [

            'latitude' =>
                $latitude,

            'longitude' =>
                $longitude,

            'accuracy' =>
                $accuracy,

            'altitude' =>
                $altitude,

            'heading' =>
                $heading,

            'speed' =>
                $speed,

            'created_at' =>
                date(
                    'Y-m-d H:i:s'
                )

        ];

}


/* ============================================================
   GOOGLE CLIENT ID
============================================================ */

function googleClientId(): string
{
    /*
     * Preferred source:
     * config/google.php
     */
    if (
        function_exists(
            'lovemiGoogleClientId'
        )
    ) {

        $id =
            trim(
                (string)
                lovemiGoogleClientId()
            );


        if (
            $id !== ''
        ) {

            return $id;

        }

    }


    /*
     * Fallback to environment variable.
     */
    $environmentId =
        trim(
            (string)(
                getenv(
                    'LOVEMI_GOOGLE_CLIENT_ID'
                )
                ?:
                ''
            )
        );


    return $environmentId;
}


/* ============================================================
   GOOGLE CSRF TOKEN
============================================================ */

function getGoogleCsrfToken(): string
{
    $existing =
        trim(
            (string)(
                $_SESSION[
                    'lovemi_google_login_csrf'
                ]
                ??
                ''
            )
        );


    if (
        $existing !== ''
    ) {

        return $existing;

    }


    try {

        $token =
            bin2hex(
                random_bytes(
                    32
                )
            );

    } catch (
        Throwable $e
    ) {

        /*
         * random_bytes() should be available on supported PHP.
         * Never use a predictable token fallback.
         */
        error_log(
            '[LOVEMI GOOGLE CSRF] '
            .
            $e->getMessage()
        );


        return '';

    }


    $_SESSION[
        'lovemi_google_login_csrf'
    ] =
        $token;


    return $token;
}


/* ============================================================
   VALIDATE GOOGLE CSRF TOKEN
============================================================ */

function validateGoogleCsrf(
    array $input
): bool {

    $posted =
        trim(
            (string)(
                $input['csrf_token']
                ??
                $input['google_csrf_token']
                ??
                $input['g_csrf_token']
                ??
                ''
            )
        );


    if (
        $posted === ''
    ) {

        return false;

    }


    $sessionToken =
        trim(
            (string)(
                $_SESSION[
                    'lovemi_google_login_csrf'
                ]
                ??
                ''
            )
        );


    if (
        $sessionToken === ''
    ) {

        return false;

    }


    return hash_equals(
        $sessionToken,
        $posted
    );
}


/* ============================================================
   GOOGLE ERROR JSON
============================================================ */

function googleErrorResponse(
    string $code,
    string $message,
    int $status = 400
): never {

    loginResponse(
        false,
        $message,
        [

            'code' =>
                $code

        ],
        $status
    );

}


/* ============================================================
   GOOGLE CONFIG ENDPOINT
============================================================ */

if (
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ??
            ''
        )
    )
    ===
    'GET'
) {

    $action =
        trim(
            (string)(
                $_GET['action']
                ??
                ''
            )
        );


    if (
        $action ===
        'google-config'
    ) {

        $clientId =
            googleClientId();


        if (
            $clientId === ''
        ) {

            loginResponse(
                false,
                'Google Sign-In is not configured. Add the Google Client ID in config/google.php or LOVEMI_GOOGLE_CLIENT_ID.',
                [

                    'code' =>
                        'GOOGLE_NOT_CONFIGURED',

                    'client_id' =>
                        '',

                    'csrf_token' =>
                        ''

                ],
                503
            );

        }


        $csrfToken =
            getGoogleCsrfToken();


        if (
            $csrfToken === ''
        ) {

            loginResponse(
                false,
                'Unable to initialize Google Sign-In security.',
                [

                    'code' =>
                        'GOOGLE_CSRF_ERROR',

                    'client_id' =>
                        ''

                ],
                500
            );

        }


        loginResponse(
            true,
            'Google Sign-In configuration loaded.',
            [

                'client_id' =>
                    $clientId,

                'csrf_token' =>
                    $csrfToken

            ]
        );

    }


    loginResponse(
        false,
        'Invalid request.',
        [

            'code' =>
                'INVALID_ACTION'

        ],
        400
    );

}


/* ============================================================
   REQUEST METHOD
============================================================ */

if (
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ??
            ''
        )
    )
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
   INPUT
============================================================ */

$data =
    readLoginInput();


/* ============================================================
   BASIC DEVICE / LOCATION DATA
============================================================ */

$deviceId =
    cleanDeviceId(
        (string)(
            $data['device_id']
            ??
            ''
        )
    );


$deviceName =
    mb_substr(
        trim(
            (string)(
                $data['device_name']
                ??
                ''
            )
        ),
        0,
        255
    );


$browserName =
    mb_substr(
        trim(
            (string)(
                $data['browser_name']
                ??
                ''
            )
        ),
        0,
        100
    );


$operatingSystem =
    mb_substr(
        trim(
            (string)(
                $data['operating_system']
                ??
                ''
            )
        ),
        0,
        150
    );


/*
 * Save optional location in the PHP session until full
 * authentication is completed.
 */
storePendingLocation(
    $data
);


/* ============================================================
   GOOGLE ID TOKEN FLOW
============================================================ */

$googleCredential =
    trim(
        (string)(
            $data['credential']
            ??
            $data['google_credential']
            ??
            ''
        )
    );


$googleAction =
    strtolower(
        trim(
            (string)(
                $data['action']
                ??
                ''
            )
        )
    );


/*
 * A Google credential is enough to select the Google flow,
 * even if action was omitted by an older login page.
 */
$isGoogleLogin =
    $googleCredential !== ''
    ||
    in_array(
        $googleAction,
        [

            'google',
            'google-login',
            'google_signin',
            'google-signin'

        ],
        true
    );


if (
    $isGoogleLogin
) {

    /* ========================================================
       GOOGLE CREDENTIAL REQUIRED
    ======================================================== */

    if (
        $googleCredential === ''
    ) {

        googleErrorResponse(
            'GOOGLE_CREDENTIAL_REQUIRED',
            'Google did not provide a sign-in credential.',
            422
        );

    }


    /* ========================================================
       GOOGLE CSRF
    ======================================================== */

    if (
        !validateGoogleCsrf(
            $data
        )
    ) {

        googleErrorResponse(
            'GOOGLE_CSRF_ERROR',
            'The Google sign-in security token is invalid or expired. Please refresh the login page and try again.',
            403
        );

    }


    /*
     * Rotate the Google login CSRF token after successful use.
     * This prevents replaying the same application token.
     */
    $usedGoogleCsrf =
        $_SESSION[
            'lovemi_google_login_csrf'
        ]
        ??
        '';


    unset(
        $_SESSION[
            'lovemi_google_login_csrf'
        ]
    );


    /* ========================================================
       CLIENT ID
    ======================================================== */

    $clientId =
        googleClientId();


    if (
        $clientId === ''
    ) {

        googleErrorResponse(
            'GOOGLE_NOT_CONFIGURED',
            'Google Sign-In is not configured on LOVEMI.',
            503
        );

    }


    /* ========================================================
       VERIFY GOOGLE ID TOKEN
    ======================================================== */

    $googleInfo =
        null;


    try {

        $verifyUrl =
            'https://oauth2.googleapis.com/tokeninfo?id_token='
            .
            rawurlencode(
                $googleCredential
            );


        $ch =
            curl_init(
                $verifyUrl
            );


        if (
            $ch === false
        ) {

            throw new RuntimeException(
                'Unable to initialize Google verification.'
            );

        }


        curl_setopt_array(
            $ch,
            [

                CURLOPT_RETURNTRANSFER =>
                    true,

                CURLOPT_FOLLOWLOCATION =>
                    false,

                CURLOPT_CONNECTTIMEOUT =>
                    10,

                CURLOPT_TIMEOUT =>
                    15,

                CURLOPT_HTTPHEADER =>
                    [

                        'Accept: application/json'

                    ]

            ]
        );


        $googleRaw =
            curl_exec(
                $ch
            );


        $googleStatus =
            (int)
            curl_getinfo(
                $ch,
                CURLINFO_HTTP_CODE
            );


        $curlError =
            curl_error(
                $ch
            );


        curl_close(
            $ch
        );


        if (
            $googleRaw === false
            ||
            $curlError !== ''
            ||
            $googleStatus < 200
            ||
            $googleStatus >= 300
        ) {

            throw new RuntimeException(
                'Google token verification failed.'
            );

        }


        $googleInfo =
            json_decode(
                (string)$googleRaw,
                true
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE VERIFY] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'GOOGLE_VERIFICATION_FAILED',
            'LOVEMI could not verify the Google account. Please try again.',
            401
        );

    }


    /* ========================================================
       GOOGLE TOKEN STRUCTURE
    ======================================================== */

    if (
        !is_array(
            $googleInfo
        )
    ) {

        googleErrorResponse(
            'GOOGLE_INVALID_TOKEN',
            'Google returned an invalid sign-in token.',
            401
        );

    }


    $googleSub =
        trim(
            (string)(
                $googleInfo['sub']
                ??
                ''
            )
        );


    $googleEmail =
        strtolower(
            trim(
                (string)(
                    $googleInfo['email']
                    ??
                    ''
                )
            )
        );


    $googleName =
        trim(
            (string)(
                $googleInfo['name']
                ??
                ''
            )
        );


    $googlePicture =
        trim(
            (string)(
                $googleInfo['picture']
                ??
                ''
            )
        );


    $googleEmailVerified =
        filter_var(
            $googleInfo['email_verified']
            ??
            false,
            FILTER_VALIDATE_BOOLEAN
        );


    $googleIssuer =
        trim(
            (string)(
                $googleInfo['iss']
                ??
                ''
            )
        );


    $googleAudience =
        trim(
            (string)(
                $googleInfo['aud']
                ??
                ''
            )
        );


    $googleExpiry =
        (int)(
            $googleInfo['exp']
            ??
            0
        );


    /*
     * Google subjects are the stable identity identifier.
     */
    if (
        $googleSub === ''
    ) {

        googleErrorResponse(
            'GOOGLE_SUBJECT_MISSING',
            'Google did not provide a valid account identifier.',
            401
        );

    }


    /*
     * Google email is required for LOVEMI account matching.
     */
    if (
        $googleEmail === ''
        ||
        !filter_var(
            $googleEmail,
            FILTER_VALIDATE_EMAIL
        )
    ) {

        googleErrorResponse(
            'GOOGLE_EMAIL_INVALID',
            'Google did not provide a valid email address.',
            401
        );

    }


    /*
     * Only verified Google email addresses are accepted.
     */
    if (
        !$googleEmailVerified
    ) {

        googleErrorResponse(
            'GOOGLE_EMAIL_NOT_VERIFIED',
            'Your Google email address has not been verified by Google.',
            403
        );

    }


    /*
     * Validate issuer.
     */
    if (
        $googleIssuer !==
            'accounts.google.com'
        &&
        $googleIssuer !==
            'https://accounts.google.com'
    ) {

        googleErrorResponse(
            'GOOGLE_ISSUER_INVALID',
            'The Google sign-in issuer is invalid.',
            401
        );

    }


    /*
     * Validate audience against LOVEMI's actual Client ID.
     */
    if (
        !hash_equals(
            $clientId,
            $googleAudience
        )
    ) {

        googleErrorResponse(
            'GOOGLE_AUDIENCE_INVALID',
            'The Google sign-in was issued for a different application.',
            401
        );

    }


    /*
     * Validate expiry.
     */
    if (
        $googleExpiry <=
        time()
    ) {

        googleErrorResponse(
            'GOOGLE_TOKEN_EXPIRED',
            'The Google sign-in token has expired. Please sign in again.',
            401
        );

    }


    /* ========================================================
       DATABASE
    ======================================================== */

    try {

        $pdo =
            db();


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE DB] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'DATABASE_ERROR',
            'The login service is temporarily unavailable.',
            500
        );

    }


    /* ========================================================
       ENSURE GOOGLE ACCOUNT TABLE
    ======================================================== */

    try {

        /*
         * This definition matches the LOVEMI migration 027
         * structure and is only used when the table does not
         * already exist.
         */
        $pdo->exec(
            "
            CREATE TABLE IF NOT EXISTS user_google_accounts
            (
                id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,

                user_id BIGINT(20) UNSIGNED NOT NULL,

                google_sub VARCHAR(255) NOT NULL,

                email VARCHAR(190) NOT NULL,

                picture_url TEXT NULL,

                created_at DATETIME NOT NULL
                    DEFAULT CURRENT_TIMESTAMP,

                updated_at DATETIME NOT NULL
                    DEFAULT CURRENT_TIMESTAMP
                    ON UPDATE CURRENT_TIMESTAMP,

                PRIMARY KEY (id),

                UNIQUE KEY uq_google_sub
                    (google_sub),

                UNIQUE KEY uq_google_user
                    (user_id),

                KEY idx_google_email
                    (email),

                CONSTRAINT fk_google_account_user
                    FOREIGN KEY (user_id)
                    REFERENCES users(id)
                    ON DELETE CASCADE
                    ON UPDATE CASCADE

            )
            ENGINE=InnoDB
            DEFAULT CHARSET=utf8mb4
            COLLATE=utf8mb4_unicode_ci
            "
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE TABLE] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'GOOGLE_TABLE_ERROR',
            'The Google account service could not be initialized. Please run migration 027_registration_google_education.sql.',
            500
        );

    }


    /* ========================================================
       FIND ACCOUNT BY GOOGLE SUBJECT
    ======================================================== */

    try {

        $googleStmt =
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

                    c.iso2 AS country_iso2,

                    ga.google_sub,

                    ga.email AS google_account_email,

                    ga.picture_url AS google_picture_url

                FROM user_google_accounts ga

                INNER JOIN users u
                    ON u.id = ga.user_id

                LEFT JOIN roles r
                    ON r.id = u.role_id

                LEFT JOIN countries c
                    ON c.id = u.country_id

                WHERE ga.google_sub =
                    :google_sub

                LIMIT 1
                "
            );


        $googleStmt->execute(
            [

                ':google_sub' =>
                    $googleSub

            ]
        );


        $user =
            $googleStmt->fetch(
                PDO::FETCH_ASSOC
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE SUBJECT QUERY] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'GOOGLE_ACCOUNT_QUERY_ERROR',
            'Unable to process your Google account.',
            500
        );

    }


    /* ========================================================
       MATCH EXISTING LOVEMI ACCOUNT BY VERIFIED EMAIL
    ======================================================== */

    if (
        !$user
    ) {

        try {

            $emailStmt =
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

                    WHERE LOWER(u.email) =
                        LOWER(:email)

                    LIMIT 1
                    "
                );


            $emailStmt->execute(
                [

                    ':email' =>
                        $googleEmail

                ]
            );


            $user =
                $emailStmt->fetch(
                    PDO::FETCH_ASSOC
                );


            /*
             * If an existing LOVEMI account was found,
             * securely link the verified Google identity.
             */
            if (
                $user
            ) {

                $linkStmt =
                    $pdo->prepare(
                        "
                        INSERT INTO user_google_accounts
                        (
                            user_id,
                            google_sub,
                            email,
                            picture_url
                        )
                        VALUES
                        (
                            :user_id,
                            :google_sub,
                            :email,
                            :picture_url
                        )
                        ON DUPLICATE KEY UPDATE

                            user_id =
                                VALUES(user_id),

                            email =
                                VALUES(email),

                            picture_url =
                                VALUES(picture_url),

                            updated_at =
                                CURRENT_TIMESTAMP
                        "
                    );


                $linkStmt->execute(
                    [

                        ':user_id' =>
                            (int)$user['id'],

                        ':google_sub' =>
                            $googleSub,

                        ':email' =>
                            $googleEmail,

                        ':picture_url' =>
                            $googlePicture !== ''
                                ?
                                mb_substr(
                                    $googlePicture,
                                    0,
                                    2000
                                )
                                :
                                null

                    ]
                );

            }


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI GOOGLE EMAIL MATCH] '
                .
                $e->getMessage()
            );


            googleErrorResponse(
                'GOOGLE_EMAIL_MATCH_ERROR',
                'Unable to connect your Google account to LOVEMI.',
                500
            );

        }

    }


    /* ========================================================
       NEW GOOGLE USER
    ======================================================== */

    if (
        !$user
    ) {

        /*
         * Do not create the account here.
         *
         * Registration must collect the remaining LOVEMI
         * required information.
         */
        $_SESSION[
            'lovemi_google_signup'
        ] =
            [

                'google_sub' =>
                    $googleSub,

                'email' =>
                    $googleEmail,

                'full_names' =>
                    $googleName,

                'picture_url' =>
                    $googlePicture,

                'email_verified' =>
                    true,

                'created_at' =>
                    date(
                        'Y-m-d H:i:s'
                    )

            ];


        /*
         * Tell login.html to redirect using JSON.
         *
         * We do NOT send an HTTP Location header here because
         * login.html uses fetch() and expects JSON.
         */
        loginResponse(
            true,
            'Your Google account was verified. Please complete the LOVEMI registration form.',
            [

                'google_signup' =>
                    true,

                'authenticated' =>
                    false,

                'registration_required' =>
                    true,

                'code' =>
                    'GOOGLE_REGISTRATION_REQUIRED',

                'redirect' =>
                    'registration.html?google_signup=1'

            ]
        );

    }


    /* ========================================================
       ACCOUNT DELETED
    ======================================================== */

    if (
        (int)(
            $user['is_deleted']
            ??
            0
        )
        ===
        1
    ) {

        googleErrorResponse(
            'ACCOUNT_DELETED',
            'This LOVEMI account is no longer available.',
            403
        );

    }


    /* ========================================================
       ACCOUNT SUSPENDED / DISABLED
    ======================================================== */

    if (
        (int)(
            $user['is_suspended']
            ??
            0
        )
        ===
        1
        ||
        (int)(
            $user['is_active']
            ??
            0
        )
        !==
        1
        ||
        in_array(
            strtolower(
                trim(
                    (string)(
                        $user['account_status']
                        ??
                        ''
                    )
                )
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

        googleErrorResponse(
            'ACCOUNT_SUSPENDED',
            'Your LOVEMI account is currently suspended or disabled.',
            403
        );

    }


    /* ========================================================
       ACCOUNT APPROVAL
    ======================================================== */

    if (
        strtolower(
            trim(
                (string)(
                    $user['account_status']
                    ??
                    ''
                )
            )
        )
        !==
        'approved'
    ) {

        loginResponse(
            false,
            'Your LOVEMI account is not ready for login.',
            [

                'code' =>
                    'ACCOUNT_NOT_APPROVED',

                'user_id' =>
                    (int)$user['id'],

                'redirect' =>
                    'verify-account.html?user='
                    .
                    rawurlencode(
                        (string)$user['id']
                    )

            ],
            403
        );

    }


    /* ========================================================
       LOVEMI EMAIL VERIFICATION
    ======================================================== */

    if (
        !(bool)(
            $user['email_verified']
            ??
            false
        )
    ) {

        loginResponse(
            false,
            'Your LOVEMI email has not been verified yet.',
            [

                'code' =>
                    'EMAIL_NOT_VERIFIED',

                'user_id' =>
                    (int)$user['id'],

                'redirect' =>
                    'verify-account.html?user='
                    .
                    rawurlencode(
                        (string)$user['id']
                    )

            ],
            403
        );

    }


    /* ========================================================
       REFRESH GOOGLE ACCOUNT DETAILS
    ======================================================== */

    try {

        $refreshGoogle =
            $pdo->prepare(
                "
                UPDATE user_google_accounts

                SET

                    email =
                        :email,

                    picture_url =
                        :picture_url,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE google_sub =
                    :google_sub

                LIMIT 1
                "
            );


        $refreshGoogle->execute(
            [

                ':email' =>
                    $googleEmail,

                ':picture_url' =>
                    $googlePicture !== ''
                        ?
                        mb_substr(
                            $googlePicture,
                            0,
                            2000
                        )
                        :
                        null,

                ':google_sub' =>
                    $googleSub

            ]
        );


    } catch (
        Throwable $e
    ) {

        /*
         * Updating the profile image/email is secondary.
         * Login can continue if this update fails.
         */
        error_log(
            '[LOVEMI GOOGLE ACCOUNT REFRESH] '
            .
            $e->getMessage()
        );

    }


    /* ========================================================
       GOOGLE SESSION TOKEN
    ======================================================== */

    try {

        session_regenerate_id(
            true
        );


        $plainToken =
            bin2hex(
                random_bytes(
                    32
                )
            );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE SESSION TOKEN] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'SESSION_TOKEN_ERROR',
            'Unable to create a secure login session.',
            500
        );

    }


    $sessionTokenHash =
        hash(
            'sha256',
            $plainToken
        );


    /*
     * Google login does not automatically activate
     * "Remember me" unless the caller explicitly supplies it.
     */
    $remember =
        filter_var(
            $data['remember']
            ??
            false,
            FILTER_VALIDATE_BOOLEAN
        );


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


    /* ========================================================
       CREATE PENDING SESSION
    ======================================================== */

    try {

        $pdo->beginTransaction();


        /*
         * Preserve the same LOVEMI policy as normal password
         * login: revoke active previous sessions for this user.
         */
        $revoke =
            $pdo->prepare(
                "
                UPDATE user_sessions

                SET
                    revoked_at =
                        CURRENT_TIMESTAMP

                WHERE user_id =
                    :user_id

                  AND revoked_at IS NULL
                "
            );


        $revoke->execute(
            [

                ':user_id' =>
                    (int)$user['id']

            ]
        );


        /*
         * Create the new pending session.
         *
         * two_factor_passed remains FALSE until
         * verify-2fa.php completes the security step.
         */
        $insert =
            $pdo->prepare(
                "
                INSERT INTO user_sessions
                (
                    user_id,
                    session_token_hash,
                    device_id,
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
                    :device_id,
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
                    (int)$user['id'],

                ':token_hash' =>
                    $sessionTokenHash,

                ':device_id' =>
                    $deviceId !== ''
                        ?
                        $deviceId
                        :
                        null,

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
            (int)$pdo->lastInsertId();


        /*
         * Update Google account's last successful use through
         * updated_at. The current migration does not require a
         * separate last_login_at column.
         */
        $touchGoogle =
            $pdo->prepare(
                "
                UPDATE user_google_accounts

                SET
                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE google_sub =
                    :google_sub

                LIMIT 1
                "
            );


        $touchGoogle->execute(
            [

                ':google_sub' =>
                    $googleSub

            ]
        );


        /*
         * Login audit.
         *
         * Use the existing login_logs table when available.
         */
        try {

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
                        'google_verified_2fa_pending',
                        :ip,
                        :agent
                    )
                    "
                );


            $log->execute(
                [

                    ':user_id' =>
                        (int)$user['id'],

                    ':identifier' =>
                        mb_substr(
                            $googleEmail,
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


        } catch (
            Throwable $logError
        ) {

            /*
             * Audit failure must not destroy a valid login
             * transaction, but it should be logged.
             */
            error_log(
                '[LOVEMI GOOGLE LOGIN LOG ERROR] '
                .
                $logError->getMessage()
            );

        }


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
            '[LOVEMI GOOGLE SESSION CREATION] '
            .
            $e->getMessage()
        );


        googleErrorResponse(
            'SESSION_CREATION_ERROR',
            'Unable to create your LOVEMI login session.',
            500
        );

    }


    /* ========================================================
       PHP SESSION VALUES
    ======================================================== */

    $_SESSION[
        'lovemi_user_id'
    ] =
        (int)$user['id'];


    $_SESSION[
        'lovemi_session_token'
    ] =
        $plainToken;


    $_SESSION[
        'lovemi_database_session_id'
    ] =
        $databaseSessionId;


    $_SESSION[
        'lovemi_2fa_pending_user_id'
    ] =
        (int)$user['id'];


    $_SESSION[
        'lovemi_role_slug'
    ] =
        strtolower(
            trim(
                (string)(
                    $user['role_slug']
                    ??
                    ''
                )
            )
        );


    $_SESSION[
        'lovemi_device_id'
    ] =
        $deviceId;


    $_SESSION[
        'lovemi_device_name'
    ] =
        $deviceName;


    $_SESSION[
        'lovemi_browser_name'
    ] =
        $browserName;


    $_SESSION[
        'lovemi_operating_system'
    ] =
        $operatingSystem;


    $_SESSION[
        'lovemi_google_login'
    ] =
        true;


    $_SESSION[
        'lovemi_google_sub'
    ] =
        $googleSub;


    /*
     * The temporary Google signup information is no longer
     * required for an existing account.
     */
    unset(
        $_SESSION[
            'lovemi_google_signup'
        ]
    );


    /* ========================================================
       GOOGLE AUTHENTICATOR STATUS
    ======================================================== */

    $twoFactorEnabled =
        (bool)(
            $user['two_factor_enabled']
            ??
            false
        );


    $secretExists =
        !empty(
            $user[
                'two_factor_secret_encrypted'
            ]
        );


    /* ========================================================
       2FA CONFIGURATION ERROR
    ======================================================== */

    if (
        $twoFactorEnabled
        &&
        !$secretExists
    ) {

        error_log(
            '[LOVEMI SECURITY] User '
            .
            (int)$user['id']
            .
            ' has 2FA enabled but no secret.'
        );


        loginResponse(
            false,
            'Your two-step verification configuration needs to be repaired. Please contact LOVEMI support.',
            [

                'code' =>
                    '2FA_CONFIGURATION_ERROR',

                'user_id' =>
                    (int)$user['id']

            ],
            409
        );

    }


    /* ========================================================
       GOOGLE AUTHENTICATOR ALREADY CONFIGURED
    ======================================================== */

    if (
        $twoFactorEnabled
        &&
        $secretExists
    ) {

        loginResponse(
            true,
            'Google account verified. Enter your Google Authenticator code to complete login.',
            [

                'authenticated' =>
                    false,

                'google_authenticated' =>
                    true,

                'password_verified' =>
                    false,

                'google_verified' =>
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
                    (int)$user['id'],

                'role' =>
                    $_SESSION[
                        'lovemi_role_slug'
                    ],

                'redirect' =>
                    'verify-account.html?step=login-2fa'

            ]
        );

    }


    /* ========================================================
       GOOGLE AUTHENTICATOR SETUP REQUIRED
    ======================================================== */

    loginResponse(
        true,
        'Google account verified. Complete Google Authenticator setup before entering LOVEMI.',
        [

            'authenticated' =>
                false,

            'google_authenticated' =>
                true,

            'google_verified' =>
                true,

            'password_verified' =>
                false,

            'two_factor_required' =>
                true,

            'two_factor_enabled' =>
                false,

            'two_factor_passed' =>
                false,

            'code' =>
                'TWO_FACTOR_SETUP_REQUIRED',

            'user_id' =>
                (int)$user['id'],

            'role' =>
                $_SESSION[
                    'lovemi_role_slug'
                ],

            'redirect' =>
                'verify-account.html?step=2fa'

        ]
    );

}


/* ============================================================
   NORMAL LOGIN INPUT
============================================================ */

$identifier =
    trim(
        (string)(
            $data['identifier']
            ??
            ''
        )
    );


$password =
    (string)(
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
   NORMAL LOGIN VALIDATION
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


} catch (
    Throwable $e
) {

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
   USER QUERY
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
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );


} catch (
    Throwable $e
) {

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
    (bool)$user['is_deleted']
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
   ACCOUNT DISABLED
============================================================ */

if (
    !(bool)$user['is_active']
    ||
    (bool)$user['is_suspended']
    ||
    in_array(
        strtolower(
            (string)(
                $user['account_status']
            )
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
   PASSWORD VERIFY
============================================================ */

$passwordValid =
    password_verify(
        $password,
        (string)(
            $user['password_hash']
        )
    );


if (
    !$passwordValid
) {

    /*
     * Failed login audit.
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
                    (int)$user['id'],

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


    } catch (
        Throwable $e
    ) {

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
        (string)(
            $user['password_hash']
        ),
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

                    SET
                        password_hash =
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
                        (int)$user['id']

                ]
            );

        }


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PASSWORD REHASH ERROR] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   EMAIL VERIFIED
============================================================ */

if (
    !(bool)$user['email_verified']
) {

    loginResponse(
        false,
        'Your email has not been verified yet. Continue from the email verification step.',
        [

            'code' =>
                'EMAIL_NOT_VERIFIED',

            'user_id' =>
                (int)$user['id'],

            'redirect' =>
                'verify-account.html?user='
                .
                rawurlencode(
                    (string)$user['id']
                )

        ],
        403
    );

}


/* ============================================================
   ACCOUNT APPROVED
============================================================ */

if (
    strtolower(
        (string)(
            $user['account_status']
        )
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
                (int)$user['id'],

            'redirect' =>
                'verify-account.html?user='
                .
                rawurlencode(
                    (string)$user['id']
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
   SESSION TOKEN
============================================================ */

try {

    $plainToken =
        bin2hex(
            random_bytes(
                32
            )
        );


} catch (
    Throwable $e
) {

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
   CREATE PENDING SESSION
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Revoke older active sessions for this user.
     */
    $revoke =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                revoked_at =
                    CURRENT_TIMESTAMP

            WHERE user_id =
                :user_id

              AND revoked_at IS NULL
            "
        );


    $revoke->execute(
        [

            ':user_id' =>
                (int)$user['id']

        ]
    );


    /*
     * Create pending session.
     */
    $insert =
        $pdo->prepare(
            "
            INSERT INTO user_sessions
            (
                user_id,
                session_token_hash,
                device_id,
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
                :device_id,
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
                (int)$user['id'],

            ':token_hash' =>
                $sessionTokenHash,

            ':device_id' =>
                $deviceId !== ''
                    ?
                    $deviceId
                    :
                    null,

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
        (int)$pdo->lastInsertId();


    /*
     * Login audit.
     */
    try {

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
                    (int)$user['id'],

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


    } catch (
        Throwable $logError
    ) {

        error_log(
            '[LOVEMI LOGIN LOG ERROR] '
            .
            $logError->getMessage()
        );

    }


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
   PHP SESSION VALUES
============================================================ */

$_SESSION[
    'lovemi_user_id'
] =
    (int)$user['id'];


$_SESSION[
    'lovemi_session_token'
] =
    $plainToken;


$_SESSION[
    'lovemi_database_session_id'
] =
    $databaseSessionId;


$_SESSION[
    'lovemi_2fa_pending_user_id'
] =
    (int)$user['id'];


$_SESSION[
    'lovemi_role_slug'
] =
    strtolower(
        trim(
            (string)(
                $user['role_slug']
                ??
                ''
            )
        )
    );


$_SESSION[
    'lovemi_device_id'
] =
    $deviceId;


$_SESSION[
    'lovemi_device_name'
] =
    $deviceName;


$_SESSION[
    'lovemi_browser_name'
] =
    $browserName;


$_SESSION[
    'lovemi_operating_system'
] =
    $operatingSystem;


/* ============================================================
   REMOVE OLD GOOGLE MARKER
============================================================ */

unset(
    $_SESSION[
        'lovemi_google_login'
    ]
);


/* ============================================================
   GOOGLE AUTHENTICATOR CHECK
============================================================ */

$twoFactorEnabled =
    (bool)$user['two_factor_enabled'];


$secretExists =
    !empty(
        $user[
            'two_factor_secret_encrypted'
        ]
    );


/* ============================================================
   SECURITY CONFIGURATION ERROR
============================================================ */

if (
    $twoFactorEnabled
    &&
    !$secretExists
) {

    error_log(
        '[LOVEMI SECURITY] User '
        .
        (int)$user['id']
        .
        ' has 2FA enabled but no secret.'
    );


    loginResponse(
        false,
        'Your two-step verification configuration needs to be repaired. Please contact LOVEMI support.',
        [

            'code' =>
                '2FA_CONFIGURATION_ERROR'

        ],
        409
    );

}


/* ============================================================
   TWO FACTOR ALREADY CONFIGURED
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
                (int)$user['id'],

            'role' =>
                $_SESSION[
                    'lovemi_role_slug'
                ],

            'redirect' =>
                'verify-account.html?step=login-2fa'

        ]
    );

}


/* ============================================================
   TWO FACTOR SETUP REQUIRED
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
            (int)$user['id'],

        'role' =>
            $_SESSION[
                'lovemi_role_slug'
            ],

        'redirect' =>
            'verify-account.html?step=2fa'

    ]
);