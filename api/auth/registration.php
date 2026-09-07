<?php
/**
 * ============================================================
 * LOVEMI - REGISTRATION API
 * ============================================================
 *
 * Supports:
 *
 * 1. Normal LOVEMI registration
 * 2. Google registration preparation
 * 3. Google registration session retrieval
 *
 * Existing registration behavior remains:
 * - Username
 * - Full names
 * - Gender
 * - Date of birth
 * - Email
 * - Country
 * - Phone
 * - ID number
 * - Password
 * - First-admin registration
 * - Terms
 * - Email verification
 *
 * Added:
 * - Current city
 * - Education level
 * - University / College
 * - Course
 * - Google account registration
 * - Google account linking
 * - Official welcome email
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


/* ============================================================
   GOOGLE CONFIG
============================================================ */

require_once
    __DIR__
    . '/../../config/google.php';


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

if (
    session_status() !== PHP_SESSION_ACTIVE
) {

    session_start();

}


/* ============================================================
   RESPONSE
============================================================ */

function registrationResponse(
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
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;
}


/* ============================================================
   GOOGLE CSRF TOKEN
============================================================ */

function getGoogleCsrfToken(): string
{

    if (
        empty(
            $_SESSION[
                'lovemi_registration_google_csrf'
            ]
        )
    ) {

        $_SESSION[
            'lovemi_registration_google_csrf'
        ] =
            bin2hex(
                random_bytes(32)
            );

    }


    return (string)
        $_SESSION[
            'lovemi_registration_google_csrf'
        ];

}


/* ============================================================
   VALIDATE GOOGLE CSRF
============================================================ */

function validateGoogleCsrf(
    string $token
): bool {

    $sessionToken =
        (string)(
            $_SESSION[
                'lovemi_registration_google_csrf'
            ]
            ??
            ''
        );


    if (
        $sessionToken === ''
        ||
        $token === ''
    ) {

        return false;

    }


    return hash_equals(
        $sessionToken,
        $token
    );

}


/* ============================================================
   GOOGLE TOKEN INFO
============================================================ */

function requestGoogleTokenInfo(
    string $idToken
): array {

    if (
        trim(
            $idToken
        ) === ''
    ) {

        throw new RuntimeException(
            'GOOGLE_TOKEN_REQUIRED'
        );

    }


    $url =
        'https://oauth2.googleapis.com/tokeninfo?id_token='
        .
        rawurlencode(
            $idToken
        );


    /* ========================================================
       CURL
    ======================================================== */

    if (
        function_exists(
            'curl_init'
        )
    ) {

        $curl =
            curl_init(
                $url
            );


        curl_setopt_array(
            $curl,
            [

                CURLOPT_RETURNTRANSFER =>
                    true,

                CURLOPT_FOLLOWLOCATION =>
                    false,

                CURLOPT_CONNECTTIMEOUT =>
                    10,

                CURLOPT_TIMEOUT =>
                    15,

                CURLOPT_SSL_VERIFYPEER =>
                    true,

                CURLOPT_SSL_VERIFYHOST =>
                    2,

                CURLOPT_HTTPHEADER =>
                    [
                        'Accept: application/json'
                    ]

            ]
        );


        $body =
            curl_exec(
                $curl
            );


        $httpCode =
            (int)
            curl_getinfo(
                $curl,
                CURLINFO_HTTP_CODE
            );


        $curlError =
            curl_error(
                $curl
            );


        curl_close(
            $curl
        );


        if (
            $body === false
        ) {

            error_log(
                '[LOVEMI GOOGLE TOKEN CURL] '
                .
                $curlError
            );


            throw new RuntimeException(
                'GOOGLE_TOKEN_VALIDATION_FAILED'
            );

        }

    } else {

        /* ====================================================
           FILE GET CONTENTS FALLBACK
        ==================================================== */

        $context =
            stream_context_create(
                [

                    'http' =>
                        [

                            'method' =>
                                'GET',

                            'timeout' =>
                                15,

                            'ignore_errors' =>
                                true,

                            'header' =>
                                "Accept: application/json\r\n"

                        ],

                    'ssl' =>
                        [

                            'verify_peer' =>
                                true,

                            'verify_peer_name' =>
                                true

                        ]

                ]
            );


        $body =
            @file_get_contents(
                $url,
                false,
                $context
            );


        $httpCode =
            0;


        if (
            isset(
                $http_response_header
            )
            &&
            is_array(
                $http_response_header
            )
        ) {

            foreach (
                $http_response_header
                as $header
            ) {

                if (
                    preg_match(
                        '#HTTP/\S+\s+(\d+)#',
                        $header,
                        $matches
                    )
                ) {

                    $httpCode =
                        (int)
                        $matches[1];

                    break;

                }

            }

        }

    }


    if (
        !is_string(
            $body
        )
        ||
        trim(
            $body
        ) === ''
    ) {

        throw new RuntimeException(
            'GOOGLE_TOKEN_EMPTY'
        );

    }


    $payload =
        json_decode(
            $body,
            true
        );


    if (
        !is_array(
            $payload
        )
    ) {

        throw new RuntimeException(
            'GOOGLE_TOKEN_INVALID'
        );

    }


    if (
        $httpCode >= 400
        ||
        isset(
            $payload['error']
        )
    ) {

        throw new RuntimeException(
            'GOOGLE_TOKEN_REJECTED'
        );

    }


    return $payload;

}


/* ============================================================
   VALIDATE GOOGLE IDENTITY
============================================================ */

function validateGoogleIdentity(
    string $credential
): array {

    $payload =
        requestGoogleTokenInfo(
            $credential
        );


    $clientId =
        lovemiGoogleClientId();


    if (
        $clientId === ''
    ) {

        throw new RuntimeException(
            'GOOGLE_CLIENT_ID_NOT_CONFIGURED'
        );

    }


    $issuer =
        trim(
            (string)(
                $payload['iss']
                ??
                ''
            )
        );


    $audience =
        trim(
            (string)(
                $payload['aud']
                ??
                ''
            )
        );


    $sub =
        trim(
            (string)(
                $payload['sub']
                ??
                ''
            )
        );


    $email =
        strtolower(
            trim(
                (string)(
                    $payload['email']
                    ??
                    ''
                )
            )
        );


    $emailVerified =
        filter_var(
            $payload['email_verified']
                ??
                false,
            FILTER_VALIDATE_BOOLEAN
        );


    $fullNames =
        trim(
            (string)(
                $payload['name']
                ??
                ''
            )
        );


    $picture =
        trim(
            (string)(
                $payload['picture']
                ??
                ''
            )
        );


    $expiresAt =
        isset(
            $payload['exp']
        )
            ?
            (int)
            $payload['exp']
            :
            0;


    /* ========================================================
       ISSUER
    ======================================================== */

    if (
        !in_array(
            $issuer,
            [
                'accounts.google.com',
                'https://accounts.google.com'
            ],
            true
        )
    ) {

        throw new RuntimeException(
            'GOOGLE_ISSUER_INVALID'
        );

    }


    /* ========================================================
       AUDIENCE
    ======================================================== */

    if (
        !hash_equals(
            $clientId,
            $audience
        )
    ) {

        throw new RuntimeException(
            'GOOGLE_AUDIENCE_INVALID'
        );

    }


    /* ========================================================
       SUB
    ======================================================== */

    if (
        $sub === ''
    ) {

        throw new RuntimeException(
            'GOOGLE_SUB_MISSING'
        );

    }


    /* ========================================================
       EMAIL
    ======================================================== */

    if (
        !filter_var(
            $email,
            FILTER_VALIDATE_EMAIL
        )
    ) {

        throw new RuntimeException(
            'GOOGLE_EMAIL_INVALID'
        );

    }


    /* ========================================================
       EMAIL VERIFIED
    ======================================================== */

    if (
        !$emailVerified
    ) {

        throw new RuntimeException(
            'GOOGLE_EMAIL_NOT_VERIFIED'
        );

    }


    /* ========================================================
       EXPIRATION
    ======================================================== */

    if (
        $expiresAt <= 0
        ||
        $expiresAt < time()
    ) {

        throw new RuntimeException(
            'GOOGLE_TOKEN_EXPIRED'
        );

    }


    /* ========================================================
       FALLBACK NAME
    ======================================================== */

    if (
        $fullNames === ''
    ) {

        $emailName =
            strstr(
                $email,
                '@',
                true
            );


        $fullNames =
            $emailName
            ?:
            'LOVEMI Member';

    }


    return [

        'sub' =>
            $sub,

        'email' =>
            $email,

        'full_names' =>
            $fullNames,

        'picture' =>
            $picture

    ];

}


/* ============================================================
   APP URL
============================================================ */

function lovemiApplicationUrl(): string
{

    $configured =
        getenv(
            'LOVEMI_APP_URL'
        );


    if (
        is_string(
            $configured
        )
        &&
        trim(
            $configured
        ) !== ''
    ) {

        return rtrim(
            trim(
                $configured
            ),
            '/'
        );

    }


    $scheme =
        (
            !empty(
                $_SERVER['HTTPS']
            )
            &&
            strtolower(
                (string)
                $_SERVER['HTTPS']
            ) !== 'off'
        )
            ?
            'https'
            :
            'http';


    $host =
        preg_replace(
            '/[^A-Za-z0-9.\-:\[\]]/',
            '',
            (string)(
                $_SERVER['HTTP_HOST']
                ??
                'localhost'
            )
        );


    return
        $scheme
        .
        '://'
        .
        $host
        .
        '/LOVEMI';

}


/* ============================================================
   WELCOME EMAIL
============================================================ */

function sendLovemiWelcomeEmail(
    string $recipientEmail,
    string $recipientName,
    string $username,
    string $city,
    string $educationLevel,
    string $universityName,
    string $course,
    bool $googleSignup
): bool {

    try {

        require_once
            __DIR__
            .
            '/../../services/email/email-service.php';


        if (
            !function_exists(
                'lovemiMail'
            )
        ) {

            throw new RuntimeException(
                'LOVEMI_MAIL_SERVICE_NOT_FOUND'
            );

        }


        $mailer =
            lovemiMail();


        $mailer->addAddress(
            $recipientEmail,
            $recipientName
        );


        /* ====================================================
           EMBED LOVEMI LOGO
        ==================================================== */

        $logoPath =
            dirname(
                __DIR__,
                2
            )
            .
            DIRECTORY_SEPARATOR
            .
            'assets'
            .
            DIRECTORY_SEPARATOR
            .
            'logo1'
            .
            DIRECTORY_SEPARATOR
            .
            'logo1.png';


        if (
            is_file(
                $logoPath
            )
        ) {

            $mailer->addEmbeddedImage(
                $logoPath,
                'lovemi_logo',
                'logo1.png',
                'base64',
                'image/png'
            );

        }


        $safeName =
            htmlspecialchars(
                $recipientName,
                ENT_QUOTES,
                'UTF-8'
            );


        $safeUsername =
            htmlspecialchars(
                $username,
                ENT_QUOTES,
                'UTF-8'
            );


        $safeCity =
            htmlspecialchars(
                $city,
                ENT_QUOTES,
                'UTF-8'
            );


        $safeEducation =
            htmlspecialchars(
                $educationLevel,
                ENT_QUOTES,
                'UTF-8'
            );


        $safeUniversity =
            htmlspecialchars(
                $universityName !== ''
                    ?
                    $universityName
                    :
                    'Not provided',
                ENT_QUOTES,
                'UTF-8'
            );


        $safeCourse =
            htmlspecialchars(
                $course !== ''
                    ?
                    $course
                    :
                    'Not provided',
                ENT_QUOTES,
                'UTF-8'
            );


        $registrationMethod =
            $googleSignup
                ?
                'Google account registration'
                :
                'Standard LOVEMI registration';


        $appUrl =
            htmlspecialchars(
                lovemiApplicationUrl(),
                ENT_QUOTES,
                'UTF-8'
            );


        $createdAt =
            htmlspecialchars(
                date(
                    'F j, Y \a\t H:i'
                ),
                ENT_QUOTES,
                'UTF-8'
            );


        $mailer->isHTML(
            true
        );


        $mailer->Subject =
            'Welcome to LOVEMI — Your Account Has Been Created';


        $logoHtml =
            is_file(
                $logoPath
            )
                ?
                '
                <img
                    src="cid:lovemi_logo"
                    alt="LOVEMI"
                    style="
                        width:76px;
                        height:76px;
                        object-fit:contain;
                        border-radius:18px;
                        margin-bottom:15px;
                    "
                >
                '
                :
                '';


        $mailer->Body = '

<!doctype html>

<html>

<head>

<meta charset="UTF-8">

<title>Welcome to LOVEMI</title>

</head>

<body
    style="
        margin:0;
        padding:0;
        background:#f7f7fb;
        font-family:Arial,Helvetica,sans-serif;
        color:#18181b;
    "
>

<table
    width="100%"
    cellpadding="0"
    cellspacing="0"
    border="0"
    style="
        background:#f7f7fb;
        padding:30px 15px;
    "
>

<tr>

<td align="center">

<table
    width="100%"
    cellpadding="0"
    cellspacing="0"
    border="0"
    style="
        max-width:640px;
        background:#ffffff;
        border-radius:22px;
        overflow:hidden;
        box-shadow:0 12px 35px rgba(0,0,0,.08);
    "
>

<tr>

<td
    align="center"
    style="
        padding:35px 25px;
        background:linear-gradient(
            135deg,
            #3f176f,
            #6d28d9,
            #9d174d
        );
    "
>

'
.
$logoHtml
.
'

<div
    style="
        color:#ffffff;
        font-size:30px;
        font-weight:800;
    "
>
LOVEMI
</div>

<div
    style="
        color:rgba(255,255,255,.78);
        font-size:10px;
        margin-top:5px;
        letter-spacing:1px;
    "
>
DISCOVER • CONNECT • MEET
</div>

</td>

</tr>

<tr>

<td style="padding:35px;">

<h1
    style="
        margin:0 0 12px;
        color:#18181b;
        font-size:24px;
    "
>
Welcome to LOVEMI, '
.
$safeName
.
'
</h1>

<p
    style="
        color:#55555c;
        font-size:14px;
        line-height:1.7;
        margin:0 0 15px;
    "
>
Thank you for creating your LOVEMI account.
We are pleased to welcome you to LOVEMI.
</p>

<p
    style="
        color:#55555c;
        font-size:14px;
        line-height:1.7;
        margin:0 0 20px;
    "
>
Your registration has been successfully received.
Please complete the email verification process using
the separate verification email sent to this address.
</p>

<table
    width="100%"
    cellpadding="0"
    cellspacing="0"
    border="0"
    style="
        border:1px solid #eeeeef;
        border-radius:15px;
        overflow:hidden;
        margin:20px 0;
    "
>

<tr>

<td
    colspan="2"
    style="
        padding:14px 15px;
        background:#faf8ff;
        color:#6d28d9;
        font-weight:800;
        font-size:13px;
    "
>
Registration Details
</td>

</tr>

<tr>

<td
    style="
        width:42%;
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Username
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$safeUsername
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Current City
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$safeCity
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Education Level
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$safeEducation
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
University / College
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$safeUniversity
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Course
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$safeCourse
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Registration Method
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
htmlspecialchars(
    $registrationMethod,
    ENT_QUOTES,
    'UTF-8'
)
.
'
</td>

</tr>

<tr>

<td
    style="
        padding:10px 15px;
        color:#777;
        font-size:12px;
    "
>
Created
</td>

<td
    style="
        padding:10px 15px;
        font-size:12px;
        font-weight:700;
    "
>
'
.
$createdAt
.
'
</td>

</tr>

</table>

<div
    style="
        text-align:center;
        margin:25px 0;
    "
>

<a
    href="'
.
$appUrl
.
'"
    style="
        display:inline-block;
        padding:13px 25px;
        color:#ffffff;
        background:linear-gradient(
            135deg,
            #6d28d9,
            #db2777
        );
        border-radius:10px;
        text-decoration:none;
        font-weight:800;
        font-size:13px;
    "
>
Open LOVEMI
</a>

</div>

<p
    style="
        color:#777;
        font-size:12px;
        line-height:1.7;
        margin:0;
    "
>
Please keep your LOVEMI account information secure.
If you did not create this account, please contact
LOVEMI support immediately.
</p>

</td>

</tr>

<tr>

<td
    style="
        padding:20px 35px 30px;
        border-top:1px solid #eeeeef;
        color:#999;
        font-size:11px;
        line-height:1.6;
    "
>

<strong
    style="color:#6d28d9;"
>
LOVEMI
</strong>

<br>

Discover • Connect • Meet

<br>

This is an official automated message from LOVEMI.

</td>

</tr>

</table>

</td>

</tr>

</table>

</body>

</html>
';


        $mailer->AltBody =
            "Welcome to LOVEMI, {$recipientName}.\n\n"
            .
            "Thank you for creating your LOVEMI account.\n\n"
            .
            "Username: {$username}\n"
            .
            "Current City: {$city}\n"
            .
            "Education Level: {$educationLevel}\n"
            .
            "University / College: "
            .
            (
                $universityName !== ''
                    ?
                    $universityName
                    :
                    'Not provided'
            )
            .
            "\n"
            .
            "Course: "
            .
            (
                $course !== ''
                    ?
                    $course
                    :
                    'Not provided'
            )
            .
            "\n"
            .
            "Registration Method: "
            .
            $registrationMethod
            .
            "\n\n"
            .
            "Please complete the email verification process."
            .
            "\n\n"
            .
            "LOVEMI"
            .
            "\nDiscover • Connect • Meet";


        return
            (bool)
            $mailer->send();


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI WELCOME EMAIL ERROR] '
            .
            $e->getMessage()
        );


        return false;

    }

}


/* ============================================================
   REQUEST METHOD
============================================================ */

$method =
    strtoupper(
        trim(
            (string)(
                $_SERVER['REQUEST_METHOD']
                ??
                ''
            )
        )
    );


$action =
    strtolower(
        trim(
            (string)(
                $_GET['action']
                ??
                ''
            )
        )
    );


/* ============================================================
   GOOGLE CONFIG ENDPOINT
============================================================ */

if (
    $method === 'GET'
    &&
    $action === 'google-config'
) {

    registrationResponse(
        true,
        'Google registration configuration loaded.',
        [
            'client_id' =>
                lovemiGoogleClientId(),

            'csrf_token' =>
                getGoogleCsrfToken()
        ]
    );

}


/* ============================================================
   GOOGLE SESSION ENDPOINT
============================================================ */

if (
    $method === 'GET'
    &&
    $action === 'google-session'
) {

    $google =
        $_SESSION[
            'lovemi_google_signup'
        ]
        ??
        null;


    if (
        !is_array(
            $google
        )
        ||
        empty(
            $google['sub']
        )
        ||
        empty(
            $google['email']
        )
    ) {

        registrationResponse(
            false,
            'No pending Google registration was found.',
            [
                'code' =>
                    'GOOGLE_SIGNUP_SESSION_NOT_FOUND'
            ],
            404
        );

    }


    if (
        isset(
            $google['created_at']
        )
        &&
        (
            time()
            -
            (int)
            $google['created_at']
        ) > 1800
    ) {

        unset(
            $_SESSION[
                'lovemi_google_signup'
            ]
        );


        registrationResponse(
            false,
            'Your Google registration session has expired. Please start again.',
            [
                'code' =>
                    'GOOGLE_SESSION_EXPIRED'
            ],
            422
        );

    }


    registrationResponse(
        true,
        'Pending Google registration loaded.',
        [
            'google' =>
                [
                    'sub' =>
                        (string)
                        $google['sub'],

                    'email' =>
                        (string)
                        $google['email'],

                    'full_names' =>
                        (string)
                        (
                            $google['full_names']
                            ??
                            ''
                        ),

                    'picture' =>
                        (string)
                        (
                            $google['picture']
                            ??
                            ''
                        )
                ]
        ]
    );

}


/* ============================================================
   GOOGLE PREPARE
============================================================ */

if (
    $method === 'POST'
    &&
    $action === 'google-prepare'
) {

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
        !is_array(
            $data
        )
    ) {

        $data = [];

    }


    $csrfToken =
        trim(
            (string)(
                $data['csrf_token']
                ??
                ''
            )
        );


    if (
        !validateGoogleCsrf(
            $csrfToken
        )
    ) {

        registrationResponse(
            false,
            'Google registration security validation failed. Please refresh the page and try again.',
            [
                'code' =>
                    'GOOGLE_CSRF_FAILED'
            ],
            403
        );

    }


    $credential =
        trim(
            (string)(
                $data['credential']
                ??
                ''
            )
        );


    try {

        $google =
            validateGoogleIdentity(
                $credential
            );


        $pdo =
            db();


        /* ====================================================
           CHECK GOOGLE SUB
        ==================================================== */

        $stmt =
            $pdo->prepare(
                "
                SELECT user_id
                FROM user_google_accounts
                WHERE google_sub = :google_sub
                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':google_sub' =>
                    $google['sub']
            ]
        );


        if (
            $stmt->fetch()
        ) {

            registrationResponse(
                false,
                'This Google account is already connected to LOVEMI. Please use Login with Google.',
                [
                    'code' =>
                        'ACCOUNT_EXISTS'
                ],
                409
            );

        }


        /* ====================================================
           CHECK EMAIL
        ==================================================== */

        $stmt =
            $pdo->prepare(
                "
                SELECT
                    id,
                    username,
                    full_names,
                    account_status
                FROM users
                WHERE LOWER(email) =
                      LOWER(:email)
                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':email' =>
                    $google['email']
            ]
        );


        $existingUser =
            $stmt->fetch();


        if (
            $existingUser
        ) {

            registrationResponse(
                false,
                'A LOVEMI account already exists with this email address. Please use Login with Google or your existing login details.',
                [
                    'code' =>
                        'ACCOUNT_EXISTS',

                    'user_id' =>
                        (int)
                        $existingUser['id']
                ],
                409
            );

        }


        /* ====================================================
           STORE TRUSTED GOOGLE SESSION
        ==================================================== */

        $_SESSION[
            'lovemi_google_signup'
        ] =
            [

                'sub' =>
                    $google['sub'],

                'email' =>
                    $google['email'],

                'full_names' =>
                    $google['full_names'],

                'picture' =>
                    $google['picture'],

                'created_at' =>
                    time()

            ];


        registrationResponse(
            true,
            'Google account accepted. Complete the remaining LOVEMI registration details.',
            [
                'google' =>
                    [
                        'sub' =>
                            $google['sub'],

                        'email' =>
                            $google['email'],

                        'full_names' =>
                            $google['full_names'],

                        'picture' =>
                            $google['picture']
                    ]
            ]
        );


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GOOGLE PREPARE ERROR] '
            .
            $e->getMessage()
        );


        $message =
            'Google registration could not be completed. Please try again.';


        switch (
            $e->getMessage()
        ) {

            case 'GOOGLE_CLIENT_ID_NOT_CONFIGURED':

                $message =
                    'Google registration is not configured on the LOVEMI server.';

                break;


            case 'GOOGLE_EMAIL_NOT_VERIFIED':

                $message =
                    'Google did not provide a verified email address.';

                break;


            case 'GOOGLE_AUDIENCE_INVALID':

                $message =
                    'The Google client ID configured for LOVEMI does not match the Google account configuration.';

                break;


            case 'GOOGLE_TOKEN_EXPIRED':

                $message =
                    'The Google registration request has expired. Please try again.';

                break;

        }


        registrationResponse(
            false,
            $message,
            [
                'code' =>
                    'GOOGLE_REGISTRATION_FAILED'
            ],
            422
        );

    }

}


/* ============================================================
   NORMAL REGISTRATION
============================================================ */

if (
    $method !== 'POST'
) {

    registrationResponse(
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
   REQUEST DATA
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
    !is_array(
        $data
    )
    ||
    empty(
        $data
    )
) {

    /*
     * Keep compatibility with normal
     * application/x-www-form-urlencoded requests.
     */

    $data =
        $_POST;

}


if (
    !is_array(
        $data
    )
) {

    $data = [];

}


/* ============================================================
   GOOGLE REGISTRATION FLAG
============================================================ */

$googleSignup =
    filter_var(
        $data['google_signup']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


$pendingGoogle =
    $_SESSION[
        'lovemi_google_signup'
    ]
    ??
    null;


/* ============================================================
   TRUST GOOGLE EMAIL FROM SESSION
============================================================ */

if (
    $googleSignup
) {

    if (
        !is_array(
            $pendingGoogle
        )
        ||
        empty(
            $pendingGoogle['sub']
        )
        ||
        empty(
            $pendingGoogle['email']
        )
    ) {

        registrationResponse(
            false,
            'Your Google registration session has expired. Please start Google registration again.',
            [
                'code' =>
                    'GOOGLE_SESSION_EXPIRED'
            ],
            422
        );

    }


    if (
        isset(
            $pendingGoogle['created_at']
        )
        &&
        (
            time()
            -
            (int)
            $pendingGoogle['created_at']
        ) > 1800
    ) {

        unset(
            $_SESSION[
                'lovemi_google_signup'
            ]
        );


        registrationResponse(
            false,
            'Your Google registration session has expired. Please start again.',
            [
                'code' =>
                    'GOOGLE_SESSION_EXPIRED'
            ],
            422
        );

    }


    $email =
        strtolower(
            trim(
                (string)
                $pendingGoogle['email']
            )
        );

} else {

    $email =
        strtolower(
            trim(
                (string)(
                    $data['email']
                    ??
                    ''
                )
            )
        );

}


/* ============================================================
   INPUTS
============================================================ */

$username =
    trim(
        (string)(
            $data['username']
            ??
            ''
        )
    );


$fullNames =
    trim(
        (string)(
            $data['full_names']
            ??
            ''
        )
    );


/*
 * Google supplies the initial name.
 */
if (
    $fullNames === ''
    &&
    $googleSignup
    &&
    is_array(
        $pendingGoogle
    )
) {

    $fullNames =
        trim(
            (string)(
                $pendingGoogle['full_names']
                ??
                ''
            )
        );

}


$gender =
    trim(
        (string)(
            $data['gender']
            ??
            ''
        )
    );


$dateOfBirth =
    trim(
        (string)(
            $data['date_of_birth']
            ??
            ''
        )
    );


$countryId =
    isset(
        $data['country_id']
    )
        ?
        (int)
        $data['country_id']
        :
        0;


$phoneCode =
    trim(
        (string)(
            $data['phone_code']
            ??
            ''
        )
    );


$phoneNumber =
    trim(
        (string)(
            $data['phone_number']
            ??
            ''
        )
    );


$idNumber =
    trim(
        (string)(
            $data['id_number']
            ??
            ''
        )
    );


$city =
    trim(
        (string)(
            $data['city']
            ??
            ''
        )
    );


$educationLevel =
    trim(
        (string)(
            $data['education_level']
            ??
            ''
        )
    );


$universityName =
    trim(
        (string)(
            $data['university_name']
            ??
            ''
        )
    );


$course =
    trim(
        (string)(
            $data['course']
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


$confirmPassword =
    (string)(
        $data['confirm_password']
        ??
        ''
    );


$registerAsAdmin =
    filter_var(
        $data['register_as_admin']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


$agree =
    filter_var(
        $data['agree']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    );


/* ============================================================
   USERNAME
============================================================ */

if (
    !preg_match(
        '/^[A-Za-z0-9_.-]{3,50}$/',
        $username
    )
) {

    registrationResponse(
        false,
        'Invalid username.',
        [
            'code' =>
                'INVALID_USERNAME'
        ],
        422
    );

}


/* ============================================================
   FULL NAMES
============================================================ */

if (
    mb_strlen(
        $fullNames
    ) < 2
    ||
    mb_strlen(
        $fullNames
    ) > 180
) {

    registrationResponse(
        false,
        'Please enter your full names.',
        [
            'code' =>
                'INVALID_FULL_NAMES'
        ],
        422
    );

}


/* ============================================================
   GENDER
============================================================ */

if (
    !in_array(
        $gender,
        [
            'Male',
            'Female',
            'Other'
        ],
        true
    )
) {

    registrationResponse(
        false,
        'Please select a valid gender.',
        [
            'code' =>
                'INVALID_GENDER'
        ],
        422
    );

}


/* ============================================================
   DATE OF BIRTH
============================================================ */

$dob =
    DateTime::createFromFormat(
        'Y-m-d',
        $dateOfBirth
    );


if (
    !$dob
    ||
    $dob->format(
        'Y-m-d'
    )
    !==
    $dateOfBirth
) {

    registrationResponse(
        false,
        'Please provide a valid date of birth.',
        [
            'code' =>
                'INVALID_DATE_OF_BIRTH'
        ],
        422
    );

}


$today =
    new DateTime(
        'today'
    );


if (
    $dob > $today
) {

    registrationResponse(
        false,
        'Date of birth cannot be in the future.',
        [],
        422
    );

}


$age =
    $dob->diff(
        $today
    )->y;


if (
    $age < 18
) {

    registrationResponse(
        false,
        'You must be at least 18 years old.',
        [
            'code' =>
                'UNDER_18'
        ],
        422
    );

}


/* ============================================================
   EMAIL
============================================================ */

if (
    !filter_var(
        $email,
        FILTER_VALIDATE_EMAIL
    )
) {

    registrationResponse(
        false,
        'Please enter a valid email address.',
        [
            'code' =>
                'INVALID_EMAIL'
        ],
        422
    );

}


/* ============================================================
   COUNTRY
============================================================ */

if (
    $countryId <= 0
) {

    registrationResponse(
        false,
        'Please select your country.',
        [
            'code' =>
                'COUNTRY_REQUIRED'
        ],
        422
    );

}


try {

    $pdo =
        db();


    $countryStmt =
        $pdo->prepare(
            "
            SELECT
                id,
                name,
                phone_code
            FROM countries
            WHERE id = :id
              AND is_active = TRUE
            LIMIT 1
            "
        );


    $countryStmt->execute(
        [
            ':id' =>
                $countryId
        ]
    );


    $country =
        $countryStmt->fetch();


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI REGISTRATION COUNTRY ERROR] '
        .
        $e->getMessage()
    );


    registrationResponse(
        false,
        'Unable to validate the selected country.',
        [],
        500
    );

}


if (
    !$country
) {

    registrationResponse(
        false,
        'The selected country is not available.',
        [
            'code' =>
                'COUNTRY_NOT_FOUND'
        ],
        422
    );

}


if (
    (string)
    $country['phone_code']
    !==
    $phoneCode
) {

    registrationResponse(
        false,
        'The phone country code does not match the selected country.',
        [
            'code' =>
                'PHONE_CODE_MISMATCH'
        ],
        422
    );

}


/* ============================================================
   PHONE
============================================================ */

$nationalPhone =
    preg_replace(
        '/[^0-9]/',
        '',
        $phoneNumber
    );


if (
    !is_string(
        $nationalPhone
    )
    ||
    strlen(
        $nationalPhone
    ) < 5
) {

    registrationResponse(
        false,
        'Please enter a valid phone number.',
        [
            'code' =>
                'INVALID_PHONE'
        ],
        422
    );

}


$phoneE164 =
    $phoneCode .
    $nationalPhone;


if (
    strlen(
        $phoneE164
    ) > 20
) {

    registrationResponse(
        false,
        'Phone number is too long.',
        [
            'code' =>
                'INVALID_PHONE'
        ],
        422
    );

}


/* ============================================================
   ID NUMBER HASH
============================================================ */

$normalizedId =
    strtolower(
        preg_replace(
            '/[\s-]+/',
            '',
            $idNumber
        )
    );


if (
    strlen(
        $normalizedId
    ) < 4
) {

    registrationResponse(
        false,
        'Please enter a valid ID number.',
        [
            'code' =>
                'INVALID_ID'
        ],
        422
    );

}


$idNumberHash =
    hash(
        'sha256',
        $normalizedId
    );


/* ============================================================
   CURRENT CITY
============================================================ */

if (
    mb_strlen(
        $city
    ) < 2
    ||
    mb_strlen(
        $city
    ) > 120
) {

    registrationResponse(
        false,
        'Please enter your current city.',
        [
            'code' =>
                'INVALID_CITY'
        ],
        422
    );

}


/* ============================================================
   EDUCATION
============================================================ */

$allowedEducationLevels =
    [

        'Secondary School',

        'Certificate',

        'Diploma',

        "Bachelor's Degree",

        "Master's Degree",

        'Doctorate',

        'Other'

    ];


if (
    !in_array(
        $educationLevel,
        $allowedEducationLevels,
        true
    )
) {

    registrationResponse(
        false,
        'Please select a valid education level.',
        [
            'code' =>
                'INVALID_EDUCATION_LEVEL'
        ],
        422
    );

}


/* ============================================================
   UNIVERSITY
============================================================ */

if (
    mb_strlen(
        $universityName
    ) > 255
) {

    registrationResponse(
        false,
        'University or college name is too long.',
        [
            'code' =>
                'INVALID_UNIVERSITY'
        ],
        422
    );

}


/* ============================================================
   COURSE
============================================================ */

if (
    mb_strlen(
        $course
    ) > 255
) {

    registrationResponse(
        false,
        'Course name is too long.',
        [
            'code' =>
                'INVALID_COURSE'
        ],
        422
    );

}


/* ============================================================
   PASSWORD
============================================================ */

if (
    strlen(
        $password
    ) < 8
) {

    registrationResponse(
        false,
        'Password must contain at least 8 characters.',
        [
            'code' =>
                'PASSWORD_TOO_SHORT'
        ],
        422
    );

}


if (
    $password !==
    $confirmPassword
) {

    registrationResponse(
        false,
        'Passwords do not match.',
        [
            'code' =>
                'PASSWORD_MISMATCH'
        ],
        422
    );

}


if (
    !$agree
) {

    registrationResponse(
        false,
        'Please accept the Terms of Service and Privacy Policy.',
        [
            'code' =>
                'TERMS_REQUIRED'
        ],
        422
    );

}


/* ============================================================
   PASSWORD HASH
============================================================ */

$passwordHash =
    password_hash(
        $password,
        PASSWORD_DEFAULT
    );


if (
    $passwordHash === false
) {

    registrationResponse(
        false,
        'Unable to secure your password.',
        [],
        500
    );

}


/* ============================================================
   GOOGLE DUPLICATE CHECK BEFORE TRANSACTION
============================================================ */

if (
    $googleSignup
) {

    $googleCheck =
        $pdo->prepare(
            "
            SELECT id
            FROM user_google_accounts
            WHERE google_sub = :google_sub
            LIMIT 1
            "
        );


    $googleCheck->execute(
        [
            ':google_sub' =>
                $pendingGoogle['sub']
        ]
    );


    if (
        $googleCheck->fetch()
    ) {

        registrationResponse(
            false,
            'This Google account is already connected to LOVEMI.',
            [
                'code' =>
                    'GOOGLE_EXISTS'
            ],
            409
        );

    }

}


/* ============================================================
   FIRST ADMIN LOCK
============================================================ */

try {

    $lockResult =
        $pdo->query(
            "
            SELECT GET_LOCK(
                'lovemi_first_admin_registration',
                10
            ) AS lock_result
            "
        )
        ->fetch();


    if (
        (int)
        (
            $lockResult['lock_result']
            ??
            0
        )
        !==
        1
    ) {

        registrationResponse(
            false,
            'Registration is temporarily busy. Please try again.',
            [
                'code' =>
                    'REGISTRATION_BUSY'
            ],
            503
        );

    }


} catch (
    Throwable $e
) {

    registrationResponse(
        false,
        'Registration is temporarily unavailable.',
        [],
        500
    );

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       USERNAME DUPLICATE
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE LOWER(username) =
                  LOWER(:username)
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':username' =>
                $username
        ]
    );


    if (
        $stmt->fetch()
    ) {

        throw new RuntimeException(
            'USERNAME_EXISTS'
        );

    }


    /* ========================================================
       EMAIL DUPLICATE
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE LOWER(email) =
                  LOWER(:email)
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':email' =>
                $email
        ]
    );


    if (
        $stmt->fetch()
    ) {

        throw new RuntimeException(
            'EMAIL_EXISTS'
        );

    }


    /* ========================================================
       PHONE DUPLICATE
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE phone_e164 = :phone
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':phone' =>
                $phoneE164
        ]
    );


    if (
        $stmt->fetch()
    ) {

        throw new RuntimeException(
            'PHONE_EXISTS'
        );

    }


    /* ========================================================
       ID DUPLICATE
    ======================================================== */

    $stmt =
        $pdo->prepare(
            "
            SELECT id
            FROM users
            WHERE id_number_hash = :id_hash
            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':id_hash' =>
                $idNumberHash
        ]
    );


    if (
        $stmt->fetch()
    ) {

        throw new RuntimeException(
            'ID_EXISTS'
        );

    }


    /* ========================================================
       ROLES
    ======================================================== */

    $roleStmt =
        $pdo->query(
            "
            SELECT id, slug
            FROM roles
            WHERE slug IN ('member','admin')
            "
        );


    $roles = [];


    while (
        $role =
            $roleStmt->fetch()
    ) {

        $roles[
            $role['slug']
        ] =
            (int)
            $role['id'];

    }


    if (
        !isset(
            $roles['member']
        )
        ||
        !isset(
            $roles['admin']
        )
    ) {

        throw new RuntimeException(
            'ROLES_NOT_CONFIGURED'
        );

    }


    /* ========================================================
       ADMIN STATUS
    ======================================================== */

    $adminStmt =
        $pdo->query(
            "
            SELECT u.id
            FROM users u
            INNER JOIN roles r
                ON r.id = u.role_id
            WHERE r.slug = 'admin'
              AND u.is_deleted = FALSE
            LIMIT 1
            "
        );


    $adminExists =
        (bool)
        $adminStmt->fetch();


    if (
        !$adminExists
        &&
        $registerAsAdmin
    ) {

        $roleId =
            $roles['admin'];

        $roleSlug =
            'admin';

    } else {

        $roleId =
            $roles['member'];

        $roleSlug =
            'member';

    }


    /* ========================================================
       INSERT USER
    ======================================================== */

    $insert =
        $pdo->prepare(
            "
            INSERT INTO users
            (
                role_id,
                username,
                full_names,
                gender,
                email,
                country_id,
                phone_number,
                phone_e164,
                id_number_hash,
                date_of_birth,
                password_hash,
                account_status,
                email_verified,
                phone_verified,
                identity_verified,
                age_verified,
                is_active,
                is_suspended,
                is_deleted,
                two_factor_enabled
            )
            VALUES
            (
                :role_id,
                :username,
                :full_names,
                :gender,
                :email,
                :country_id,
                :phone_number,
                :phone_e164,
                :id_number_hash,
                :date_of_birth,
                :password_hash,
                'pending',
                FALSE,
                FALSE,
                FALSE,
                TRUE,
                TRUE,
                FALSE,
                FALSE,
                FALSE
            )
            "
        );


    $insert->execute(
        [

            ':role_id' =>
                $roleId,

            ':username' =>
                $username,

            ':full_names' =>
                $fullNames,

            ':gender' =>
                $gender,

            ':email' =>
                $email,

            ':country_id' =>
                $countryId,

            ':phone_number' =>
                $phoneNumber,

            ':phone_e164' =>
                $phoneE164,

            ':id_number_hash' =>
                $idNumberHash,

            ':date_of_birth' =>
                $dateOfBirth,

            ':password_hash' =>
                $passwordHash

        ]
    );


    $newUserId =
        (int)
        $pdo->lastInsertId();


    /* ========================================================
       PROFILE
    ======================================================== */

    /*
     * The existing database trigger creates the profiles row.
     * Your current database already uses this trigger to create
     * profiles after user creation. :contentReference[oaicite:1]{index=1}
     */

    $profileCheck =
        $pdo->prepare(
            "
            SELECT id
            FROM profiles
            WHERE user_id = :user_id
            LIMIT 1
            "
        );


    $profileCheck->execute(
        [
            ':user_id' =>
                $newUserId
        ]
    );


    $profileExists =
        $profileCheck->fetch();


    if (
        !$profileExists
    ) {

        $profileInsert =
            $pdo->prepare(
                "
                INSERT INTO profiles
                (
                    user_id,
                    display_name
                )
                VALUES
                (
                    :user_id,
                    :display_name
                )
                "
            );


        $profileInsert->execute(
            [
                ':user_id' =>
                    $newUserId,

                ':display_name' =>
                    $fullNames
            ]
        );

    }


    /* ========================================================
       PROFILE DATA
    ======================================================== */

    $profileUpdate =
        $pdo->prepare(
            "
            UPDATE profiles
            SET
                display_name =
                    :display_name,

                education =
                    :education,

                city =
                    :city,

                education_level =
                    :education_level,

                university_name =
                    :university_name,

                course =
                    :course,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE user_id = :user_id
            LIMIT 1
            "
        );


    $profileUpdate->execute(
        [

            ':display_name' =>
                $fullNames,

            ':education' =>
                $educationLevel,

            ':city' =>
                $city,

            ':education_level' =>
                $educationLevel,

            ':university_name' =>
                (
                    $universityName !== ''
                        ?
                        $universityName
                        :
                        null
                ),

            ':course' =>
                (
                    $course !== ''
                        ?
                        $course
                        :
                        null
                ),

            ':user_id' =>
                $newUserId

        ]
    );


    /* ========================================================
       GOOGLE ACCOUNT LINK
    ======================================================== */

    if (
        $googleSignup
    ) {

        $googleInsert =
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
                "
            );


        $googleInsert->execute(
            [

                ':user_id' =>
                    $newUserId,

                ':google_sub' =>
                    $pendingGoogle['sub'],

                ':email' =>
                    $email,

                ':picture_url' =>
                    (
                        !empty(
                            $pendingGoogle['picture']
                        )
                        ?
                        (string)
                        $pendingGoogle['picture']
                        :
                        null
                    )

            ]
        );

    }


    /* ========================================================
       EMAIL VERIFICATION
    ======================================================== */

    $verificationCode =
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


    $verificationHash =
        hash(
            'sha256',
            $verificationCode
        );


    $verificationExpires =
        date(
            'Y-m-d H:i:s',
            time() + 600
        );


    $verification =
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


    $verification->execute(
        [

            ':user_id' =>
                $newUserId,

            ':email' =>
                $email,

            ':code_hash' =>
                $verificationHash,

            ':expires_at' =>
                $verificationExpires

        ]
    );


    /* ========================================================
       AUDIT
    ======================================================== */

    $audit =
        $pdo->prepare(
            "
            INSERT INTO audit_logs
            (
                user_id,
                action,
                entity_type,
                entity_id,
                new_values,
                ip_address,
                user_agent
            )
            VALUES
            (
                :user_id,
                'registration',
                'user',
                :entity_id,
                :new_values,
                :ip_address,
                :user_agent
            )
            "
        );


    $audit->execute(
        [

            ':user_id' =>
                $newUserId,

            ':entity_id' =>
                $newUserId,

            ':new_values' =>
                json_encode(
                    [

                        'role' =>
                            $roleSlug,

                        'account_status' =>
                            'pending',

                        'google_signup' =>
                            $googleSignup,

                        'city' =>
                            $city,

                        'education_level' =>
                            $educationLevel,

                        'university_name' =>
                            (
                                $universityName !== ''
                                    ?
                                    $universityName
                                    :
                                    null
                            ),

                        'course' =>
                            (
                                $course !== ''
                                    ?
                                    $course
                                    :
                                    null
                            )

                    ],
                    JSON_UNESCAPED_UNICODE |
                    JSON_UNESCAPED_SLASHES
                ),

            ':ip_address' =>
                $_SERVER['REMOTE_ADDR']
                ??
                null,

            ':user_agent' =>
                $_SERVER['HTTP_USER_AGENT']
                ??
                null

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


    try {

        $pdo->query(
            "
            SELECT RELEASE_LOCK(
                'lovemi_first_admin_registration'
            )
            "
        );

    } catch (
        Throwable $lockError
    ) {

        error_log(
            '[LOVEMI LOCK RELEASE ERROR] '
            .
            $lockError->getMessage()
        );

    }


    switch (
        $e->getMessage()
    ) {

        case 'USERNAME_EXISTS':

            registrationResponse(
                false,
                'That username is already registered.',
                [
                    'code' =>
                        'USERNAME_EXISTS'
                ],
                409
            );

            break;


        case 'EMAIL_EXISTS':

            registrationResponse(
                false,
                'That email address is already registered.',
                [
                    'code' =>
                        'EMAIL_EXISTS'
                ],
                409
            );

            break;


        case 'PHONE_EXISTS':

            registrationResponse(
                false,
                'That phone number is already registered.',
                [
                    'code' =>
                        'PHONE_EXISTS'
                ],
                409
            );

            break;


        case 'ID_EXISTS':

            registrationResponse(
                false,
                'That ID number is already registered.',
                [
                    'code' =>
                        'ID_EXISTS'
                ],
                409
            );

            break;


        case 'GOOGLE_EXISTS':

            registrationResponse(
                false,
                'This Google account is already connected to LOVEMI.',
                [
                    'code' =>
                        'GOOGLE_EXISTS'
                ],
                409
            );

            break;


        default:

            error_log(
                '[LOVEMI REGISTRATION ERROR] '
                .
                $e->getMessage()
            );


            registrationResponse(
                false,
                'Registration could not be completed.',
                [
                    'code' =>
                        'REGISTRATION_FAILED'
                ],
                500
            );

    }

}


/* ============================================================
   RELEASE LOCK
============================================================ */

try {

    $pdo->query(
        "
        SELECT RELEASE_LOCK(
            'lovemi_first_admin_registration'
        )
        "
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI LOCK RELEASE ERROR] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   SEND VERIFICATION EMAIL
============================================================ */

$verificationEmailSent =
    false;


try {

    require_once
        __DIR__
        .
        '/../../services/email/email-service.php';


    if (
        function_exists(
            'sendLovemiVerificationEmail'
        )
    ) {

        $verificationEmailSent =
            sendLovemiVerificationEmail(
                $email,
                $fullNames,
                $verificationCode
            );

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI VERIFICATION EMAIL ERROR] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   SEND WELCOME EMAIL
============================================================ */

$welcomeEmailSent =
    sendLovemiWelcomeEmail(
        $email,
        $fullNames,
        $username,
        $city,
        $educationLevel,
        $universityName,
        $course,
        $googleSignup
    );


/* ============================================================
   CLEAR GOOGLE SESSION
============================================================ */

if (
    $googleSignup
) {

    unset(
        $_SESSION[
            'lovemi_google_signup'
        ]
    );

}


/* ============================================================
   RESPONSE
============================================================ */

$message =
    'Your LOVEMI account has been created.';


if (
    $verificationEmailSent
) {

    $message .=
        ' A verification email has been sent to your email address.';

} else {

    $message .=
        ' The verification email could not be delivered. Please use Resend Code on the verification page.';

}


if (
    $welcomeEmailSent
) {

    $message .=
        ' An official LOVEMI welcome email has also been sent.';

}


registrationResponse(
    true,
    $message,
    [

        'user_id' =>
            $newUserId,

        'role' =>
            $roleSlug,

        'google_signup' =>
            $googleSignup,

        'verification_email_sent' =>
            $verificationEmailSent,

        'welcome_email_sent' =>
            $welcomeEmailSent,

        'email_verification_required' =>
            true,

        'two_factor_required' =>
            true,

        'redirect' =>
            'verify-account.html?user='
            .
            rawurlencode(
                (string)
                $newUserId
            )

    ],
    201
);