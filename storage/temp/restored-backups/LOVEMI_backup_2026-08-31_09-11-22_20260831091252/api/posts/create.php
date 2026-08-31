<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function createPostResponse(
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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    createPostResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
============================================================ */

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    createPostResponse(
        false,
        'Please log in first.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html'
        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw = file_get_contents('php://input');

$input = json_decode(
    (string) $raw,
    true
);

if (!is_array($input)) {
    $input = $_POST;
}

$content =
    trim(
        (string) (
            $input['content']
            ??
            ''
        )
    );

$visibility =
    strtolower(
        trim(
            (string) (
                $input['visibility']
                ??
                'public'
            )
        )
    );


/* ============================================================
   VALIDATION
============================================================ */

$allowedVisibility = [
    'public',
    'connections',
    'private'
];

if (
    !in_array(
        $visibility,
        $allowedVisibility,
        true
    )
) {

    createPostResponse(
        false,
        'Invalid post visibility.',
        [
            'code' => 'INVALID_VISIBILITY',
            'allowed' => $allowedVisibility
        ],
        422
    );
}


/*
|--------------------------------------------------------------------------
| A text post cannot be completely empty.
|--------------------------------------------------------------------------
*/

if ($content === '') {

    createPostResponse(
        false,
        'Please write something before publishing the post.',
        [
            'code' => 'CONTENT_REQUIRED'
        ],
        422
    );
}


/*
|--------------------------------------------------------------------------
| Reasonable application-side limit.
|--------------------------------------------------------------------------
*/

if (
    mb_strlen($content) > 10000
) {

    createPostResponse(
        false,
        'Your post is too long. Maximum allowed length is 10,000 characters.',
        [
            'code' => 'CONTENT_TOO_LONG'
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
        '[LOVEMI CREATE POST DB] ' .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Database connection failed.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}


/* ============================================================
   VERIFY USER
============================================================ */

try {

    $userStmt = $pdo->prepare(
        "
        SELECT

            id,
            gender,
            account_status,
            email_verified,
            is_active,
            is_suspended,
            is_deleted

        FROM users

        WHERE id = :user_id

        LIMIT 1
        "
    );

    $userStmt->execute([
        ':user_id' => $userId
    ]);

    $user = $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE POST USER] ' .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Unable to verify your account.',
        [
            'code' => 'USER_LOOKUP_FAILED'
        ],
        500
    );
}


if (!$user) {

    createPostResponse(
        false,
        'Account not found.',
        [
            'code' => 'USER_NOT_FOUND'
        ],
        404
    );
}


if (
    (int) $user['is_deleted'] === 1
) {

    createPostResponse(
        false,
        'Your account has been deleted.',
        [
            'code' => 'ACCOUNT_DELETED'
        ],
        403
    );
}


if (
    (int) $user['is_suspended'] === 1
) {

    createPostResponse(
        false,
        'Your account is suspended.',
        [
            'code' => 'ACCOUNT_SUSPENDED'
        ],
        403
    );
}


if (
    (int) $user['is_active'] !== 1
) {

    createPostResponse(
        false,
        'Your account is inactive.',
        [
            'code' => 'ACCOUNT_INACTIVE'
        ],
        403
    );
}


/* ============================================================
   EMAIL VERIFICATION
============================================================ */

if (
    (int) $user['email_verified'] !== 1
) {

    createPostResponse(
        false,
        'Please verify your email before creating posts.',
        [
            'code' => 'EMAIL_VERIFICATION_REQUIRED',
            'redirect' => 'verify-account.html'
        ],
        403
    );
}


/* ============================================================
   CHECK ACTIVE PREMIUM
============================================================ */

try {

    $premiumStmt = $pdo->prepare(
        "
        SELECT

            s.id,
            s.status,
            s.start_at,
            s.end_at,

            sv.id AS service_id,
            sv.name AS service_name,
            sv.slug AS service_slug,
            sv.is_premium,
            sv.is_active

        FROM subscriptions s

        INNER JOIN services sv
            ON sv.id = s.service_id

        WHERE s.user_id = :user_id

          AND s.status = 'active'

          AND s.end_at IS NOT NULL

          AND s.end_at > CURRENT_TIMESTAMP

          AND sv.is_premium = 1

          AND sv.is_active = 1

          AND sv.slug = 'lovemi-premium'

        ORDER BY
            s.end_at DESC,
            s.id DESC

        LIMIT 1
        "
    );

    $premiumStmt->execute([
        ':user_id' => $userId
    ]);

    $premium = $premiumStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CREATE POST PREMIUM] ' .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Unable to verify Premium access.',
        [
            'code' => 'PREMIUM_CHECK_FAILED'
        ],
        500
    );
}


if (!$premium) {

    createPostResponse(
        false,
        'An active LOVEMI Premium subscription is required to create a post.',
        [
            'code' => 'PREMIUM_REQUIRED',
            'redirect' => 'premium.html'
        ],
        403
    );
}


/* ============================================================
   CREATE POST
============================================================ */

try {

    $pdo->beginTransaction();


    $insertStmt = $pdo->prepare(
        "
        INSERT INTO posts
        (
            user_id,
            content,
            visibility,
            approval_status,
            is_featured
        )
        VALUES
        (
            :user_id,
            :content,
            :visibility,
            'pending',
            0
        )
        "
    );


    $insertStmt->execute([
        ':user_id' => $userId,
        ':content' => $content,
        ':visibility' => $visibility
    ]);


    $postId =
        (int)
        $pdo->lastInsertId();


    $pdo->commit();

} catch (Throwable $e) {

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }

    error_log(
        '[LOVEMI CREATE POST INSERT] ' .
        $e->getMessage()
    );

    createPostResponse(
        false,
        'Unable to create your post.',
        [
            'code' => 'POST_CREATION_FAILED'
        ],
        500
    );
}


/* ============================================================
   RESPONSE
============================================================ */

createPostResponse(
    true,
    'Post submitted successfully and is awaiting admin approval.',
    [

        'post' => [

            'id' =>
                $postId,

            'content' =>
                $content,

            'visibility' =>
                $visibility,

            'approval_status' =>
                'pending',

            'is_featured' =>
                false,

            'created_at' =>
                date('Y-m-d H:i:s')

        ],

        'premium' => [

            'subscription_id' =>
                (int)
                $premium['id'],

            'end_at' =>
                $premium['end_at']

        ]

    ],
    201
);