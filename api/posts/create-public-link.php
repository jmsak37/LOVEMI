<?php
/**
 * ============================================================
 * LOVEMI - CREATE SECURE PUBLIC POST VIEW LINK
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\posts\create-public-link.php
 *
 * PURPOSE:
 *
 * - Any authenticated LOVEMI user may create/reuse a secure
 *   viewing token for any APPROVED + PUBLIC post.
 *
 * - The viewer does NOT need to own the post.
 *
 * - The token contains no user ID or user name.
 *
 * - Private post information is never returned.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   JSON HEADERS
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
   FORCE PHP ERRORS INTO LOGS
   DO NOT DISPLAY HTML ERRORS
============================================================ */

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'log_errors',
    '1'
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

function publicLinkResponse(
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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    publicLinkResponse(
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
   AUTHENTICATION
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $userId <= 0
) {

    publicLinkResponse(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
    );

}


/* ============================================================
   READ JSON INPUT
============================================================ */

$rawInput =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        $rawInput ?: '{}',
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        [];

}


$postId =
    isset(
        $input['post_id']
    )
        ?
        (int)
        $input['post_id']
        :
        0;


if (
    $postId <= 0
) {

    publicLinkResponse(
        false,
        'Invalid post.',
        [
            'code' =>
                'INVALID_POST'
        ],
        422
    );

}


/* ============================================================
   DATABASE CONNECTION
============================================================ */

try {

    $pdo =
        db();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PUBLIC LINK DB] '
        .
        $e->getMessage()
    );


    publicLinkResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   VERIFY CURRENT USER
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                is_active,
                is_suspended,
                is_deleted,
                email_verified

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


    $viewer =
        $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PUBLIC LINK USER QUERY] '
        .
        $e->getMessage()
    );


    publicLinkResponse(
        false,
        'Unable to verify your account.',
        [
            'code' =>
                'USER_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$viewer
) {

    publicLinkResponse(
        false,
        'Your account could not be found.',
        [
            'code' =>
                'USER_NOT_FOUND'
        ],
        404
    );

}


if (
    !(bool)
    $viewer['email_verified']
) {

    publicLinkResponse(
        false,
        'Please verify your email before viewing posts.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED'
        ],
        403
    );

}


if (
    !(bool)
    $viewer['is_active']
    ||
    (bool)
    $viewer['is_suspended']
    ||
    (bool)
    $viewer['is_deleted']
) {

    publicLinkResponse(
        false,
        'Your account is currently unavailable.',
        [
            'code' =>
                'ACCOUNT_UNAVAILABLE'
        ],
        403
    );

}


/* ============================================================
   PREPARE SECURE LINK TABLE
============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS post_public_links
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            post_id BIGINT UNSIGNED NOT NULL,

            public_token CHAR(64) NOT NULL,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            last_used_at DATETIME NULL,

            PRIMARY KEY (id),

            UNIQUE KEY uq_post_public_token
                (public_token),

            UNIQUE KEY uq_post_public_post
                (post_id),

            KEY idx_post_public_post
                (post_id),

            CONSTRAINT fk_post_public_link_post
                FOREIGN KEY (post_id)
                REFERENCES posts(id)
                ON DELETE CASCADE

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (Throwable $e) {

    /*
     * Some installations may already have the table with
     * a slightly different foreign-key definition.
     *
     * The existing table is still usable if creation fails
     * because of an already-existing schema relationship.
     */

    error_log(
        '[LOVEMI PUBLIC LINK TABLE] '
        .
        $e->getMessage()
    );


    try {

        $checkTable =
            $pdo->query(
                "
                SHOW TABLES LIKE
                'post_public_links'
                "
            );


        $tableExists =
            $checkTable
            &&
            $checkTable->fetch();

    } catch (Throwable $ignored) {

        $tableExists =
            false;

    }


    if (
        !$tableExists
    ) {

        publicLinkResponse(
            false,
            'Unable to prepare secure post viewing links.',
            [
                'code' =>
                    'PUBLIC_LINK_TABLE_ERROR'
            ],
            500
        );

    }

}


/* ============================================================
   IMPORTANT
   NO OWNERSHIP CHECK HERE
============================================================ */

/*
 * Previous broken logic used:
 *
 *     p.user_id = :user_id
 *
 * That made a user unable to create a viewing token for
 * another member's post.
 *
 * The dashboard requires any eligible logged-in user to be
 * able to view any approved public post.
 *
 * Therefore ownership is intentionally NOT checked.
 */


/* ============================================================
   VERIFY THE POST ITSELF
============================================================ */

try {

    $postStmt =
        $pdo->prepare(
            "
            SELECT

                p.id,
                p.user_id,
                p.approval_status,
                p.visibility,
                p.deleted_at,

                u.is_active,
                u.is_suspended,
                u.is_deleted,
                u.email_verified

            FROM posts p

            INNER JOIN users u
                ON u.id = p.user_id

            WHERE

                p.id = :post_id

              AND p.approval_status = 'approved'

              AND p.visibility = 'public'

              AND p.deleted_at IS NULL

              AND u.email_verified = 1

              AND u.is_active = 1

              AND u.is_suspended = 0

              AND u.is_deleted = 0

            LIMIT 1
            "
        );


    $postStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $post =
        $postStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PUBLIC LINK POST QUERY] '
        .
        $e->getMessage()
    );


    publicLinkResponse(
        false,
        'Unable to verify this post.',
        [
            'code' =>
                'POST_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$post
) {

    publicLinkResponse(
        false,
        'This post cannot be viewed.',
        [
            'code' =>
                'POST_NOT_AVAILABLE'
        ],
        404
    );

}


/* ============================================================
   REUSE EXISTING TOKEN
============================================================ */

try {

    $existingStmt =
        $pdo->prepare(
            "
            SELECT

                public_token

            FROM post_public_links

            WHERE post_id = :post_id

            LIMIT 1
            "
        );


    $existingStmt->execute(
        [
            ':post_id' =>
                $postId
        ]
    );


    $existingToken =
        $existingStmt->fetchColumn();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PUBLIC LINK EXISTING QUERY] '
        .
        $e->getMessage()
    );


    $existingToken =
        false;

}


if (
    is_string(
        $existingToken
    )
    &&
    preg_match(
        '/^[a-f0-9]{64}$/',
        $existingToken
    )
) {

    publicLinkResponse(
        true,
        'Secure post link ready.',
        [
            'token' =>
                $existingToken,

            'view_url' =>
                'view.html?token='
                .
                rawurlencode(
                    $existingToken
                )
        ]
    );

}


/* ============================================================
   GENERATE TOKEN
============================================================ */

try {

    $token =
        bin2hex(
            random_bytes(
                32
            )
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PUBLIC TOKEN GENERATION] '
        .
        $e->getMessage()
    );


    publicLinkResponse(
        false,
        'Unable to create a secure post link.',
        [
            'code' =>
                'TOKEN_GENERATION_ERROR'
        ],
        500
    );

}


/* ============================================================
   SAVE TOKEN
============================================================ */

try {

    $insertStmt =
        $pdo->prepare(
            "
            INSERT INTO post_public_links
            (
                post_id,
                public_token,
                created_at
            )
            VALUES
            (
                :post_id,
                :token,
                CURRENT_TIMESTAMP
            )
            "
        );


    $insertStmt->execute(
        [
            ':post_id' =>
                $postId,

            ':token' =>
                $token
        ]
    );

} catch (Throwable $e) {

    /*
     * A simultaneous request may have created the token.
     * Try to retrieve the existing token before failing.
     */

    try {

        $retryStmt =
            $pdo->prepare(
                "
                SELECT public_token

                FROM post_public_links

                WHERE post_id = :post_id

                LIMIT 1
                "
            );


        $retryStmt->execute(
            [
                ':post_id' =>
                    $postId
            ]
        );


        $retryToken =
            $retryStmt->fetchColumn();


        if (
            is_string(
                $retryToken
            )
            &&
            preg_match(
                '/^[a-f0-9]{64}$/',
                $retryToken
            )
        ) {

            publicLinkResponse(
                true,
                'Secure post link ready.',
                [
                    'token' =>
                        $retryToken,

                    'view_url' =>
                        'view.html?token='
                        .
                        rawurlencode(
                            $retryToken
                        )
                ]
            );

        }

    } catch (Throwable $retryError) {

        error_log(
            '[LOVEMI PUBLIC LINK RETRY] '
            .
            $retryError->getMessage()
        );

    }


    error_log(
        '[LOVEMI PUBLIC LINK INSERT] '
        .
        $e->getMessage()
    );


    publicLinkResponse(
        false,
        'Unable to save the secure post link.',
        [
            'code' =>
                'PUBLIC_LINK_SAVE_ERROR'
        ],
        500
    );

}


/* ============================================================
   SUCCESS
============================================================ */

publicLinkResponse(
    true,
    'Secure post link created.',
    [
        'token' =>
            $token,

        'view_url' =>
            'view.html?token='
            .
            rawurlencode(
                $token
            )
    ],
    201
);