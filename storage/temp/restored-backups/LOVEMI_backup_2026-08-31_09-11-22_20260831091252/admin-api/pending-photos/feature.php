<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - FEATURE / UNFEATURE PHOTO
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


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


function pendingPhotoFeatureResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code(
        $status
    );


    echo json_encode(
        [
            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| METHOD
|--------------------------------------------------------------------------
*/

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    pendingPhotoFeatureResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
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


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    pendingPhotoFeatureResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    pendingPhotoFeatureResponse(
        false,
        'You must log in first.',
        [],
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT
                u.id

            FROM users u

            INNER JOIN roles r
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
                    'photos.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash

        ]
    );


    if (
        !$auth->fetch()
    ) {

        pendingPhotoFeatureResponse(
            false,
            'You do not have permission to manage photos.',
            [],
            403
        );

    }

} catch (
    Throwable $e
) {

    pendingPhotoFeatureResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/*
|--------------------------------------------------------------------------
| INPUT
|--------------------------------------------------------------------------
*/

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$photoId =
    (int)(
        $input['photo_id']
        ??
        0
    );


if (
    $photoId <= 0
) {

    pendingPhotoFeatureResponse(
        false,
        'A valid photo ID is required.',
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| TRANSACTION
|--------------------------------------------------------------------------
*/

try {

    $pdo->beginTransaction();


    $stmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                file_name,

                approval_status,

                is_featured

            FROM photos

            WHERE
                id =
                    :photo_id

            LIMIT 1

            FOR UPDATE
            "
        );


    $stmt->execute(
        [
            ':photo_id' =>
                $photoId
        ]
    );


    $photo =
        $stmt->fetch();


    if (
        !$photo
    ) {

        throw new RuntimeException(
            'The requested media was not found.'
        );

    }


    if (
        strtolower(
            (string)
            $photo['approval_status']
        )
        !==
        'approved'
    ) {

        throw new RuntimeException(
            'Only approved media can be featured.'
        );

    }


    $oldFeatured =
        (int)
        $photo['is_featured'];


    $newFeatured =
        $oldFeatured
            ?
            0
            :
            1;


    /*
     * Update feature status.
     */

    $update =
        $pdo->prepare(
            "
            UPDATE photos

            SET
                is_featured =
                    :is_featured

            WHERE
                id =
                    :photo_id

            LIMIT 1
            "
        );


    $update->execute(
        [

            ':is_featured' =>
                $newFeatured,

            ':photo_id' =>
                $photoId

        ]
    );


    if (
        $update->rowCount()
        !==
        1
    ) {

        throw new RuntimeException(
            'The featured status could not be changed.'
        );

    }


    /*
     * Audit.
     */

    try {

        $audit =
            $pdo->prepare(
                "
                INSERT INTO audit_logs
                (
                    user_id,
                    action,
                    entity_type,
                    entity_id,
                    old_values,
                    new_values,
                    ip_address,
                    user_agent
                )
                VALUES
                (
                    :user_id,
                    'admin_feature_photo',
                    'photo',
                    :entity_id,
                    :old_values,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute(
            [

                ':user_id' =>
                    $adminId,

                ':entity_id' =>
                    $photoId,

                ':old_values' =>
                    json_encode(
                        [
                            'is_featured' =>
                                $oldFeatured
                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [
                            'is_featured' =>
                                $newFeatured,

                            'changed_by' =>
                                $adminId,

                            'changed_at' =>
                                date(
                                    'Y-m-d H:i:s'
                                )
                        ],
                        JSON_UNESCAPED_UNICODE
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
        Throwable $auditError
    ) {

        error_log(
            '[LOVEMI PHOTO FEATURE AUDIT] '
            .
            $auditError->getMessage()
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


    pendingPhotoFeatureResponse(
        false,
        $e->getMessage(),
        [],
        422
    );

}


/*
|--------------------------------------------------------------------------
| RESPONSE
|--------------------------------------------------------------------------
*/

pendingPhotoFeatureResponse(
    true,
    $newFeatured
        ?
        'The media has been featured successfully.'
        :
        'The media has been removed from featured media.',
    [

        'photo_id' =>
            $photoId,

        'is_featured' =>
            (bool)
            $newFeatured

    ]
);