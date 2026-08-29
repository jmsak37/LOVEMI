<?php

declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI - ADMIN UPDATE PROFILE API
|--------------------------------------------------------------------------
|
| POST /admin-api/profiles/update.php
|
| JSON:
|
| {
|   "user_id": 4,
|   "display_name": "Example Name",
|   "bio": "About me",
|   "occupation": "Developer",
|   "education": "University",
|   "city": "Kitui",
|   "relationship_status": "Single",
|   "looking_for": "Relationship",
|   "interests": "Technology, music",
|   "profile_visibility": "public",
|   "show_online_status": 1,
|   "allow_messages": 1
| }
|
|--------------------------------------------------------------------------
*/

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

header(
    'X-Content-Type-Options: nosniff'
);

ini_set(
    'display_errors',
    '0'
);

error_reporting(
    E_ALL
);


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params([
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
]);


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

function profileUpdateResponse(
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

    profileUpdateResponse(
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
   SESSION
============================================================ */

$adminId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


$sessionToken =
    isset(
        $_SESSION['lovemi_session_token']
    )
        ?
        (string)
        $_SESSION['lovemi_session_token']
        :
        '';


$sessionId =
    isset(
        $_SESSION['lovemi_database_session_id']
    )
        ?
        (int)
        $_SESSION['lovemi_database_session_id']
        :
        0;


if (
    $adminId <= 0
    ||
    $sessionToken === ''
    ||
    $sessionId <= 0
) {

    profileUpdateResponse(
        false,
        'You must log in first.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
        401
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
        '[LOVEMI UPDATE PROFILE DB] '
        .
        $e->getMessage()
    );


    profileUpdateResponse(
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
   ADMIN AUTH
============================================================ */

$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $auth =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug,

                r.is_admin_role

            FROM users u

            INNER JOIN roles r
                ON r.id =
                   u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                   u.id

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

            LIMIT 1
            "
        );


    $auth->execute([
        ':admin_id' =>
            $adminId,

        ':session_id' =>
            $sessionId,

        ':token_hash' =>
            $tokenHash
    ]);


    $admin =
        $auth->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE PROFILE AUTH] '
        .
        $e->getMessage()
    );


    profileUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [
            'code' =>
                'ADMIN_AUTH_FAILED'
        ],
        500
    );

}


if (
    !$admin
) {

    profileUpdateResponse(
        false,
        'Administrator access is required.',
        [
            'code' =>
                'ADMIN_ACCESS_REQUIRED'
        ],
        403
    );

}


/* ============================================================
   PERMISSION
============================================================ */

try {

    $permission =
        $pdo->prepare(
            "
            SELECT COUNT(*)

            FROM role_permissions rp

            INNER JOIN permissions p
                ON p.id =
                   rp.permission_id

            WHERE

                rp.role_id =
                    :role_id

                AND p.slug =
                    'profiles.manage'
            "
        );


    $permission->execute([
        ':role_id' =>
            (int)
            $admin['role_id']
    ]);


    $allowed =
        (
            (int)
            $permission->fetchColumn()
        )
        >
        0;

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE PROFILE PERMISSION] '
        .
        $e->getMessage()
    );


    profileUpdateResponse(
        false,
        'Unable to verify your permission.',
        [
            'code' =>
                'PERMISSION_CHECK_FAILED'
        ],
        500
    );

}


if (
    !$allowed
) {

    profileUpdateResponse(
        false,
        'You do not have permission to update profiles.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   JSON
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

    $data =
        $_POST;

}


/* ============================================================
   USER ID
============================================================ */

$userId =
    (int)
    (
        $data['user_id']
        ??
        $data['id']
        ??
        0
    );


if (
    $userId <= 0
) {

    profileUpdateResponse(
        false,
        'A valid user ID is required.',
        [
            'code' =>
                'USER_ID_REQUIRED'
        ],
        422
    );

}


/* ============================================================
   FIELDS
============================================================ */

$displayName =
    trim(
        (string)
        (
            $data['display_name']
            ??
            ''
        )
    );


$bio =
    trim(
        (string)
        (
            $data['bio']
            ??
            ''
        )
    );


$occupation =
    trim(
        (string)
        (
            $data['occupation']
            ??
            ''
        )
    );


$education =
    trim(
        (string)
        (
            $data['education']
            ??
            ''
        )
    );


$city =
    trim(
        (string)
        (
            $data['city']
            ??
            ''
        )
    );


$relationshipStatus =
    trim(
        (string)
        (
            $data['relationship_status']
            ??
            ''
        )
    );


$lookingFor =
    trim(
        (string)
        (
            $data['looking_for']
            ??
            ''
        )
    );


$interests =
    trim(
        (string)
        (
            $data['interests']
            ??
            ''
        )
    );


$visibility =
    strtolower(
        trim(
            (string)
            (
                $data['profile_visibility']
                ??
                'public'
            )
        )
    );


$showOnlineStatus =
    filter_var(
        $data['show_online_status']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
        ?
        1
        :
        0;


$allowMessages =
    filter_var(
        $data['allow_messages']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
        ?
        1
        :
        0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    mb_strlen($displayName) >
    180
) {

    profileUpdateResponse(
        false,
        'Display name must not exceed 180 characters.',
        [
            'code' =>
                'DISPLAY_NAME_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($bio) >
    5000
) {

    profileUpdateResponse(
        false,
        'Bio is too long.',
        [
            'code' =>
                'BIO_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($occupation) >
    150
) {

    profileUpdateResponse(
        false,
        'Occupation must not exceed 150 characters.',
        [
            'code' =>
                'OCCUPATION_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($education) >
    180
) {

    profileUpdateResponse(
        false,
        'Education must not exceed 180 characters.',
        [
            'code' =>
                'EDUCATION_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($city) >
    120
) {

    profileUpdateResponse(
        false,
        'City must not exceed 120 characters.',
        [
            'code' =>
                'CITY_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($relationshipStatus) >
    50
) {

    profileUpdateResponse(
        false,
        'Relationship status is too long.',
        [
            'code' =>
                'RELATIONSHIP_STATUS_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($lookingFor) >
    100
) {

    profileUpdateResponse(
        false,
        'Looking-for value is too long.',
        [
            'code' =>
                'LOOKING_FOR_TOO_LONG'
        ],
        422
    );

}


if (
    mb_strlen($interests) >
    5000
) {

    profileUpdateResponse(
        false,
        'Interests value is too long.',
        [
            'code' =>
                'INTERESTS_TOO_LONG'
        ],
        422
    );

}


if (
    !in_array(
        $visibility,
        [
            'public',
            'private',
            'friends'
        ],
        true
    )
) {

    profileUpdateResponse(
        false,
        'Invalid profile visibility.',
        [
            'code' =>
                'INVALID_VISIBILITY'
        ],
        422
    );

}


/* ============================================================
   LOAD CURRENT PROFILE
============================================================ */

try {

    $currentStmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.user_id,

                p.display_name,

                p.bio,

                p.occupation,

                p.education,

                p.city,

                p.relationship_status,

                p.looking_for,

                p.interests,

                p.profile_visibility,

                p.show_online_status,

                p.allow_messages

            FROM profiles p

            WHERE
                p.user_id =
                    :user_id

            LIMIT 1
            "
        );


    $currentStmt->execute([
        ':user_id' =>
            $userId
    ]);


    $oldProfile =
        $currentStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI UPDATE PROFILE LOAD] '
        .
        $e->getMessage()
    );


    profileUpdateResponse(
        false,
        'Unable to load the profile.',
        [
            'code' =>
                'PROFILE_LOAD_FAILED'
        ],
        500
    );

}


if (
    !$oldProfile
) {

    /*
     * A trigger normally creates the profile when the user
     * account is created, but this safely creates it when an
     * account is missing its profile row.
     */

    try {

        $createProfile =
            $pdo->prepare(
                "
                INSERT INTO profiles
                (
                    user_id,
                    display_name,
                    profile_visibility,
                    show_online_status,
                    allow_messages
                )
                VALUES
                (
                    :user_id,
                    :display_name,
                    :visibility,
                    :show_online,
                    :allow_messages
                )
                "
            );


        $createProfile->execute([
            ':user_id' =>
                $userId,

            ':display_name' =>
                $displayName !== ''
                    ?
                    $displayName
                    :
                    null,

            ':visibility' =>
                $visibility,

            ':show_online' =>
                $showOnlineStatus,

            ':allow_messages' =>
                $allowMessages
        ]);


        $oldProfile = [

            'id' =>
                (int)
                $pdo->lastInsertId(),

            'user_id' =>
                $userId,

            'display_name' =>
                null,

            'bio' =>
                null,

            'occupation' =>
                null,

            'education' =>
                null,

            'city' =>
                null,

            'relationship_status' =>
                null,

            'looking_for' =>
                null,

            'interests' =>
                null,

            'profile_visibility' =>
                'public',

            'show_online_status' =>
                1,

            'allow_messages' =>
                1

        ];

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI UPDATE PROFILE CREATE MISSING] '
            .
            $e->getMessage()
        );


        profileUpdateResponse(
            false,
            'Unable to create the missing profile.',
            [
                'code' =>
                    'PROFILE_CREATE_FAILED'
            ],
            500
        );

    }

}


/* ============================================================
   UPDATE
============================================================ */

try {

    $pdo->beginTransaction();


    $update =
        $pdo->prepare(
            "
            UPDATE profiles

            SET

                display_name =
                    :display_name,

                bio =
                    :bio,

                occupation =
                    :occupation,

                education =
                    :education,

                city =
                    :city,

                relationship_status =
                    :relationship_status,

                looking_for =
                    :looking_for,

                interests =
                    :interests,

                profile_visibility =
                    :profile_visibility,

                show_online_status =
                    :show_online_status,

                allow_messages =
                    :allow_messages,

                updated_at =
                    CURRENT_TIMESTAMP

            WHERE
                user_id =
                    :user_id

            LIMIT 1
            "
        );


    $update->execute([
        ':display_name' =>
            $displayName !== ''
                ?
                $displayName
                :
                null,

        ':bio' =>
            $bio !== ''
                ?
                $bio
                :
                null,

        ':occupation' =>
            $occupation !== ''
                ?
                $occupation
                :
                null,

        ':education' =>
            $education !== ''
                ?
                $education
                :
                null,

        ':city' =>
            $city !== ''
                ?
                $city
                :
                null,

        ':relationship_status' =>
            $relationshipStatus !== ''
                ?
                $relationshipStatus
                :
                null,

        ':looking_for' =>
            $lookingFor !== ''
                ?
                $lookingFor
                :
                null,

        ':interests' =>
            $interests !== ''
                ?
                $interests
                :
                null,

        ':profile_visibility' =>
            $visibility,

        ':show_online_status' =>
            $showOnlineStatus,

        ':allow_messages' =>
            $allowMessages,

        ':user_id' =>
            $userId
    ]);


    /* ========================================================
       AUDIT
    ========================================================= */

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
                'admin_profile_updated',
                'profile',
                :entity_id,
                :old_values,
                :new_values,
                :ip,
                :agent
            )
            "
        );


    $audit->execute([
        ':user_id' =>
            $adminId,

        ':entity_id' =>
            (int)
            $oldProfile['id'],

        ':old_values' =>
            json_encode(
                $oldProfile,
                JSON_UNESCAPED_UNICODE
            ),

        ':new_values' =>
            json_encode(
                [
                    'user_id' =>
                        $userId,

                    'display_name' =>
                        $displayName,

                    'bio' =>
                        $bio,

                    'occupation' =>
                        $occupation,

                    'education' =>
                        $education,

                    'city' =>
                        $city,

                    'relationship_status' =>
                        $relationshipStatus,

                    'looking_for' =>
                        $lookingFor,

                    'interests' =>
                        $interests,

                    'profile_visibility' =>
                        $visibility,

                    'show_online_status' =>
                        $showOnlineStatus,

                    'allow_messages' =>
                        $allowMessages

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

    ]);


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
        '[LOVEMI UPDATE PROFILE SAVE] '
        .
        $e->getMessage()
    );


    profileUpdateResponse(
        false,
        'Unable to update the profile.',
        [
            'code' =>
                'PROFILE_UPDATE_FAILED'
        ],
        500
    );

}


/* ============================================================
   RESPONSE
============================================================ */

profileUpdateResponse(
    true,
    'Profile updated successfully.',
    [
        'data' => [

            'user_id' =>
                $userId,

            'display_name' =>
                $displayName,

            'bio' =>
                $bio,

            'occupation' =>
                $occupation,

            'education' =>
                $education,

            'city' =>
                $city,

            'relationship_status' =>
                $relationshipStatus,

            'looking_for' =>
                $lookingFor,

            'interests' =>
                $interests,

            'profile_visibility' =>
                $visibility,

            'show_online_status' =>
                $showOnlineStatus,

            'allow_messages' =>
                $allowMessages

        ]

    ]
);