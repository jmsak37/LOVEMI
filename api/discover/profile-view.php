<?php

/**
 * ============================================================
 * LOVEMI - DISCOVER PROFILE VIEW API
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\discover\profile-view.php
 *
 * GET:
 * ?user_id=4
 *
 * Returns JSON ONLY.
 *
 * Loads:
 * - User
 * - Public profile
 * - Primary profile photo
 * - Approved public posts
 * - All approved post media
 * - Online status
 * - Connection status
 *
 * IMPORTANT:
 * No email, phone number, ID information, password,
 * encryption data or other private security information
 * is returned.
 * ============================================================
 */


/* ============================================================
   PHP ERROR / OUTPUT PROTECTION
============================================================ */

error_reporting(E_ALL);

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'html_errors',
    '0'
);


/*
 * Start buffering so accidental output such as warnings,
 * notices or whitespace cannot corrupt the JSON response.
 */

ob_start();


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
   JSON RESPONSE FUNCTION
============================================================ */

function profileViewResponse(
    $success,
    $message,
    $data = array(),
    $status = 200
) {

    /*
     * Remove accidental PHP output.
     */

    while (
        ob_get_level() > 0
    ) {

        @ob_end_clean();

    }


    http_response_code(
        (int)$status
    );


    header(
        'Content-Type: application/json; charset=utf-8'
    );


    echo json_encode(
        array_merge(
            array(
                'success' =>
                    (bool)$success,

                'message' =>
                    (string)$message
            ),
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/* ============================================================
   CONVERT PHP ERRORS TO EXCEPTIONS
============================================================ */

set_error_handler(
    function (
        $severity,
        $message,
        $file,
        $line
    ) {

        /*
         * Respect PHP errors which are masked with @.
         */

        if (
            !(error_reporting() & $severity)
        ) {

            return false;

        }


        throw new ErrorException(
            $message,
            0,
            $severity,
            $file,
            $line
        );

    }
);


/* ============================================================
   GLOBAL EXCEPTION HANDLER
============================================================ */

set_exception_handler(
    function (
        $exception
    ) {

        error_log(
            '[LOVEMI DISCOVER PROFILE EXCEPTION] '
            .
            $exception->getMessage()
            .
            ' in '
            .
            $exception->getFile()
            .
            ':'
            .
            $exception->getLine()
        );


        profileViewResponse(
            false,
            'The profile could not be loaded because of a server error.',
            array(
                'code' =>
                    'PROFILE_SERVER_ERROR'
            ),
            500
        );

    }
);


/* ============================================================
   SHUTDOWN HANDLER
============================================================ */

register_shutdown_function(
    function () {

        $error =
            error_get_last();


        if (
            !$error
        ) {

            return;

        }


        $fatalTypes =
            array(
                E_ERROR,
                E_PARSE,
                E_CORE_ERROR,
                E_COMPILE_ERROR
            );


        if (
            in_array(
                $error['type'],
                $fatalTypes,
                true
            )
        ) {

            error_log(
                '[LOVEMI DISCOVER PROFILE FATAL] '
                .
                $error['message']
                .
                ' in '
                .
                $error['file']
                .
                ':'
                .
                $error['line']
            );


            /*
             * At this stage the previous output may already have
             * been generated. Clear it and return valid JSON.
             */

            while (
                ob_get_level() > 0
            ) {

                @ob_end_clean();

            }


            http_response_code(
                500
            );


            header(
                'Content-Type: application/json; charset=utf-8'
            );


            echo json_encode(
                array(
                    'success' =>
                        false,

                    'message' =>
                        'The profile could not be loaded because of a server error.',

                    'code' =>
                        'PROFILE_FATAL_ERROR'
                ),
                JSON_UNESCAPED_UNICODE |
                JSON_UNESCAPED_SLASHES
            );

        }

    }
);


/* ============================================================
   DATABASE
============================================================ */

require_once __DIR__ .
    '/../../config/database.php';


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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'GET'
) {

    profileViewResponse(
        false,
        'Only GET requests are allowed.',
        array(
            'code' =>
                'METHOD_NOT_ALLOWED'
        ),
        405
    );

}


/* ============================================================
   CURRENT USER
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    profileViewResponse(
        false,
        'Please log in first.',
        array(
            'code' =>
                'AUTHENTICATION_REQUIRED',

            'redirect' =>
                'login.html?return=discover.html'
        ),
        401
    );

}


/* ============================================================
   TARGET USER
============================================================ */

$targetUserId = 0;


if (
    isset(
        $_GET['user_id']
    )
) {

    $targetUserId =
        (int)
        $_GET['user_id'];

} elseif (
    isset(
        $_GET['id']
    )
) {

    $targetUserId =
        (int)
        $_GET['id'];

}


if (
    $targetUserId <= 0
) {

    profileViewResponse(
        false,
        'A valid user_id is required.',
        array(
            'code' =>
                'INVALID_USER_ID'
        ),
        422
    );

}


/* ============================================================
   NO SELF PROFILE
============================================================ */

if (
    $targetUserId ===
    $currentUserId
) {

    profileViewResponse(
        false,
        'Your own profile is available from the Profile page.',
        array(
            'code' =>
                'OWN_PROFILE'
        ),
        403
    );

}


/* ============================================================
   DATABASE CONNECTION
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DISCOVER PROFILE DATABASE] '
        .
        $e->getMessage()
    );


    profileViewResponse(
        false,
        'Unable to connect to the database.',
        array(
            'code' =>
                'DATABASE_ERROR'
        ),
        500
    );

}


/* ============================================================
   TARGET USER
============================================================ */

$userStmt =
    $pdo->prepare(
        "
        SELECT

            u.id,

            u.username,

            u.full_names,

            u.gender,

            u.country_id,

            u.date_of_birth,

            u.account_status,

            u.email_verified,

            u.phone_verified,

            u.identity_verified,

            u.age_verified,

            u.is_active,

            u.is_suspended,

            u.is_deleted,

            u.last_seen_at,

            u.created_at,

            c.name AS country_name,

            c.iso2 AS country_iso2

        FROM users u

        LEFT JOIN countries c
            ON c.id = u.country_id

        WHERE

            u.id =
                :user_id

            AND u.account_status =
                'approved'

            AND u.email_verified =
                1

            AND u.is_active =
                1

            AND u.is_suspended =
                0

            AND u.is_deleted =
                0

        LIMIT 1
        "
    );


$userStmt->execute(
    array(
        ':user_id' =>
            $targetUserId
    )
);


$user =
    $userStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !$user
) {

    profileViewResponse(
        false,
        'The requested member was not found.',
        array(
            'code' =>
                'USER_NOT_FOUND'
        ),
        404
    );

}


/* ============================================================
   PROFILE
============================================================ */

$profile =
    array();


$profileStmt =
    $pdo->prepare(
        "
        SELECT

            id,

            user_id,

            display_name,

            bio,

            occupation,

            education,

            city,

            relationship_status,

            looking_for,

            interests,

            profile_visibility,

            show_online_status,

            allow_messages,

            created_at,

            updated_at

        FROM profiles

        WHERE user_id =
            :user_id

        LIMIT 1
        "
    );


$profileStmt->execute(
    array(
        ':user_id' =>
            $targetUserId
    )
);


$profile =
    $profileStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !is_array(
        $profile
    )
) {

    $profile =
        array();

}


/* ============================================================
   PROFILE VISIBILITY
============================================================ */

$profileVisibility =
    strtolower(
        trim(
            (string)(
                $profile['profile_visibility']
                ??
                'public'
            )
        )
    );


if (
    $profileVisibility !==
    'public'
) {

    profileViewResponse(
        false,
        'This profile is not currently public.',
        array(
            'code' =>
                'PROFILE_NOT_PUBLIC'
        ),
        403
    );

}


/* ============================================================
   PRIMARY PROFILE PHOTO
============================================================ */

$profilePhoto =
    null;


$photoStmt =
    $pdo->prepare(
        "
        SELECT

            id,

            file_name,

            file_path,

            thumbnail_path,

            mime_type,

            file_size,

            width,

            height,

            photo_type,

            approval_status,

            is_primary,

            is_featured,

            uploaded_at,

            approved_at

        FROM photos

        WHERE

            user_id =
                :user_id

            AND approval_status =
                'approved'

        ORDER BY

            is_primary DESC,

            uploaded_at DESC

        LIMIT 1
        "
    );


$photoStmt->execute(
    array(
        ':user_id' =>
            $targetUserId
    )
);


$profilePhoto =
    $photoStmt->fetch(
        PDO::FETCH_ASSOC
    );


if (
    !is_array(
        $profilePhoto
    )
) {

    $profilePhoto =
        null;

}


/* ============================================================
   ONLINE STATUS
============================================================ */

$isOnline =
    false;


try {

    $onlineStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM user_sessions

            WHERE

                user_id =
                    :user_id

                AND revoked_at IS NULL

                AND expires_at >
                    CURRENT_TIMESTAMP

                AND last_activity_at >=
                    DATE_SUB(
                        CURRENT_TIMESTAMP,
                        INTERVAL 10 MINUTE
                    )

            ORDER BY
                last_activity_at DESC

            LIMIT 1
            "
        );


    $onlineStmt->execute(
        array(
            ':user_id' =>
                $targetUserId
        )
    );


    $onlineRow =
        $onlineStmt->fetch(
            PDO::FETCH_ASSOC
        );


    $isOnline =
        is_array(
            $onlineRow
        );

} catch (
    Throwable $e
) {

    /*
     * Presence should never stop the profile from loading.
     */

    error_log(
        '[LOVEMI DISCOVER PROFILE PRESENCE] '
        .
        $e->getMessage()
    );


    $isOnline =
        false;

}


/* ============================================================
   CONNECTION STATUS
============================================================ */

$connectionStatus =
    '';


try {

    $connectionStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                user_id,

                connected_user_id,

                initiated_by,

                status,

                connected_at,

                created_at

            FROM connections

            WHERE

                (
                    user_id =
                        :current_user_one

                    AND connected_user_id =
                        :target_user_one
                )

                OR

                (
                    user_id =
                        :target_user_two

                    AND connected_user_id =
                        :current_user_two
                )

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $connectionStmt->execute(
        array(
            ':current_user_one' =>
                $currentUserId,

            ':target_user_one' =>
                $targetUserId,

            ':target_user_two' =>
                $targetUserId,

            ':current_user_two' =>
                $currentUserId
        )
    );


    $connection =
        $connectionStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        is_array(
            $connection
        )
    ) {

        $connectionRawStatus =
            strtolower(
                trim(
                    (string)(
                        $connection['status']
                        ??
                        ''
                    )
                )
            );


        if (
            $connectionRawStatus ===
            'accepted'
            ||
            $connectionRawStatus ===
            'connected'
        ) {

            $connectionStatus =
                'connected';

        } elseif (
            $connectionRawStatus ===
            'pending'
        ) {

            $initiatedBy =
                (int)(
                    $connection['initiated_by']
                    ??
                    0
                );


            if (
                $initiatedBy ===
                $currentUserId
            ) {

                $connectionStatus =
                    'pending_sent';

            } else {

                $connectionStatus =
                    'pending_received';

            }

        } else {

            $connectionStatus =
                $connectionRawStatus;

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI DISCOVER PROFILE CONNECTION] '
        .
        $e->getMessage()
    );


    $connectionStatus =
        '';

}


/* ============================================================
   POSTS
============================================================ */

$posts =
    array();


$postsStmt =
    $pdo->prepare(
        "
        SELECT

            p.id,

            p.user_id,

            p.content,

            p.visibility,

            p.approval_status,

            p.is_featured,

            p.created_at,

            p.updated_at,

            p.approved_at

        FROM posts p

        WHERE

            p.user_id =
                :user_id

            AND p.approval_status =
                'approved'

            AND p.visibility =
                'public'

            AND p.deleted_at IS NULL

        ORDER BY
            p.created_at DESC

        LIMIT 100
        "
    );


$postsStmt->execute(
    array(
        ':user_id' =>
            $targetUserId
    )
);


$postRows =
    $postsStmt->fetchAll(
        PDO::FETCH_ASSOC
    );


if (
    !is_array(
        $postRows
    )
) {

    $postRows =
        array();

}


/* ============================================================
   LOAD EACH POST AND ALL MEDIA
============================================================ */

foreach (
    $postRows
    as $post
) {

    $postId =
        (int)(
            $post['id']
            ??
            0
        );


    $post['id'] =
        $postId;


    $post['user_id'] =
        (int)(
            $post['user_id']
            ??
            $targetUserId
        );


    $post['post_id'] =
        $postId;


    $post['posted_at'] =
        $post['created_at']
        ??
        null;


    $post['media'] =
        array();


    /*
     * Load ALL approved media associated with this post.
     *
     * This is important because the old public view was often
     * limited to display_order = 1.
     */

    if (
        $postId > 0
    ) {

        $mediaStmt =
            $pdo->prepare(
                "
                SELECT

                    ph.id,

                    ph.user_id,

                    ph.file_name,

                    ph.file_path,

                    ph.thumbnail_path,

                    ph.mime_type,

                    ph.file_size,

                    ph.width,

                    ph.height,

                    ph.photo_type,

                    ph.approval_status,

                    ph.is_primary,

                    ph.is_featured,

                    ph.uploaded_at,

                    pp.display_order,

                    pp.created_at AS linked_at

                FROM post_photos pp

                INNER JOIN photos ph
                    ON ph.id =
                        pp.photo_id

                WHERE

                    pp.post_id =
                        :post_id

                    AND ph.user_id =
                        :user_id

                    AND ph.approval_status =
                        'approved'

                ORDER BY

                    pp.display_order ASC,

                    pp.id ASC

                LIMIT 50
                "
            );


        $mediaStmt->execute(
            array(
                ':post_id' =>
                    $postId,

                ':user_id' =>
                    $targetUserId
            )
        );


        $mediaRows =
            $mediaStmt->fetchAll(
                PDO::FETCH_ASSOC
            );


        if (
            is_array(
                $mediaRows
            )
        ) {

            foreach (
                $mediaRows
                as $media
            ) {

                $media['id'] =
                    (int)(
                        $media['id']
                        ??
                        0
                    );


                $media['user_id'] =
                    (int)(
                        $media['user_id']
                        ??
                        $targetUserId
                    );


                $media['display_order'] =
                    (int)(
                        $media['display_order']
                        ??
                        1
                    );


                $post['media'][] =
                    $media;

            }

        }

    }


    /*
     * Legacy fields kept for compatibility with your existing
     * Discover JavaScript.
     */

    if (
        !empty(
            $post['media']
        )
    ) {

        $firstMedia =
            $post['media'][0];


        $post['media_url'] =
            $firstMedia['file_path']
            ??
            '';


        $post['file_path'] =
            $firstMedia['file_path']
            ??
            '';


        $post['post_image'] =
            $firstMedia['file_path']
            ??
            '';


        $post['post_thumbnail'] =
            $firstMedia['thumbnail_path']
            ??
            '';


        $post['mime_type'] =
            $firstMedia['mime_type']
            ??
            '';

    } else {

        $post['media_url'] =
            '';


        $post['file_path'] =
            '';


        $post['post_image'] =
            '';


        $post['post_thumbnail'] =
            '';


        $post['mime_type'] =
            '';

    }


    $posts[] =
        $post;

}


/* ============================================================
   SAFE COUNTRY OBJECT
============================================================ */

$countryObject =
    array(

        'id' =>
            (int)(
                $user['country_id']
                ??
                0
            ),

        'name' =>
            (string)(
                $user['country_name']
                ??
                ''
            ),

        'iso2' =>
            (string)(
                $user['country_iso2']
                ??
                ''
            )

    );


/* ============================================================
   PROFILE OBJECT
============================================================ */

$profile['user_id'] =
    $targetUserId;


$profile['display_name'] =
    $profile['display_name']
    ??
    $user['full_names']
    ??
    $user['username']
    ??
    'LOVEMI Member';


$profile['country_id'] =
    (int)(
        $user['country_id']
        ??
        0
    );


$profile['country_name'] =
    (string)(
        $user['country_name']
        ??
        ''
    );


$profile['country'] =
    $countryObject;


$profile['is_online'] =
    $isOnline;


$profile['online'] =
    $isOnline;


$profile['connection_status'] =
    $connectionStatus;


/* ============================================================
   PROFILE PHOTO
============================================================ */

$profile['profile_photo'] =
    $profilePhoto['file_path']
    ??
    '';


$profile['profile_thumbnail'] =
    $profilePhoto['thumbnail_path']
    ??
    '';


$profile['photo'] =
    $profilePhoto
    ?:
    null;


/* ============================================================
   USER OBJECT
============================================================ */

$userResponse =
    array(

        'id' =>
            (int)(
                $user['id']
                ??
                $targetUserId
            ),

        'user_id' =>
            (int)(
                $user['id']
                ??
                $targetUserId
            ),

        'username' =>
            (string)(
                $user['username']
                ??
                ''
            ),

        'full_names' =>
            (string)(
                $user['full_names']
                ??
                ''
            ),

        'full_name' =>
            (string)(
                $user['full_names']
                ??
                ''
            ),

        'gender' =>
            (string)(
                $user['gender']
                ??
                ''
            ),

        'country_id' =>
            (int)(
                $user['country_id']
                ??
                0
            ),

        'country_name' =>
            (string)(
                $user['country_name']
                ??
                ''
            ),

        'country' =>
            $countryObject,

        'iso2' =>
            (string)(
                $user['country_iso2']
                ??
                ''
            ),

        'date_of_birth' =>
            $user['date_of_birth']
            ??
            null,

        'last_seen_at' =>
            $user['last_seen_at']
            ??
            null,

        'created_at' =>
            $user['created_at']
            ??
            null,

        'is_online' =>
            $isOnline,

        'online' =>
            $isOnline,

        'profile_photo' =>
            $profilePhoto['file_path']
            ??
            '',

        'profile_thumbnail' =>
            $profilePhoto['thumbnail_path']
            ??
            '',

        'connection_status' =>
            $connectionStatus

    );


/* ============================================================
   FINAL RESPONSE
============================================================ */

profileViewResponse(
    true,
    'Profile loaded successfully.',
    array(

        'profile' =>
            array(

                /*
                 * User data.
                 */

                'user' =>
                    $userResponse,

                /*
                 * Profile table data.
                 */

                'profile' =>
                    $profile,

                /*
                 * Flattened fields for frontend compatibility.
                 */

                'id' =>
                    $userResponse['id'],

                'user_id' =>
                    $userResponse['user_id'],

                'username' =>
                    $userResponse['username'],

                'full_name' =>
                    $userResponse['full_name'],

                'full_names' =>
                    $userResponse['full_names'],

                'gender' =>
                    $userResponse['gender'],

                'country_id' =>
                    $userResponse['country_id'],

                'country_name' =>
                    $userResponse['country_name'],

                'country' =>
                    $countryObject,

                'date_of_birth' =>
                    $userResponse['date_of_birth'],

                'profile_photo' =>
                    $userResponse['profile_photo'],

                'profile_thumbnail' =>
                    $userResponse['profile_thumbnail'],

                'is_online' =>
                    $isOnline,

                'online' =>
                    $isOnline,

                'connection_status' =>
                    $connectionStatus,

                /*
                 * Profile-specific fields.
                 */

                'bio' =>
                    $profile['bio']
                    ??
                    '',

                'occupation' =>
                    $profile['occupation']
                    ??
                    '',

                'education' =>
                    $profile['education']
                    ??
                    '',

                'city' =>
                    $profile['city']
                    ??
                    '',

                'relationship_status' =>
                    $profile['relationship_status']
                    ??
                    '',

                'looking_for' =>
                    $profile['looking_for']
                    ??
                    '',

                'interests' =>
                    $profile['interests']
                    ??
                    '',

                'show_online_status' =>
                    (int)(
                        $profile['show_online_status']
                        ??
                        1
                    ),

                'allow_messages' =>
                    (int)(
                        $profile['allow_messages']
                        ??
                        1
                    ),

                /*
                 * Primary photo object.
                 */

                'photo' =>
                    $profilePhoto,

                /*
                 * Public approved posts.
                 */

                'posts' =>
                    $posts,

                /*
                 * Statistics.
                 */

                'statistics' =>
                    array(

                        'posts' =>
                            count(
                                $posts
                            ),

                        'media' =>
                            array_sum(
                                array_map(
                                    function (
                                        $post
                                    ) {

                                        return count(
                                            is_array(
                                                $post['media']
                                                ??
                                                null
                                            )
                                                ?
                                                $post['media']
                                                :
                                                array()
                                        );

                                    },
                                    $posts
                                )
                            )

                    )

            )

    )
);