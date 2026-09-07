<?php
/**
 * ============================================================
 * LOVEMI - PROFILE EXTRA DETAILS API
 * ============================================================
 *
 * Returns additional public profile information without
 * changing api/profile/data.php.
 *
 * Sources:
 *
 * profiles:
 * - city
 * - education
 * - education_level
 * - university_name
 * - course
 *
 * profile_extra_details:
 * - school_name
 * - course_name
 * - education_level
 * - state_region
 * - county_name
 * - town_area
 * - workplace
 * - industry
 * - languages
 * - website_url
 * - profile_note
 *
 * The secure profile-code system is reused through _helper.php.
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   PROFILE HELPER
============================================================ */

require_once
    __DIR__
    . '/_helper.php';


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
   RESPONSE
============================================================ */

function extraDetailsResponse(
    bool $success,
    string $message,
    array $data = [],
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
    strtoupper(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ??
            ''
        )
    )
    !==
    'GET'
) {

    extraDetailsResponse(
        false,
        'Only GET requests are allowed.',
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

$currentUserId =
    profileRequireAuth();


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        profileDb();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE EXTRA DB] '
        .
        $e->getMessage()
    );

    extraDetailsResponse(
        false,
        'Unable to connect to the database.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   RESOLVE PROFILE
============================================================ */

try {

    $request =
        resolveProfileRequest(
            $pdo,
            $currentUserId
        );


    $targetUserId =
        (int)(
            $request['user_id']
            ??
            0
        );


    $isOwner =
        (bool)(
            $request['is_owner']
            ??
            false
        );


    if (
        $targetUserId <= 0
    ) {

        extraDetailsResponse(
            false,
            'The requested profile could not be identified.',
            [
                'code' =>
                    'INVALID_PROFILE_ID'
            ],
            404
        );

    }


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE EXTRA RESOLVE] '
        .
        $e->getMessage()
    );

    extraDetailsResponse(
        false,
        'The requested profile could not be resolved.',
        [
            'code' =>
                'PROFILE_RESOLUTION_FAILED'
        ],
        404
    );

}


/* ============================================================
   LOAD PROFILE + COUNTRY
============================================================ */

try {

    $profileStmt =
        $pdo->prepare(
            '
            SELECT

                u.id AS user_id,

                u.username,

                u.country_id,

                c.name AS country_name,

                p.city,

                p.education,

                p.education_level,

                p.university_name,

                p.course

            FROM users u

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE u.id = :user_id

            LIMIT 1
            '
        );


    $profileStmt->execute(
        [
            ':user_id' =>
                $targetUserId
        ]
    );


    $profile =
        $profileStmt->fetch(
            PDO::FETCH_ASSOC
        );


    if (
        !$profile
    ) {

        extraDetailsResponse(
            false,
            'The requested profile could not be found.',
            [
                'code' =>
                    'PROFILE_NOT_FOUND'
            ],
            404
        );

    }


} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE EXTRA PROFILE QUERY] '
        .
        $e->getMessage()
    );

    extraDetailsResponse(
        false,
        'Unable to load the profile details.',
        [
            'code' =>
                'PROFILE_QUERY_ERROR'
        ],
        500
    );

}


/* ============================================================
   DEFAULT PROFILE VALUES
============================================================ */

$profileCity =
    trim(
        (string)(
            $profile['city']
            ??
            ''
        )
    );


$profileEducation =
    trim(
        (string)(
            $profile['education']
            ??
            ''
        )
    );


$profileEducationLevel =
    trim(
        (string)(
            $profile['education_level']
            ??
            ''
        )
    );


$profileUniversity =
    trim(
        (string)(
            $profile['university_name']
            ??
            ''
        )
    );


$profileCourse =
    trim(
        (string)(
            $profile['course']
            ??
            ''
        )
    );


$countryName =
    trim(
        (string)(
            $profile['country_name']
            ??
            ''
        )
    );


/* ============================================================
   CHECK OPTIONAL EXTRA TABLE
============================================================ */

$extraTableInstalled =
    false;

try {

    $tableStmt =
        $pdo->query(
            "
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = DATABASE()
              AND table_name = 'profile_extra_details'
            "
        );


    $extraTableInstalled =
        (
            (int)
            $tableStmt->fetchColumn()
            >
            0
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI PROFILE EXTRA TABLE CHECK] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   EXTRA DETAILS
============================================================ */

$extra =
    [];


if (
    $extraTableInstalled
) {

    try {

        $extraStmt =
            $pdo->prepare(
                '
                SELECT

                    school_name,

                    course_name,

                    education_level,

                    state_region,

                    county_name,

                    town_area,

                    workplace,

                    industry,

                    languages,

                    website_url,

                    profile_note,

                    created_at,

                    updated_at

                FROM profile_extra_details

                WHERE user_id = :user_id

                LIMIT 1
                '
            );


        $extraStmt->execute(
            [
                ':user_id' =>
                    $targetUserId
            ]
        );


        $extra =
            $extraStmt->fetch(
                PDO::FETCH_ASSOC
            )
            ?:
            [];


    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI PROFILE EXTRA DETAILS QUERY] '
            .
            $e->getMessage()
        );

        /*
         * Keep the API usable from the main profiles table
         * even if the optional extra table has a problem.
         */

        $extra =
            [];

    }

}


/* ============================================================
   PUBLIC DETAILS
============================================================ */

/*
 * Prefer data from profile_extra_details where available.
 * Fall back to profiles for registration data.
 */

$schoolName =
    trim(
        (string)(
            $extra['school_name']
            ??
            ''
        )
    );


if (
    $schoolName === ''
) {

    $schoolName =
        $profileUniversity;

}


$courseName =
    trim(
        (string)(
            $extra['course_name']
            ??
            ''
        )
    );


if (
    $courseName === ''
) {

    $courseName =
        $profileCourse;

}


$educationLevel =
    trim(
        (string)(
            $extra['education_level']
            ??
            ''
        )
    );


if (
    $educationLevel === ''
) {

    $educationLevel =
        $profileEducationLevel;

}


if (
    $educationLevel === ''
) {

    $educationLevel =
        $profileEducation;

}


$stateRegion =
    trim(
        (string)(
            $extra['state_region']
            ??
            ''
        )
    );


$countyName =
    trim(
        (string)(
            $extra['county_name']
            ??
            ''
        )
    );


$townArea =
    trim(
        (string)(
            $extra['town_area']
            ??
            ''
        )
    );


$workplace =
    trim(
        (string)(
            $extra['workplace']
            ??
            ''
        )
    );


$industry =
    trim(
        (string)(
            $extra['industry']
            ??
            ''
        )
    );


$languages =
    trim(
        (string)(
            $extra['languages']
            ??
            ''
        )
    );


$websiteUrl =
    trim(
        (string)(
            $extra['website_url']
            ??
            ''
        )
    );


$profileNote =
    trim(
        (string)(
            $extra['profile_note']
            ??
            ''
        )
    );


/* ============================================================
   RESPONSE DETAILS
============================================================ */

extraDetailsResponse(
    true,
    'Additional profile details loaded successfully.',
    [

        'installed' =>
            $extraTableInstalled,

        'user_id' =>
            $targetUserId,

        'is_owner' =>
            $isOwner,

        'details' =>
            [

                /*
                 * Data from registration.php / profiles
                 */

                'city' =>
                    $profileCity !== ''
                        ? $profileCity
                        : null,

                'country_name' =>
                    $countryName !== ''
                        ? $countryName
                        : null,

                'education' =>
                    $profileEducation !== ''
                        ? $profileEducation
                        : null,

                'university_name' =>
                    $profileUniversity !== ''
                        ? $profileUniversity
                        : null,

                'course' =>
                    $profileCourse !== ''
                        ? $profileCourse
                        : null,

                /*
                 * Additional details
                 */

                'school_name' =>
                    $schoolName !== ''
                        ? $schoolName
                        : null,

                'course_name' =>
                    $courseName !== ''
                        ? $courseName
                        : null,

                'education_level' =>
                    $educationLevel !== ''
                        ? $educationLevel
                        : null,

                'state_region' =>
                    $stateRegion !== ''
                        ? $stateRegion
                        : null,

                'county_name' =>
                    $countyName !== ''
                        ? $countyName
                        : null,

                'town_area' =>
                    $townArea !== ''
                        ? $townArea
                        : null,

                'workplace' =>
                    $workplace !== ''
                        ? $workplace
                        : null,

                'industry' =>
                    $industry !== ''
                        ? $industry
                        : null,

                'languages' =>
                    $languages !== ''
                        ? $languages
                        : null,

                'website_url' =>
                    $websiteUrl !== ''
                        ? $websiteUrl
                        : null,

                'profile_note' =>
                    $profileNote !== ''
                        ? $profileNote
                        : null,

                'created_at' =>
                    isset(
                        $extra['created_at']
                    )
                        ?
                        (string)
                        $extra['created_at']
                        :
                        null,

                'updated_at' =>
                    isset(
                        $extra['updated_at']
                    )
                        ?
                        (string)
                        $extra['updated_at']
                        :
                        null

            ]

    ],
    200
);