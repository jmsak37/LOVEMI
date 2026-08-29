<?php
/**
 * ============================================================
 * LOVEMI - UPDATE PROFILE API
 * ============================================================
 */

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


/* ============================================================
   SESSION
============================================================ */

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function updateProfileResponse(
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

    updateProfileResponse(
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
   USER
============================================================ */

$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ? (int)
        $_SESSION['lovemi_user_id']
        : 0;


if (
    $userId <= 0
) {

    updateProfileResponse(
        false,
        'Please log in before updating your profile.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED',
            'redirect' =>
                'login.html'
        ],
        401
    );
}


/* ============================================================
   INPUT
============================================================ */

$raw =
    file_get_contents(
        'php://input'
    );


$data =
    json_decode(
        $raw ?: '{}',
        true
    );


if (
    !is_array($data)
) {
    $data = [];
}


/* ============================================================
   FIELDS
============================================================ */

$fullNames =
    trim(
        (string)(
            $data['full_names']
            ??
            $data['full_name']
            ??
            ''
        )
    );


$gender =
    trim(
        (string)(
            $data['gender']
            ??
            ''
        )
    );


$countryId =
    isset(
        $data['country_id']
    )
        ? (int)$data['country_id']
        : 0;


$phoneNumber =
    trim(
        (string)(
            $data['phone_number']
            ??
            ''
        )
    );


$bio =
    trim(
        (string)(
            $data['bio']
            ??
            ''
        )
    );


$occupation =
    trim(
        (string)(
            $data['occupation']
            ??
            ''
        )
    );


$education =
    trim(
        (string)(
            $data['education']
            ??
            ''
        )
    );


$city =
    trim(
        (string)(
            $data['city']
            ??
            $data['location']
            ??
            ''
        )
    );


$relationshipStatus =
    trim(
        (string)(
            $data['relationship_status']
            ??
            ''
        )
    );


$lookingFor =
    trim(
        (string)(
            $data['looking_for']
            ??
            ''
        )
    );


$interests =
    trim(
        (string)(
            $data['interests']
            ??
            ''
        )
    );


/* ============================================================
   VALIDATION
============================================================ */

if (
    mb_strlen($fullNames) < 2
    ||
    mb_strlen($fullNames) > 180
) {

    updateProfileResponse(
        false,
        'Please enter valid full names.',
        [
            'code' =>
                'INVALID_FULL_NAMES'
        ],
        422
    );
}


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

    updateProfileResponse(
        false,
        'Please select a valid gender.',
        [
            'code' =>
                'INVALID_GENDER'
        ],
        422
    );
}


if (
    $countryId <= 0
) {

    updateProfileResponse(
        false,
        'Please select a valid country.',
        [
            'code' =>
                'INVALID_COUNTRY'
        ],
        422
    );
}


if (
    mb_strlen($bio) > 5000
) {

    updateProfileResponse(
        false,
        'Your bio is too long.',
        [
            'code' =>
                'BIO_TOO_LONG'
        ],
        422
    );
}


if (
    mb_strlen($occupation) > 150
) {

    updateProfileResponse(
        false,
        'Occupation is too long.',
        [
            'code' =>
                'OCCUPATION_TOO_LONG'
        ],
        422
    );
}


if (
    mb_strlen($education) > 180
) {

    updateProfileResponse(
        false,
        'Education is too long.',
        [
            'code' =>
                'EDUCATION_TOO_LONG'
        ],
        422
    );
}


if (
    mb_strlen($city) > 120
) {

    updateProfileResponse(
        false,
        'City/location is too long.',
        [
            'code' =>
                'CITY_TOO_LONG'
        ],
        422
    );
}


if (
    mb_strlen($relationshipStatus) > 50
) {

    updateProfileResponse(
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
    mb_strlen($lookingFor) > 100
) {

    updateProfileResponse(
        false,
        'Looking-for information is too long.',
        [
            'code' =>
                'LOOKING_FOR_TOO_LONG'
        ],
        422
    );
}


if (
    mb_strlen($interests) > 5000
) {

    updateProfileResponse(
        false,
        'Your interests are too long.',
        [
            'code' =>
                'INTERESTS_TOO_LONG'
        ],
        422
    );
}


/* ============================================================
   PHONE
============================================================ */

$cleanPhone =
    preg_replace(
        '/[^0-9+]/',
        '',
        $phoneNumber
    );


if (
    !is_string(
        $cleanPhone
    )
) {

    $cleanPhone =
        '';

}


if (
    $cleanPhone !== ''
    &&
    (
        strlen($cleanPhone) < 7
        ||
        strlen($cleanPhone) > 30
    )
) {

    updateProfileResponse(
        false,
        'Please enter a valid phone number.',
        [
            'code' =>
                'INVALID_PHONE'
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
        '[LOVEMI UPDATE PROFILE DB] '
        .
        $e->getMessage()
    );

    updateProfileResponse(
        false,
        'Unable to connect to the database.',
        [],
        500
    );
}


/* ============================================================
   ACCOUNT CHECK
============================================================ */

try {

    $userStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                email_verified,
                is_active,
                is_suspended,
                is_deleted

            FROM users

            WHERE id = :id

            LIMIT 1
            "
        );


    $userStmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $user =
        $userStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPDATE PROFILE USER] '
        .
        $e->getMessage()
    );

    updateProfileResponse(
        false,
        'Unable to load your account.',
        [],
        500
    );
}


if (
    !$user
) {

    updateProfileResponse(
        false,
        'Your account could not be found.',
        [],
        404
    );
}


if (
    !(bool)$user['email_verified']
) {

    updateProfileResponse(
        false,
        'Please complete email verification first.',
        [
            'code' =>
                'EMAIL_NOT_VERIFIED'
        ],
        403
    );
}


if (
    !(bool)$user['is_active']
    ||
    (bool)$user['is_suspended']
    ||
    (bool)$user['is_deleted']
) {

    updateProfileResponse(
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
   COUNTRY
============================================================ */

try {

    $countryStmt =
        $pdo->prepare(
            "
            SELECT

                id,
                name,
                iso2,
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

} catch (Throwable $e) {

    error_log(
        '[LOVEMI UPDATE COUNTRY] '
        .
        $e->getMessage()
    );

    updateProfileResponse(
        false,
        'Unable to validate the selected country.',
        [],
        500
    );
}


if (
    !$country
) {

    updateProfileResponse(
        false,
        'The selected country does not exist or is inactive.',
        [
            'code' =>
                'COUNTRY_NOT_FOUND'
        ],
        422
    );
}


/* ============================================================
   PHONE E164
============================================================ */

$phoneE164 =
    $cleanPhone;


if (
    $cleanPhone !== ''
) {

    $digits =
        ltrim(
            $cleanPhone,
            '+'
        );


    /*
     * If the user entered only a local number,
     * add the selected country code.
     */

    if (
        !str_starts_with(
            $digits,
            ltrim(
                (string)$country['phone_code'],
                '+'
            )
        )
    ) {

        $digits =
            ltrim(
                $digits,
                '0'
            );


        $phoneE164 =
            '+'
            .
            ltrim(
                (string)$country['phone_code'],
                '+'
            )
            .
            $digits;

    } else {

        $phoneE164 =
            '+'
            .
            $digits;

    }

}


/* ============================================================
   PHONE DUPLICATE
============================================================ */

if (
    $phoneE164 !== ''
) {

    try {

        $phoneStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM users

                WHERE phone_e164 = :phone

                  AND id <> :user_id

                LIMIT 1
                "
            );


        $phoneStmt->execute(
            [
                ':phone' =>
                    $phoneE164,

                ':user_id' =>
                    $userId
            ]
        );


        if (
            $phoneStmt->fetch()
        ) {

            updateProfileResponse(
                false,
                'That phone number is already used by another account.',
                [
                    'code' =>
                        'PHONE_ALREADY_EXISTS'
                ],
                409
            );
        }

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI PHONE CHECK] '
            .
            $e->getMessage()
        );

        updateProfileResponse(
            false,
            'Unable to validate your phone number.',
            [],
            500
        );
    }
}


/* ============================================================
   SAVE
============================================================ */

try {

    $pdo->beginTransaction();


    /*
     * Update USERS table.
     *
     * These columns actually exist in your schema.
     */

    $userUpdate =
        $pdo->prepare(
            "
            UPDATE users

            SET

                full_names = :full_names,

                gender = :gender,

                country_id = :country_id,

                phone_number = :phone_number,

                phone_e164 = :phone_e164

            WHERE id = :id

            LIMIT 1
            "
        );


    $userUpdate->execute(
        [
            ':full_names' =>
                $fullNames,

            ':gender' =>
                $gender,

            ':country_id' =>
                $countryId,

            ':phone_number' =>
                $phoneNumber,

            ':phone_e164' =>
                $phoneE164,

            ':id' =>
                $userId
        ]
    );


    /*
     * Update PROFILE table.
     *
     * display_name, bio, occupation, education, city, etc.
     * are real columns in profiles.
     */

    $profileUpdate =
        $pdo->prepare(
            "
            INSERT INTO profiles
            (
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
                allow_messages
            )

            VALUES
            (
                :user_id,
                :display_name,
                :bio,
                :occupation,
                :education,
                :city,
                :relationship_status,
                :looking_for,
                :interests,
                'public',
                TRUE,
                TRUE
            )

            ON DUPLICATE KEY UPDATE

                display_name =
                    VALUES(display_name),

                bio =
                    VALUES(bio),

                occupation =
                    VALUES(occupation),

                education =
                    VALUES(education),

                city =
                    VALUES(city),

                relationship_status =
                    VALUES(relationship_status),

                looking_for =
                    VALUES(looking_for),

                interests =
                    VALUES(interests),

                updated_at =
                    CURRENT_TIMESTAMP
            "
        );


    $profileUpdate->execute(
        [
            ':user_id' =>
                $userId,

            ':display_name' =>
                $fullNames,

            ':bio' =>
                $bio !== ''
                    ? $bio
                    : null,

            ':occupation' =>
                $occupation !== ''
                    ? $occupation
                    : null,

            ':education' =>
                $education !== ''
                    ? $education
                    : null,

            ':city' =>
                $city !== ''
                    ? $city
                    : null,

            ':relationship_status' =>
                $relationshipStatus !== ''
                    ? $relationshipStatus
                    : null,

            ':looking_for' =>
                $lookingFor !== ''
                    ? $lookingFor
                    : null,

            ':interests' =>
                $interests !== ''
                    ? $interests
                    : null
        ]
    );


    /*
     * Audit without storing the phone number or other
     * sensitive values.
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
                    new_values,
                    ip_address,
                    user_agent
                )

                VALUES
                (
                    :user_id,
                    'profile_update',
                    'profile',
                    :entity_id,
                    :new_values,
                    :ip,
                    :agent
                )
                "
            );


        $audit->execute(
            [
                ':user_id' =>
                    $userId,

                ':entity_id' =>
                    $userId,

                ':new_values' =>
                    json_encode(
                        [
                            'updated_fields' =>
                                [
                                    'full_names',
                                    'gender',
                                    'country_id',
                                    'phone_number',
                                    'bio',
                                    'occupation',
                                    'education',
                                    'city',
                                    'relationship_status',
                                    'looking_for',
                                    'interests'
                                ]
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

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI PROFILE AUDIT] '
            .
            $auditError->getMessage()
        );
    }


    $pdo->commit();

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();
    }


    error_log(
        '[LOVEMI UPDATE PROFILE ERROR] '
        .
        $e->getMessage()
    );


    updateProfileResponse(
        false,
        'Your profile could not be saved.',
        [
            'code' =>
                'PROFILE_SAVE_FAILED',

            'technical' =>
                'Database update failed. Check the PHP error log.'
        ],
        500
    );
}


/* ============================================================
   RETURN FRESH PROFILE
============================================================ */

try {

    $freshStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,
                u.username,
                u.full_names,
                u.gender,
                u.email,
                u.country_id,
                u.phone_number,
                u.date_of_birth,

                c.name AS country_name,
                c.iso2 AS country_iso2,
                c.phone_code AS country_phone_code,

                p.display_name,
                p.bio,
                p.occupation,
                p.education,
                p.city,
                p.relationship_status,
                p.looking_for,
                p.interests,

                (
                    SELECT
                        COALESCE(
                            ph.thumbnail_path,
                            ph.file_path
                        )

                    FROM photos ph

                    WHERE ph.user_id = u.id

                      AND ph.photo_type = 'profile'

                      AND ph.approval_status = 'approved'

                    ORDER BY
                        ph.is_primary DESC,
                        ph.approved_at DESC,
                        ph.id DESC

                    LIMIT 1

                ) AS profile_photo

            FROM users u

            LEFT JOIN countries c
                ON c.id = u.country_id

            LEFT JOIN profiles p
                ON p.user_id = u.id

            WHERE u.id = :id

            LIMIT 1
            "
        );


    $freshStmt->execute(
        [
            ':id' =>
                $userId
        ]
    );


    $fresh =
        $freshStmt->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI FRESH PROFILE] '
        .
        $e->getMessage()
    );


    updateProfileResponse(
        true,
        'Your profile was saved successfully.'
    );
}


/* ============================================================
   RESPONSE
============================================================ */

updateProfileResponse(
    true,
    'Your profile was saved successfully.',
    [
        'profile' =>
            [
                'id' =>
                    (int)$fresh['id'],

                'username' =>
                    (string)$fresh['username'],

                'full_name' =>
                    (string)$fresh['full_names'],

                'full_names' =>
                    (string)$fresh['full_names'],

                'gender' =>
                    (string)$fresh['gender'],

                'email' =>
                    (string)$fresh['email'],

                'country_id' =>
                    (int)$fresh['country_id'],

                'country_name' =>
                    $fresh['country_name'],

                'country_iso2' =>
                    $fresh['country_iso2'],

                'country_phone_code' =>
                    $fresh['country_phone_code'],

                'phone_number' =>
                    $fresh['phone_number'],

                'date_of_birth' =>
                    $fresh['date_of_birth'],

                'display_name' =>
                    $fresh['display_name']
                    ?: $fresh['full_names'],

                'bio' =>
                    $fresh['bio'],

                'occupation' =>
                    $fresh['occupation'],

                'education' =>
                    $fresh['education'],

                'city' =>
                    $fresh['city'],

                'location' =>
                    $fresh['city'],

                'relationship_status' =>
                    $fresh['relationship_status'],

                'looking_for' =>
                    $fresh['looking_for'],

                'interests' =>
                    $fresh['interests'],

                'profile_photo' =>
                    $fresh['profile_photo']
            ]
    ]
);