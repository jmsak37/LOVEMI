<?php

declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI ADMIN - SYSTEM SETTINGS UPDATE API
 * ============================================================
 *
 * Updates existing records in:
 *
 *     system_settings
 *
 * Security:
 *
 * 1. Requires a valid PHP login session.
 * 2. Requires a valid database user_sessions record.
 * 3. Requires two-factor verification.
 * 4. Requires an admin role.
 * 5. Requires settings.manage permission.
 * 6. Updates only settings that already exist.
 * 7. Records changes in audit_logs.
 *
 * ============================================================
 */


/* ============================================================
   ERROR DISPLAY
   Never send PHP errors into the JSON response.
============================================================ */

error_reporting(E_ALL);

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'display_startup_errors',
    '0'
);


/* ============================================================
   DATABASE
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


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

function settingsUpdateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    if (
        ob_get_level() > 0
    ) {

        while (
            ob_get_level() > 0
        ) {

            ob_end_clean();

        }

    }


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
        |
        JSON_INVALID_UTF8_SUBSTITUTE
    );


    exit;

}


/* ============================================================
   GLOBAL EXCEPTION HANDLER
============================================================ */

set_exception_handler(
    function (
        Throwable $exception
    ): void {

        error_log(
            '[LOVEMI SYSTEM SETTINGS UPDATE EXCEPTION] '
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


        settingsUpdateResponse(
            false,
            'The server could not process the settings update.',
            [
                'code' =>
                    'SERVER_EXCEPTION'
            ],
            500
        );

    }
);


/* ============================================================
   GLOBAL ERROR HANDLER
============================================================ */

set_error_handler(
    function (
        int $severity,
        string $message,
        string $file,
        int $line
    ): bool {

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
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    settingsUpdateResponse(
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
   SESSION COOKIE
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

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


    session_start();

}


/* ============================================================
   DATABASE CONNECTION
============================================================ */

try {

    $pdo =
        db();


    if (
        !$pdo instanceof PDO
    ) {

        throw new RuntimeException(
            'Database connection is not a PDO instance.'
        );

    }


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SYSTEM SETTINGS UPDATE DATABASE] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
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
   SESSION INFORMATION
============================================================ */

$adminId =
    (int)(
        $_SESSION[
            'lovemi_user_id'
        ]
        ??
        0
    );


$databaseSessionId =
    (int)(
        $_SESSION[
            'lovemi_database_session_id'
        ]
        ??
        0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION[
                'lovemi_session_token'
            ]
            ??
            ''
        )
    );


/* ============================================================
   SESSION VALIDATION
============================================================ */

if (
    $adminId <= 0
    ||
    $databaseSessionId <= 0
    ||
    $sessionToken === ''
) {

    settingsUpdateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
        401
    );

}


/* ============================================================
   HASH SESSION TOKEN
============================================================ */

$sessionTokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/* ============================================================
   VERIFY ADMIN + 2FA + PERMISSION
============================================================ */

try {

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                u.role_id,

                r.name AS role_name,

                r.slug AS role_slug

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
                    :session_token_hash

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
                    'settings.manage'

            LIMIT 1
            "
        );


    $authStmt->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $databaseSessionId,

            ':session_token_hash' =>
                $sessionTokenHash

        ]
    );


    $admin =
        $authStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SYSTEM SETTINGS AUTH QUERY] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
        false,
        'Unable to verify administrator permissions.',
        [
            'code' =>
                'AUTHORIZATION_QUERY_ERROR'
        ],
        500
    );

}


if (
    !$admin
) {

    settingsUpdateResponse(
        false,
        'You do not have permission to manage system settings.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   UPDATE SESSION ACTIVITY
============================================================ */

try {

    $activityStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE

                id =
                    :session_id

                AND user_id =
                    :user_id

            LIMIT 1
            "
        );


    $activityStmt->execute(
        [

            ':session_id' =>
                $databaseSessionId,

            ':user_id' =>
                $adminId

        ]
    );

} catch (
    Throwable $e
) {

    /*
     * Activity update failure must not prevent an otherwise
     * valid settings operation. Log it only.
     */

    error_log(
        '[LOVEMI SYSTEM SETTINGS ACTIVITY ERROR] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   READ JSON REQUEST
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $rawBody,
        true
    );


if (
    !is_array(
        $input
    )
) {

    /*
     * Allow regular form POST as fallback.
     */

    $input =
        $_POST;

}


$settings =
    $input[
        'settings'
    ]
    ??
    null;


/* ============================================================
   VALIDATE SETTINGS ARRAY
============================================================ */

if (
    !is_array(
        $settings
    )
) {

    settingsUpdateResponse(
        false,
        'No settings were submitted.',
        [
            'code' =>
                'SETTINGS_REQUIRED'
        ],
        422
    );

}


if (
    count(
        $settings
    )
    ===
    0
) {

    settingsUpdateResponse(
        true,
        'No settings were changed.',
        [
            'updated_count' =>
                0,

            'updated' =>
                []
        ]
    );

}


/* ============================================================
   LOAD EXISTING SETTINGS
============================================================ */

try {

    $settingsStmt =
        $pdo->query(
            "
            SELECT

                id,

                setting_key,

                setting_value,

                value_type,

                description,

                is_public

            FROM system_settings

            ORDER BY
                id ASC
            "
        );


    $databaseSettings =
        $settingsStmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SYSTEM SETTINGS LOAD] '
        .
        $e->getMessage()
    );


    settingsUpdateResponse(
        false,
        'Unable to load the current system settings.',
        [
            'code' =>
                'SETTINGS_LOAD_ERROR'
        ],
        500
    );

}


/* ============================================================
   CREATE LOOKUP MAPS
============================================================ */

$settingsById =
    [];


foreach (
    $databaseSettings
    as $setting
) {

    $settingsById[
        (string)
        $setting['id']
    ] =
        $setting;

}


/* ============================================================
   VALIDATE EVERY REQUESTED CHANGE
============================================================ */

$changes =
    [];


foreach (
    $settings
    as $index =>
    $item
) {

    if (
        !is_array(
            $item
        )
    ) {

        settingsUpdateResponse(
            false,
            'Invalid setting data at item '
            .
            (
                (int)
                $index
                +
                1
            )
            .
            '.',
            [
                'code' =>
                    'INVALID_SETTING'
            ],
            422
        );

    }


    $id =
        (int)(
            $item['id']
            ??
            0
        );


    $submittedKey =
        trim(
            (string)(
                $item['setting_key']
                ??
                ''
            )
        );


    $submittedType =
        strtolower(
            trim(
                (string)(
                    $item['value_type']
                    ??
                    ''
                )
            )
        );


    $submittedValue =
        (string)(
            $item['setting_value']
            ??
            ''
        );


    /* ========================================================
       ID
    ======================================================== */

    if (
        $id <= 0
    ) {

        settingsUpdateResponse(
            false,
            'Invalid setting ID.',
            [
                'code' =>
                    'INVALID_SETTING_ID'
            ],
            422
        );

    }


    /* ========================================================
       EXISTING RECORD
    ======================================================== */

    if (
        !isset(
            $settingsById[
                (string)
                $id
            ]
        )
    ) {

        settingsUpdateResponse(
            false,
            'The requested setting does not exist.',
            [
                'code' =>
                    'SETTING_NOT_FOUND',

                'setting_id' =>
                    $id

            ],
            404
        );

    }


    $current =
        $settingsById[
            (string)
            $id
        ];


    /* ========================================================
       KEY PROTECTION
    ======================================================== */

    if (
        $submittedKey === ''
        ||
        $submittedKey
        !==
        (string)
        $current['setting_key']
    ) {

        settingsUpdateResponse(
            false,
            'The setting key is invalid or does not match the database record.',
            [
                'code' =>
                    'SETTING_KEY_MISMATCH',

                'setting_id' =>
                    $id

            ],
            422
        );

    }


    $settingKey =
        (string)
        $current['setting_key'];


    /* ========================================================
       TYPE PROTECTION
    ======================================================== */

    $databaseType =
        strtolower(
            (string)
            $current['value_type']
        );


    if (
        $submittedType === ''
    ) {

        $submittedType =
            $databaseType;

    }


    if (
        $submittedType
        !==
        $databaseType
    ) {

        settingsUpdateResponse(
            false,
            "The value type for {$settingKey} cannot be changed.",
            [
                'code' =>
                    'SETTING_TYPE_MISMATCH',

                'setting_key' =>
                    $settingKey

            ],
            422
        );

    }


    /* ========================================================
       SUPPORTED TYPES
    ======================================================== */

    if (
        !in_array(
            $databaseType,
            [
                'string',
                'integer',
                'decimal',
                'boolean'
            ],
            true
        )
    ) {

        settingsUpdateResponse(
            false,
            "Unsupported value type for {$settingKey}.",
            [
                'code' =>
                    'UNSUPPORTED_VALUE_TYPE',

                'setting_key' =>
                    $settingKey

            ],
            422
        );

    }


    /* ========================================================
       NORMALIZE VALUE
    ======================================================== */

    $newValue =
        trim(
            $submittedValue
        );


    /* ========================================================
       STRING
    ======================================================== */

    if (
        $databaseType ===
        'string'
    ) {

        if (
            mb_strlen(
                $newValue
            )
            >
            1000
        ) {

            settingsUpdateResponse(
                false,
                "The value for {$settingKey} is too long.",
                [
                    'code' =>
                        'VALUE_TOO_LONG'
                ],
                422
            );

        }

    }


    /* ========================================================
       INTEGER
    ======================================================== */

    if (
        $databaseType ===
        'integer'
    ) {

        if (
            !preg_match(
                '/^-?\d+$/',
                $newValue
            )
        ) {

            settingsUpdateResponse(
                false,
                "The value for {$settingKey} must be a whole number.",
                [
                    'code' =>
                        'INVALID_INTEGER'
                ],
                422
            );

        }


        $integerValue =
            filter_var(
                $newValue,
                FILTER_VALIDATE_INT
            );


        if (
            $integerValue ===
            false
        ) {

            settingsUpdateResponse(
                false,
                "The integer value for {$settingKey} is invalid.",
                [
                    'code' =>
                        'INVALID_INTEGER'
                ],
                422
            );

        }


        $newValue =
            (string)
            $integerValue;

    }


    /* ========================================================
       DECIMAL
    ======================================================== */

    if (
        $databaseType ===
        'decimal'
    ) {

        if (
            !preg_match(
                '/^-?\d+(?:\.\d+)?$/',
                $newValue
            )
        ) {

            settingsUpdateResponse(
                false,
                "The value for {$settingKey} must be a valid decimal number.",
                [
                    'code' =>
                        'INVALID_DECIMAL'
                ],
                422
            );

        }


        $decimalValue =
            (float)
            $newValue;


        if (
            !is_finite(
                $decimalValue
            )
        ) {

            settingsUpdateResponse(
                false,
                "The decimal value for {$settingKey} is invalid.",
                [
                    'code' =>
                        'INVALID_DECIMAL'
                ],
                422
            );

        }


        /*
         * Premium price is stored as two decimal places.
         */

        if (
            $settingKey ===
            'premium_price_usd'
        ) {

            $newValue =
                number_format(
                    $decimalValue,
                    2,
                    '.',
                    ''
                );

        }

    }


    /* ========================================================
       BOOLEAN
    ======================================================== */

    if (
        $databaseType ===
        'boolean'
    ) {

        $normalizedBoolean =
            strtolower(
                $newValue
            );


        if (
            in_array(
                $normalizedBoolean,
                [
                    '1',
                    'true',
                    'yes',
                    'on'
                ],
                true
            )
        ) {

            $newValue =
                '1';

        } elseif (
            in_array(
                $normalizedBoolean,
                [
                    '0',
                    'false',
                    'no',
                    'off'
                ],
                true
            )
        ) {

            $newValue =
                '0';

        } else {

            settingsUpdateResponse(
                false,
                "Invalid boolean value for {$settingKey}.",
                [
                    'code' =>
                        'INVALID_BOOLEAN'
                ],
                422
            );

        }

    }


    /* ========================================================
       BUSINESS RULES
    ======================================================== */

    /*
     * LOVEMI requires members to be adults.
     */

    if (
        $settingKey ===
        'minimum_age'
    ) {

        $age =
            (int)
            $newValue;


        if (
            $age < 18
            ||
            $age > 120
        ) {

            settingsUpdateResponse(
                false,
                'Minimum age must be between 18 and 120.',
                [
                    'code' =>
                        'INVALID_MINIMUM_AGE'
                ],
                422
            );

        }

    }


    /*
     * Premium price cannot be negative.
     */

    if (
        $settingKey ===
        'premium_price_usd'
    ) {

        if (
            (float)
            $newValue
            <
            0
        ) {

            settingsUpdateResponse(
                false,
                'Premium price cannot be negative.',
                [
                    'code' =>
                        'INVALID_PREMIUM_PRICE'
                ],
                422
            );

        }

    }


    /*
     * Premium duration.
     */

    if (
        $settingKey ===
        'premium_duration_days'
    ) {

        if (
            (int)
            $newValue
            <
            1
        ) {

            settingsUpdateResponse(
                false,
                'Premium duration must be at least one day.',
                [
                    'code' =>
                        'INVALID_PREMIUM_DURATION'
                ],
                422
            );

        }

    }


    /*
     * Password reset attempts.
     */

    if (
        $settingKey ===
        'password_reset_max_attempts'
    ) {

        if (
            (int)
            $newValue
            <
            1
        ) {

            settingsUpdateResponse(
                false,
                'Password reset attempts must be at least one.',
                [
                    'code' =>
                        'INVALID_RESET_ATTEMPTS'
                ],
                422
            );

        }

    }


    /*
     * Latest post rotation.
     */

    if (
        $settingKey ===
        'latest_post_rotation_seconds'
    ) {

        if (
            (int)
            $newValue
            <
            1
        ) {

            settingsUpdateResponse(
                false,
                'Post rotation time must be at least one second.',
                [
                    'code' =>
                        'INVALID_ROTATION_TIME'
                ],
                422
            );

        }

    }


    /*
     * Application name.
     */

    if (
        $settingKey ===
        'app_name'
    ) {

        if (
            $newValue === ''
        ) {

            settingsUpdateResponse(
                false,
                'Application name cannot be empty.',
                [
                    'code' =>
                        'INVALID_APP_NAME'
                ],
                422
            );

        }

    }


    /*
     * Currency codes.
     */

    if (
        $settingKey ===
        'base_currency'
        ||
        $settingKey ===
        'kenya_currency'
    ) {

        $newValue =
            strtoupper(
                $newValue
            );


        if (
            !preg_match(
                '/^[A-Z]{3}$/',
                $newValue
            )
        ) {

            settingsUpdateResponse(
                false,
                "Currency code for {$settingKey} must contain exactly three letters.",
                [
                    'code' =>
                        'INVALID_CURRENCY_CODE'
                ],
                422
            );

        }

    }


    /*
     * Email verification must remain enabled because it is
     * part of the LOVEMI authentication flow.
     */

    if (
        $settingKey ===
        'require_email_verification'
        &&
        $newValue !==
        '1'
    ) {

        settingsUpdateResponse(
            false,
            'Email verification cannot be disabled.',
            [
                'code' =>
                    'EMAIL_VERIFICATION_REQUIRED'
            ],
            422
        );

    }


    /*
     * Phone and WhatsApp must not become publicly visible.
     */

    if (
        $settingKey ===
        'public_phone_numbers'
        &&
        $newValue !==
        '0'
    ) {

        settingsUpdateResponse(
            false,
            'Public phone numbers must remain disabled.',
            [
                'code' =>
                    'PHONE_PRIVACY_REQUIRED'
            ],
            422
        );

    }


    if (
        $settingKey ===
        'public_whatsapp_numbers'
        &&
        $newValue !==
        '0'
    ) {

        settingsUpdateResponse(
            false,
            'Public WhatsApp numbers must remain disabled.',
            [
                'code' =>
                    'WHATSAPP_PRIVACY_REQUIRED'
            ],
            422
        );

    }


    /* ========================================================
       SAVE CHANGE TO MEMORY
    ======================================================== */

    $changes[] =
        [

            'id' =>
                $id,

            'setting_key' =>
                $settingKey,

            'value_type' =>
                $databaseType,

            'old_value' =>
                (string)
                $current['setting_value'],

            'new_value' =>
                $newValue

        ];

}


/* ============================================================
   REMOVE DUPLICATES
============================================================ */

$uniqueChanges =
    [];


foreach (
    $changes
    as $change
) {

    $uniqueChanges[
        $change['id']
    ] =
        $change;

}


$changes =
    array_values(
        $uniqueChanges
    );


/* ============================================================
   KEEP ONLY REAL CHANGES
============================================================ */

$realChanges =
    [];


foreach (
    $changes
    as $change
) {

    if (
        (string)
        $change['old_value']
        !==
        (string)
        $change['new_value']
    ) {

        $realChanges[] =
            $change;

    }

}


if (
    !$realChanges
) {

    settingsUpdateResponse(
        true,
        'No system setting values were changed.',
        [

            'updated_count' =>
                0,

            'updated' =>
                []

        ]
    );

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    $updated =
        [];


    foreach (
        $realChanges
        as $change
    ) {

        /*
         * Re-check the row inside the transaction.
         */

        $verifyStmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    setting_key,

                    setting_value,

                    value_type

                FROM system_settings

                WHERE

                    id =
                        :id

                    AND setting_key =
                        :setting_key

                LIMIT 1

                FOR UPDATE
                "
            );


        $verifyStmt->execute(
            [

                ':id' =>
                    $change['id'],

                ':setting_key' =>
                    $change['setting_key']

            ]
        );


        $current =
            $verifyStmt->fetch();


        if (
            !$current
        ) {

            throw new RuntimeException(
                "Setting {$change['setting_key']} could not be found."
            );

        }


        /*
         * Do not overwrite a setting changed unexpectedly by
         * another process after the initial read.
         */

        if (
            (string)
            $current['setting_value']
            !==
            (string)
            $change['old_value']
        ) {

            throw new RuntimeException(
                "Setting {$change['setting_key']} changed while the request was being processed. Please reload the page and try again."
            );

        }


        $updateStmt =
            $pdo->prepare(
                "
                UPDATE system_settings

                SET

                    setting_value =
                        :setting_value,

                    updated_by =
                        :updated_by,

                    updated_at =
                        CURRENT_TIMESTAMP

                WHERE

                    id =
                        :id

                    AND setting_key =
                        :setting_key

                LIMIT 1
                "
            );


        $updateStmt->execute(
            [

                ':setting_value' =>
                    $change['new_value'],

                ':updated_by' =>
                    $adminId,

                ':id' =>
                    $change['id'],

                ':setting_key' =>
                    $change['setting_key']

            ]
        );


        /*
         * Do not use rowCount() as proof of failure.
         * MySQL may return zero when the value is unchanged.
         * We already verified the current value above.
         */

        $updated[] =
            [

                'id' =>
                    $change['id'],

                'setting_key' =>
                    $change['setting_key'],

                'old_value' =>
                    $change['old_value'],

                'new_value' =>
                    $change['new_value']

            ];

    }


    /* ========================================================
       AUDIT LOG
    ======================================================== */

    $oldValues =
        [];


    $newValues =
        [];


    foreach (
        $updated
        as $change
    ) {

        $oldValues[
            $change['setting_key']
        ] =
            $change['old_value'];


        $newValues[
            $change['setting_key']
        ] =
            $change['new_value'];

    }


    $auditStmt =
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
                'admin_update_system_settings',
                'system_settings',
                NULL,
                :old_values,
                :new_values,
                :ip_address,
                :user_agent
            )
            "
        );


    $auditStmt->execute(
        [

            ':user_id' =>
                $adminId,

            ':old_values' =>
                json_encode(
                    $oldValues,
                    JSON_UNESCAPED_UNICODE
                    |
                    JSON_UNESCAPED_SLASHES
                ),

            ':new_values' =>
                json_encode(
                    $newValues,
                    JSON_UNESCAPED_UNICODE
                    |
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


    error_log(
        '[LOVEMI SYSTEM SETTINGS UPDATE TRANSACTION] '
        .
        $e->getMessage()
        .
        ' in '
        .
        $e->getFile()
        .
        ':'
        .
        $e->getLine()
    );


    settingsUpdateResponse(
        false,
        $e->getMessage(),
        [
            'code' =>
                'SETTINGS_UPDATE_ERROR'
        ],
        500
    );

}


/* ============================================================
   FINAL RESPONSE
============================================================ */

settingsUpdateResponse(
    true,
    'System settings updated successfully.',
    [

        'updated_count' =>
            count(
                $updated
            ),

        'updated' =>
            $updated

    ]
);