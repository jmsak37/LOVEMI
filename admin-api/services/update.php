<?php

declare(strict_types=1);

error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');


function servicesUpdateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    http_response_code($status);

    echo json_encode(
        [
            'success' => $success,
            'message' => $message,
            'data' => $data
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
        |
        JSON_INVALID_UTF8_SUBSTITUTE
    );

    exit;
}


function servicesUpdateInput(): array
{

    $raw =
        file_get_contents(
            'php://input'
        );

    $json =
        json_decode(
            $raw ?: '{}',
            true
        );

    return
        is_array($json)
            ?
            $json
            :
            $_POST;

}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    servicesUpdateResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_set_cookie_params(
        [
            'lifetime' => 0,
            'path' => '/',
            'secure' => $isHttps,
            'httponly' => true,
            'samesite' => 'Lax'
        ]
    );

    session_start();

}


/* ============================================================
   DB
============================================================ */

try {

    $pdo = db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES UPDATE DB] '
        . $e->getMessage()
    );

    servicesUpdateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   AUTH
============================================================ */

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ?? 0
    );

$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ?? 0
    );

$sessionToken =
    trim(
        (string)(
            $_SESSION['lovemi_session_token']
            ?? ''
        )
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    servicesUpdateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [],
        401
    );

}


$sessionTokenHash =
    hash(
        'sha256',
        $sessionToken
    );


try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions p
                ON p.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash =
                    :session_token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND p.slug = 'services.manage'

            LIMIT 1
            "
        );

    $auth->execute(
        [
            ':admin_id' => $adminId,
            ':session_id' => $sessionId,
            ':session_token_hash' => $sessionTokenHash
        ]
    );

    if (!$auth->fetch()) {

        servicesUpdateResponse(
            false,
            'You do not have permission to update services.',
            [],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES UPDATE AUTH] '
        . $e->getMessage()
    );

    servicesUpdateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


/* ============================================================
   INPUT
============================================================ */

$input =
    servicesUpdateInput();


$id =
    (int)(
        $input['id']
        ??
        0
    );


$name =
    trim(
        (string)(
            $input['name']
            ??
            ''
        )
    );


$slug =
    strtolower(
        trim(
            (string)(
                $input['slug']
                ??
                ''
            )
        )
    );


$description =
    trim(
        (string)(
            $input['description']
            ??
            ''
        )
    );


$serviceType =
    strtolower(
        trim(
            (string)(
                $input['service_type']
                ??
                ''
            )
        )
    );


$basePrice =
    (string)(
        $input['base_price_usd']
        ??
        ''
    );


$durationDays =
    (int)(
        $input['duration_days']
        ??
        0
    );


$maxUsage =
    $input['max_usage']
    ??
    null;


$sortOrder =
    (int)(
        $input['sort_order']
        ??
        0
    );


$isPremium =
    filter_var(
        $input['is_premium']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


$isActive =
    filter_var(
        $input['is_active']
        ??
        false,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    $id <= 0
) {

    servicesUpdateResponse(
        false,
        'Invalid service ID.',
        [],
        422
    );

}


if (
    $name === ''
) {

    servicesUpdateResponse(
        false,
        'Service name is required.',
        [],
        422
    );

}


if (
    mb_strlen($name) > 150
) {

    servicesUpdateResponse(
        false,
        'Service name cannot exceed 150 characters.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[a-z0-9]+(?:-[a-z0-9]+)*$/',
        $slug
    )
) {

    servicesUpdateResponse(
        false,
        'Service slug is invalid.',
        [],
        422
    );

}


if (
    mb_strlen($slug) > 150
) {

    servicesUpdateResponse(
        false,
        'Service slug cannot exceed 150 characters.',
        [],
        422
    );

}


if (
    $description !== ''
    &&
    mb_strlen($description) > 5000
) {

    servicesUpdateResponse(
        false,
        'Description is too long.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[a-z0-9_-]{1,50}$/',
        $serviceType
    )
) {

    servicesUpdateResponse(
        false,
        'Service type is invalid.',
        [],
        422
    );

}


if (
    !is_numeric($basePrice)
) {

    servicesUpdateResponse(
        false,
        'Base price must be a valid number.',
        [],
        422
    );

}


$basePriceFloat =
    (float)
    $basePrice;


if (
    $basePriceFloat < 0
) {

    servicesUpdateResponse(
        false,
        'Base price cannot be negative.',
        [],
        422
    );

}


if (
    $durationDays < 1
) {

    servicesUpdateResponse(
        false,
        'Duration must be at least one day.',
        [],
        422
    );

}


if (
    $maxUsage !== null
    &&
    $maxUsage !== ''
) {

    if (
        filter_var(
            $maxUsage,
            FILTER_VALIDATE_INT
        ) === false
        ||
        (int)$maxUsage < 0
    ) {

        servicesUpdateResponse(
            false,
            'Maximum usage is invalid.',
            [],
            422
        );

    }


    $maxUsage =
        (int)$maxUsage;

} else {

    $maxUsage =
        null;

}


/* ============================================================
   START TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    /* ========================================================
       LOAD CURRENT
    ======================================================== */

    $currentStmt =
        $pdo->prepare(
            "
            SELECT *

            FROM services

            WHERE id = :id

            LIMIT 1

            FOR UPDATE
            "
        );


    $currentStmt->execute(
        [
            ':id' => $id
        ]
    );


    $current =
        $currentStmt->fetch();


    if (
        !$current
    ) {

        throw new RuntimeException(
            'SERVICE_NOT_FOUND'
        );

    }


    /* ========================================================
       UNIQUE SLUG
    ======================================================== */

    $slugCheck =
        $pdo->prepare(
            "
            SELECT id

            FROM services

            WHERE
                slug = :slug

                AND id <> :id

            LIMIT 1
            "
        );


    $slugCheck->execute(
        [
            ':slug' => $slug,
            ':id' => $id
        ]
    );


    if (
        $slugCheck->fetch()
    ) {

        throw new RuntimeException(
            'DUPLICATE_SLUG'
        );

    }


    /* ========================================================
       UPDATE
    ======================================================== */

    $update =
        $pdo->prepare(
            "
            UPDATE services

            SET

                name = :name,

                slug = :slug,

                description = :description,

                service_type = :service_type,

                base_price_usd = :base_price_usd,

                duration_days = :duration_days,

                max_usage = :max_usage,

                is_premium = :is_premium,

                is_active = :is_active,

                sort_order = :sort_order

            WHERE id = :id

            LIMIT 1
            "
        );


    $update->execute(
        [
            ':name' =>
                $name,

            ':slug' =>
                $slug,

            ':description' =>
                $description !== ''
                    ?
                    $description
                    :
                    null,

            ':service_type' =>
                $serviceType,

            ':base_price_usd' =>
                number_format(
                    $basePriceFloat,
                    2,
                    '.',
                    ''
                ),

            ':duration_days' =>
                $durationDays,

            ':max_usage' =>
                $maxUsage,

            ':is_premium' =>
                $isPremium,

            ':is_active' =>
                $isActive,

            ':sort_order' =>
                $sortOrder,

            ':id' =>
                $id
        ]
    );


    /* ========================================================
       AUDIT
    ======================================================== */

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
                    'admin_update_service',
                    'service',
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
                    $id,

                ':old_values' =>
                    json_encode(
                        [

                            'name' =>
                                $current['name'],

                            'slug' =>
                                $current['slug'],

                            'description' =>
                                $current['description'],

                            'service_type' =>
                                $current['service_type'],

                            'base_price_usd' =>
                                $current['base_price_usd'],

                            'duration_days' =>
                                $current['duration_days'],

                            'max_usage' =>
                                $current['max_usage'],

                            'is_premium' =>
                                $current['is_premium'],

                            'is_active' =>
                                $current['is_active'],

                            'sort_order' =>
                                $current['sort_order']

                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':new_values' =>
                    json_encode(
                        [

                            'name' =>
                                $name,

                            'slug' =>
                                $slug,

                            'description' =>
                                $description,

                            'service_type' =>
                                $serviceType,

                            'base_price_usd' =>
                                number_format(
                                    $basePriceFloat,
                                    2,
                                    '.',
                                    ''
                                ),

                            'duration_days' =>
                                $durationDays,

                            'max_usage' =>
                                $maxUsage,

                            'is_premium' =>
                                $isPremium,

                            'is_active' =>
                                $isActive,

                            'sort_order' =>
                                $sortOrder

                        ],
                        JSON_UNESCAPED_UNICODE
                    ),

                ':ip' =>
                    $_SERVER['REMOTE_ADDR'] ?? null,

                ':agent' =>
                    $_SERVER['HTTP_USER_AGENT'] ?? null

            ]
        );

    } catch (Throwable $auditError) {

        error_log(
            '[LOVEMI SERVICES UPDATE AUDIT] '
            . $auditError->getMessage()
        );

    }


    $pdo->commit();


    servicesUpdateResponse(
        true,
        'Service updated successfully.',
        [
            'service_id' => $id
        ]
    );

} catch (
    Throwable $e
) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    $message =
        $e->getMessage();


    if (
        $message ===
        'SERVICE_NOT_FOUND'
    ) {

        servicesUpdateResponse(
            false,
            'Service not found.',
            [
                'code' =>
                    'SERVICE_NOT_FOUND'
            ],
            404
        );

    }


    if (
        $message ===
        'DUPLICATE_SLUG'
    ) {

        servicesUpdateResponse(
            false,
            'Another service already uses this slug.',
            [
                'code' =>
                    'DUPLICATE_SLUG'
            ],
            409
        );

    }


    error_log(
        '[LOVEMI SERVICES UPDATE] '
        . $message
    );


    servicesUpdateResponse(
        false,
        'Unable to update the service.',
        [],
        500
    );

}