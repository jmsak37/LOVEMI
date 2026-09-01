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


function servicesCreateResponse(
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


function servicesInput(): array
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

    if (
        is_array($json)
    ) {

        return $json;

    }

    return $_POST;

}


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    servicesCreateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
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
   DATABASE
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
        '[LOVEMI SERVICES CREATE DB] '
        . $e->getMessage()
    );

    servicesCreateResponse(
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

    servicesCreateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [
            'code' => 'NOT_AUTHENTICATED'
        ],
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

        servicesCreateResponse(
            false,
            'You do not have permission to create services.',
            [
                'code' => 'PERMISSION_DENIED'
            ],
            403
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES CREATE AUTH] '
        . $e->getMessage()
    );

    servicesCreateResponse(
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
    servicesInput();


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
                'premium'
            )
        )
    );


$basePrice =
    (string)(
        $input['base_price_usd']
        ??
        '0.00'
    );


$durationDays =
    (int)(
        $input['duration_days']
        ??
        30
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
        true,
        FILTER_VALIDATE_BOOLEAN
    )
    ? 1
    : 0;


/* ============================================================
   VALIDATION
============================================================ */

if (
    $name === ''
) {

    servicesCreateResponse(
        false,
        'Service name is required.',
        [],
        422
    );

}


if (
    mb_strlen($name) > 150
) {

    servicesCreateResponse(
        false,
        'Service name cannot exceed 150 characters.',
        [],
        422
    );

}


if (
    $slug === ''
) {

    servicesCreateResponse(
        false,
        'Service slug is required.',
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

    servicesCreateResponse(
        false,
        'Slug may contain lowercase letters, numbers and hyphens only.',
        [],
        422
    );

}


if (
    mb_strlen($slug) > 150
) {

    servicesCreateResponse(
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

    servicesCreateResponse(
        false,
        'Description is too long.',
        [],
        422
    );

}


if (
    $serviceType === ''
    ||
    mb_strlen($serviceType) > 50
) {

    servicesCreateResponse(
        false,
        'Service type is invalid.',
        [],
        422
    );

}


if (
    !preg_match(
        '/^[a-z0-9_-]+$/',
        $serviceType
    )
) {

    servicesCreateResponse(
        false,
        'Service type may contain letters, numbers, hyphens and underscores only.',
        [],
        422
    );

}


if (
    !is_numeric($basePrice)
) {

    servicesCreateResponse(
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

    servicesCreateResponse(
        false,
        'Base price cannot be negative.',
        [],
        422
    );

}


if (
    $basePriceFloat > 9999999999
) {

    servicesCreateResponse(
        false,
        'Base price is too large.',
        [],
        422
    );

}


if (
    $durationDays < 1
) {

    servicesCreateResponse(
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

        servicesCreateResponse(
            false,
            'Maximum usage must be a non-negative whole number or empty for unlimited usage.',
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
   DUPLICATE SLUG
============================================================ */

try {

    $duplicate =
        $pdo->prepare(
            "
            SELECT id

            FROM services

            WHERE slug = :slug

            LIMIT 1
            "
        );

    $duplicate->execute(
        [
            ':slug' => $slug
        ]
    );

    if (
        $duplicate->fetch()
    ) {

        servicesCreateResponse(
            false,
            'A service with this slug already exists.',
            [
                'code' => 'DUPLICATE_SLUG'
            ],
            409
        );

    }

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES CREATE DUP CHECK] '
        . $e->getMessage()
    );

    servicesCreateResponse(
        false,
        'Unable to validate the service slug.',
        [],
        500
    );

}


/* ============================================================
   CREATE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO services
            (
                name,
                slug,
                description,
                service_type,
                base_price_usd,
                duration_days,
                max_usage,
                is_premium,
                is_active,
                sort_order
            )
            VALUES
            (
                :name,
                :slug,
                :description,
                :service_type,
                :base_price_usd,
                :duration_days,
                :max_usage,
                :is_premium,
                :is_active,
                :sort_order
            )
            "
        );

    $stmt->execute(
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
                $sortOrder
        ]
    );


    $serviceId =
        (int)
        $pdo->lastInsertId();


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
                    'admin_create_service',
                    'service',
                    :entity_id,
                    NULL,
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
                    $serviceId,

                ':new_values' =>
                    json_encode(
                        [
                            'name' => $name,
                            'slug' => $slug,
                            'service_type' => $serviceType,
                            'base_price_usd' => $basePriceFloat,
                            'duration_days' => $durationDays,
                            'max_usage' => $maxUsage,
                            'is_premium' => $isPremium,
                            'is_active' => $isActive,
                            'sort_order' => $sortOrder
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
            '[LOVEMI SERVICES CREATE AUDIT] '
            . $auditError->getMessage()
        );

    }


    servicesCreateResponse(
        true,
        'Service created successfully.',
        [
            'service_id' =>
                $serviceId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SERVICES CREATE] '
        . $e->getMessage()
    );


    /*
     * Handle database unique-key race conditions.
     */

    if (
        stripos(
            $e->getMessage(),
            'duplicate'
        ) !== false
    ) {

        servicesCreateResponse(
            false,
            'A service with this slug already exists.',
            [
                'code' => 'DUPLICATE_SLUG'
            ],
            409
        );

    }


    servicesCreateResponse(
        false,
        'Unable to create the service.',
        [],
        500
    );

}