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


function exchangeListResponse(
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

    $pdo =
        db();

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
        '[LOVEMI EXCHANGE LIST DB] '
        . $e->getMessage()
    );

    exchangeListResponse(
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

    exchangeListResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [
            'code' => 'NOT_AUTHENTICATED'
        ],
        401
    );

}


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
                r.slug AS role_slug

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
                    :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND p.slug =
                    'exchange_rates.manage'

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


    $admin =
        $auth->fetch();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE LIST AUTH] '
        . $e->getMessage()
    );

    exchangeListResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    exchangeListResponse(
        false,
        'You do not have permission to manage exchange rates.',
        [
            'code' => 'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   ACTIVITY
============================================================ */

try {

    $activity =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE

                id = :session_id

                AND user_id = :user_id

            LIMIT 1
            "
        );


    $activity->execute(
        [

            ':session_id' =>
                $sessionId,

            ':user_id' =>
                $adminId

        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE LIST ACTIVITY] '
        . $e->getMessage()
    );

}


/* ============================================================
   RATES
============================================================ */

try {

    /*
     * Return all records.
     *
     * Frontend chooses which rows to show/filter.
     * This preserves the historical rate records.
     */

    $stmt =
        $pdo->query(
            "
            SELECT

                er.id,

                er.base_currency_id,
                er.target_currency_id,

                er.rate,

                er.source,

                er.effective_at,

                er.is_active,

                er.created_at,

                bc.code AS base_code,
                bc.name AS base_name,
                bc.symbol AS base_symbol,
                bc.decimal_places AS base_decimal_places,

                tc.code AS target_code,
                tc.name AS target_name,
                tc.symbol AS target_symbol,
                tc.decimal_places AS target_decimal_places

            FROM exchange_rates er

            INNER JOIN currencies bc
                ON bc.id =
                    er.base_currency_id

            INNER JOIN currencies tc
                ON tc.id =
                    er.target_currency_id

            ORDER BY

                er.effective_at DESC,
                er.id DESC
            "
        );


    $rates =
        $stmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE LIST QUERY] '
        . $e->getMessage()
    );

    exchangeListResponse(
        false,
        'Unable to load exchange rates.',
        [],
        500
    );

}


/* ============================================================
   CURRENCIES
============================================================ */

try {

    $currencyStmt =
        $pdo->query(
            "
            SELECT

                id,
                code,
                name,
                symbol,
                decimal_places,
                is_base,
                is_active

            FROM currencies

            WHERE
                is_active = 1

            ORDER BY

                is_base DESC,
                code ASC
            "
        );


    $currencies =
        $currencyStmt->fetchAll();

} catch (Throwable $e) {

    error_log(
        '[LOVEMI EXCHANGE CURRENCIES] '
        . $e->getMessage()
    );

    exchangeListResponse(
        false,
        'Unable to load currencies.',
        [],
        500
    );

}


/* ============================================================
   ADMIN AVATAR
============================================================ */

$avatar =
    null;


try {

    $avatarStmt =
        $pdo->prepare(
            "
            SELECT file_path

            FROM photos

            WHERE

                user_id = :user_id

                AND photo_type = 'profile'

                AND is_primary = 1

                AND approval_status = 'approved'

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $avatarStmt->execute(
        [
            ':user_id' =>
                $adminId
        ]
    );


    $avatar =
        $avatarStmt->fetchColumn()
        ?:
        null;

} catch (Throwable $e) {

}


/* ============================================================
   RESPONSE
============================================================ */

exchangeListResponse(
    true,
    'Exchange rates loaded successfully.',
    [

        'admin' => [

            'id' =>
                (int)$admin['id'],

            'username' =>
                $admin['username'],

            'full_names' =>
                $admin['full_names'],

            'email' =>
                $admin['email'],

            'role_id' =>
                (int)$admin['role_id'],

            'role_name' =>
                $admin['role_name'],

            'role_slug' =>
                $admin['role_slug'],

            'avatar_url' =>
                $avatar

        ],

        'currencies' =>
            $currencies,

        'rates' =>
            $rates

    ]
);