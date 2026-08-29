<?php
/**
 * ============================================================
 * LOVEMI - CHECK WHETHER AN ADMINISTRATOR EXISTS
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\api\auth\check-admin-exists.php
 *
 * Purpose:
 * - Determine whether at least one active administrator exists.
 * - Registration page uses this to show/hide the first-admin
 *   option.
 *
 * SECURITY:
 * This endpoint is only for UI information.
 *
 * registration.php MUST still perform its own server-side
 * administrator check before assigning the admin role.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE
   ============================================================ */

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   HEADERS
   ============================================================ */

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-cache, no-store, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   METHOD
   ============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !== 'GET'
) {

    http_response_code(405);

    echo json_encode(
        [
            'success' => false,

            'message' =>
                'Only GET requests are allowed.',

            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

    exit;
}


/* ============================================================
   DATABASE
   ============================================================ */

try {

    $pdo = db();


    /* ========================================================
       FIND ADMIN ROLE
       ======================================================== */

    $roleStmt =
        $pdo->prepare(
            "
            SELECT id

            FROM roles

            WHERE slug = 'admin'

            LIMIT 1
            "
        );


    $roleStmt->execute();


    $adminRole =
        $roleStmt->fetch();


    if (!$adminRole) {

        http_response_code(500);


        echo json_encode(
            [
                'success' => false,

                'message' =>
                    'Administrator role is not configured.',

                'code' =>
                    'ADMIN_ROLE_NOT_FOUND',

                'admin_exists' =>
                    false,

                'has_admin' =>
                    false
            ],
            JSON_UNESCAPED_SLASHES
            | JSON_UNESCAPED_UNICODE
        );


        exit;

    }


    $adminRoleId =
        (int) $adminRole['id'];


    /* ========================================================
       CHECK ADMIN
       ======================================================== */

    $adminStmt =
        $pdo->prepare(
            "
            SELECT COUNT(*) AS admin_count

            FROM users

            WHERE role_id = :role_id

              AND is_deleted = FALSE

              AND is_suspended = FALSE

              AND is_active = TRUE
            "
        );


    $adminStmt->execute(
        [
            ':role_id' =>
                $adminRoleId
        ]
    );


    $result =
        $adminStmt->fetch();


    $adminCount =
        (int)
        ($result['admin_count'] ?? 0);


    $adminExists =
        $adminCount > 0;


    /* ========================================================
       RESPONSE
       ======================================================== */

    echo json_encode(
        [
            'success' =>
                true,

            'message' =>
                'Administrator status checked successfully.',

            'admin_exists' =>
                $adminExists,

            'has_admin' =>
                $adminExists,

            'admin_count' =>
                $adminCount,

            /*
             * This is useful for registration.html.
             */
            'first_admin_available' =>
                !$adminExists
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );


} catch (Throwable $e) {

    error_log(
        '[LOVEMI ADMIN CHECK ERROR] '
        . $e->getMessage()
    );


    /*
     * Fail closed.
     *
     * If the browser cannot confirm whether an admin exists,
     * registration.html MUST NOT display the admin option.
     */

    http_response_code(500);


    echo json_encode(
        [
            'success' =>
                false,

            'message' =>
                'Unable to check administrator status.',

            'admin_exists' =>
                true,

            'has_admin' =>
                true,

            'first_admin_available' =>
                false,

            'code' =>
                'ADMIN_CHECK_ERROR'
        ],
        JSON_UNESCAPED_SLASHES
        | JSON_UNESCAPED_UNICODE
    );

}


exit;