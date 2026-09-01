<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function whatsappJson(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

$userId =
    isset($_SESSION['lovemi_user_id'])
        ? (int) $_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    whatsappJson(
        false,
        'Please log in first.',
        [],
        401
    );

}

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    whatsappJson(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   CREATE TABLE
============================================================ */

try {

    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS user_whatsapp_numbers
        (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

            user_id BIGINT UNSIGNED NOT NULL,

            whatsapp_number VARCHAR(30) NOT NULL,

            is_active TINYINT(1) NOT NULL DEFAULT 1,

            created_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            updated_at DATETIME NOT NULL
                DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY(id),

            UNIQUE KEY uq_user_whatsapp
                (user_id),

            KEY idx_whatsapp_number
                (whatsapp_number)

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI WHATSAPP TABLE] '
        .
        $e->getMessage()
    );

    whatsappJson(
        false,
        'Unable to prepare WhatsApp storage.',
        [],
        500
    );

}


/* ============================================================
   GET
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    ===
    'GET'
) {

    $action =
        strtolower(
            trim(
                (string)(
                    $_GET['action']
                    ??
                    'mine'
                )
            )
        );


    if (
        $action ===
        'mine'
    ) {

        try {

            $stmt =
                $pdo->prepare(
                    "
                    SELECT

                        whatsapp_number,

                        is_active,

                        updated_at

                    FROM user_whatsapp_numbers

                    WHERE user_id =
                        :user_id

                    LIMIT 1
                    "
                );

            $stmt->execute(
                [
                    ':user_id' =>
                        $userId
                ]
            );

            $row =
                $stmt->fetch(
                    PDO::FETCH_ASSOC
                );

        } catch (
            Throwable $e
        ) {

            whatsappJson(
                false,
                'Unable to load your WhatsApp number.',
                [],
                500
            );

        }


        whatsappJson(
            true,
            'WhatsApp information loaded.',
            [

                'whatsapp' => [

                    'number' =>
                        $row
                            ?
                            (string)
                            $row['whatsapp_number']
                            :
                            null,

                    'active' =>
                        $row
                            ?
                            (bool)
                            $row['is_active']
                            :
                            false,

                    'updated_at' =>
                        $row
                            ?
                            $row['updated_at']
                            :
                            null

                ]

            ]
        );

    }


    if (
        $action ===
        'other'
    ) {

        $otherUserId =
            isset(
                $_GET['user_id']
            )
                ?
                (int)
                $_GET['user_id']
                :
                0;


        if (
            $otherUserId <= 0
        ) {

            whatsappJson(
                false,
                'Invalid member.',
                [],
                422
            );

        }


        /*
         * WhatsApp is never exposed unless an accepted
         * connection exists.
         */

        try {

            $connection =
                $pdo->prepare(
                    "
                    SELECT id

                    FROM connections

                    WHERE

                    (
                        user_id = :current_one

                        AND

                        connected_user_id =
                            :other_one
                    )

                    OR

                    (
                        user_id = :other_two

                        AND

                        connected_user_id =
                            :current_two
                    )

                    AND status IN
                    (
                        'accepted',
                        'connected'
                    )

                    LIMIT 1
                    "
                );

            $connection->execute(
                [
                    ':current_one' =>
                        $userId,

                    ':other_one' =>
                        $otherUserId,

                    ':other_two' =>
                        $otherUserId,

                    ':current_two' =>
                        $userId
                ]
            );

            $connected =
                $connection->fetchColumn();

        } catch (
            Throwable $e
        ) {

            whatsappJson(
                false,
                'Unable to verify the connection.',
                [],
                500
            );

        }


        if (
            !$connected
        ) {

            whatsappJson(
                false,
                'WhatsApp is available only after the connection is accepted.',
                [
                    'code' =>
                        'CONNECTION_REQUIRED'
                ],
                403
            );

        }


        try {

            $stmt =
                $pdo->prepare(
                    "
                    SELECT

                        whatsapp_number

                    FROM user_whatsapp_numbers

                    WHERE user_id =
                        :user_id

                      AND is_active = 1

                    LIMIT 1
                    "
                );

            $stmt->execute(
                [
                    ':user_id' =>
                        $otherUserId
                ]
            );

            $number =
                $stmt->fetchColumn();

        } catch (
            Throwable $e
        ) {

            whatsappJson(
                false,
                'Unable to load the WhatsApp number.',
                [],
                500
            );

        }


        whatsappJson(
            true,
            'WhatsApp information loaded.',
            [

                'whatsapp' => [

                    'available' =>
                        (bool)
                        $number,

                    'number' =>
                        $number
                            ?
                            (string)
                            $number
                            :
                            null

                ]

            ]
        );

    }


    whatsappJson(
        false,
        'Invalid WhatsApp action.',
        [],
        422
    );

}


/* ============================================================
   POST - SAVE
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    whatsappJson(
        false,
        'Only GET and POST requests are allowed.',
        [],
        405
    );

}

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
        [];

}

$number =
    trim(
        (string)(
            $input['whatsapp_number']
            ??
            ''
        )
    );


/*
 * Normalize spaces, brackets and dashes.
 */

$number =
    preg_replace(
        '/[\s\-\(\)]+/',
        '',
        $number
    );


if (
    !is_string(
        $number
    )
    ||
    !preg_match(
        '/^\+?[1-9]\d{7,14}$/',
        $number
    )
) {

    whatsappJson(
        false,
        'Enter a valid WhatsApp number in international format.',
        [
            'code' =>
                'INVALID_WHATSAPP_NUMBER'
        ],
        422
    );

}


/*
 * Store consistently in +countrycode format.
 */

if (
    !str_starts_with(
        $number,
        '+'
    )
) {

    $number =
        '+'
        .
        $number;

}


/* ============================================================
   SAVE
============================================================ */

try {

    $stmt =
        $pdo->prepare(
            "
            INSERT INTO user_whatsapp_numbers
            (
                user_id,
                whatsapp_number,
                is_active
            )

            VALUES
            (
                :user_id,
                :whatsapp_number,
                1
            )

            ON DUPLICATE KEY UPDATE

                whatsapp_number =
                    VALUES(whatsapp_number),

                is_active = 1,

                updated_at =
                    CURRENT_TIMESTAMP
            "
        );

    $stmt->execute(
        [
            ':user_id' =>
                $userId,

            ':whatsapp_number' =>
                $number
        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI WHATSAPP SAVE] '
        .
        $e->getMessage()
    );

    whatsappJson(
        false,
        'Unable to save your WhatsApp number.',
        [],
        500
    );

}


whatsappJson(
    true,
    'WhatsApp number saved successfully.',
    [

        'whatsapp' => [

            'number' =>
                $number,

            'active' =>
                true

        ]

    ]
);