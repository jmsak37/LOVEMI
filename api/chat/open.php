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

function openChatResponse(
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
        ? (int)$_SESSION['lovemi_user_id']
        : 0;

if ($userId <= 0) {

    openChatResponse(
        false,
        'Please log in first.',
        [],
        401
    );
}

$chatCode =
    trim(
        (string)(
            $_GET['chat']
            ??
            ''
        )
    );

if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $chatCode
    )
) {

    openChatResponse(
        false,
        'Invalid or missing chat code.',
        [
            'code' => 'INVALID_CHAT_CODE'
        ],
        422
    );
}

try {

    $pdo =
        db();

} catch (Throwable $e) {

    openChatResponse(
        false,
        'Database connection failed.',
        [],
        500
    );
}

$sql = "
    SELECT

        c.id AS conversation_id,

        c.connection_id,

        c.status,

        c.user_one_id,

        c.user_two_id,

        CASE
            WHEN c.user_one_id = :viewer_one
                THEN c.user_two_id
            ELSE c.user_one_id
        END AS other_user_id,

        ou.username,

        ou.full_names,

        ou.gender,

        ou.date_of_birth,

        op.display_name,

        op.bio,

        op.city,

        op.allow_messages,

        (
            SELECT ph.file_path
            FROM photos ph
            WHERE ph.user_id = ou.id
              AND ph.photo_type = 'profile'
              AND ph.approval_status = 'approved'
              AND ph.is_primary = 1
            ORDER BY ph.uploaded_at DESC, ph.id DESC
            LIMIT 1
        ) AS profile_photo,

        CASE
            WHEN EXISTS
            (
                SELECT 1
                FROM user_presence up0
                WHERE up0.user_id = ou.id
                  AND up0.is_online = 1
            )
            THEN 1

            WHEN EXISTS
            (
                SELECT 1
                FROM user_sessions us
                WHERE us.user_id = ou.id
                  AND us.revoked_at IS NULL
                  AND us.expires_at > CURRENT_TIMESTAMP
                  AND us.last_activity_at >=
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL 10 MINUTE
                      )
            )
            THEN 1

            ELSE 0
        END AS is_online,

        CASE
            WHEN EXISTS
            (
                SELECT 1
                FROM subscriptions s
                INNER JOIN services sv
                    ON sv.id = s.service_id
                WHERE s.user_id = :my_premium
                  AND sv.slug = 'lovemi-premium'
                  AND s.status = 'active'
                  AND s.end_at > CURRENT_TIMESTAMP
            )
            THEN 1
            ELSE 0
        END AS my_premium_active,

        CASE
            WHEN EXISTS
            (
                SELECT 1
                FROM subscriptions s2
                INNER JOIN services sv2
                    ON sv2.id = s2.service_id
                WHERE s2.user_id = ou.id
                  AND sv2.slug = 'lovemi-premium'
                  AND s2.status = 'active'
                  AND s2.end_at > CURRENT_TIMESTAMP
            )
            THEN 1
            ELSE 0
        END AS other_premium_active

    FROM conversation_access_codes cac

    INNER JOIN conversations c
        ON c.id = cac.conversation_id

    INNER JOIN users ou
        ON ou.id =
            CASE
                WHEN c.user_one_id = :viewer_two
                    THEN c.user_two_id
                ELSE c.user_one_id
            END

    LEFT JOIN profiles op
        ON op.user_id = ou.id

    WHERE cac.access_code = :access_code

      AND
      (
          c.user_one_id = :viewer_three
          OR
          c.user_two_id = :viewer_four
      )

      AND c.status = 'active'

      AND ou.is_active = 1
      AND ou.is_suspended = 0
      AND ou.is_deleted = 0

    LIMIT 1
";

try {

    $stmt =
        $pdo->prepare(
            $sql
        );

    $stmt->execute(
        [

            ':viewer_one' =>
                $userId,

            ':viewer_two' =>
                $userId,

            ':viewer_three' =>
                $userId,

            ':viewer_four' =>
                $userId,

            ':my_premium' =>
                $userId,

            ':access_code' =>
                $chatCode

        ]
    );

    $row =
        $stmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI CHAT OPEN QUERY] ' .
        $e->getMessage()
    );

    openChatResponse(
        false,
        'Unable to open this conversation.',
        [],
        500
    );
}

if (!$row) {

    openChatResponse(
        false,
        'Conversation not found or access denied.',
        [
            'code' => 'CHAT_ACCESS_DENIED'
        ],
        403
    );
}

try {

    $touch =
        $pdo->prepare(
            "
            UPDATE conversation_access_codes

            SET last_used_at = CURRENT_TIMESTAMP

            WHERE access_code = :access_code

            LIMIT 1
            "
        );

    $touch->execute(
        [
            ':access_code' =>
                $chatCode
        ]
    );

} catch (Throwable $e) {
}

openChatResponse(
    true,
    'Conversation opened.',
    [

        'conversation' => [

            'id' =>
                (int)$row['conversation_id'],

            'connection_id' =>
                $row['connection_id'] !== null
                    ?
                    (int)$row['connection_id']
                    :
                    null,

            'status' =>
                $row['status']

        ],

        'other_user' => [

            'id' =>
                (int)$row['other_user_id'],

            'username' =>
                (string)$row['username'],

            'full_names' =>
                (string)$row['full_names'],

            'display_name' =>
                $row['display_name']
                ??
                $row['full_names'],

            'gender' =>
                (string)$row['gender'],

            'bio' =>
                $row['bio'],

            'city' =>
                $row['city'],

            'profile_photo' =>
                $row['profile_photo'],

            'online' =>
                (bool)$row['is_online']

        ],

        'my_premium_active' =>
            (bool)$row['my_premium_active'],

        'other_premium_active' =>
            (bool)$row['other_premium_active']

    ]
);