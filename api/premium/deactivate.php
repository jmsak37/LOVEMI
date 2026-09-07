<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store'
);

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

function premiumDeactivateResponse(
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

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !==
    'POST'
) {

    premiumDeactivateResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' =>
                'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

$userId =
    (int) (
        $_SESSION['lovemi_user_id'] ?? 0
    );

if ($userId <= 0) {

    premiumDeactivateResponse(
        false,
        'Authentication required.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
    );
}

$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );

$subscriptionId =
    (int) (
        is_array($input)
            ? (
                $input[
                    'subscription_id'
                ] ?? 0
            )
            : 0
    );

if ($subscriptionId <= 0) {

    premiumDeactivateResponse(
        false,
        'A valid Premium subscription is required.',
        [
            'code' =>
                'INVALID_SUBSCRIPTION'
        ],
        422
    );
}

try {

    $pdo =
        db();

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

    $query =
        $pdo->prepare(
            "UPDATE subscriptions
             SET
                status = 'cancelled',
                updated_at = CURRENT_TIMESTAMP
             WHERE id = :subscription_id
               AND user_id = :user_id
               AND status = 'active'
               AND end_at > CURRENT_TIMESTAMP
             LIMIT 1"
        );

    $query->execute(
        [
            ':subscription_id' =>
                $subscriptionId,

            ':user_id' =>
                $userId
        ]
    );

    if ($query->rowCount() !== 1) {

        premiumDeactivateResponse(
            false,
            'The Premium membership could not be deactivated. It may already be inactive.',
            [
                'code' =>
                    'DEACTIVATION_FAILED'
            ],
            409
        );
    }

    try {

        $notification =
            $pdo->prepare(
                "INSERT INTO notifications
                (
                    user_id,
                    notification_type_id,
                    title,
                    message,
                    reference_type,
                    reference_id
                )
                SELECT
                    :user_id,
                    id,
                    'Premium Deactivated',
                    'Your LOVEMI Premium membership was deactivated.',
                    'subscription',
                    :subscription_id
                FROM notification_types
                WHERE slug = 'premium_expired'
                LIMIT 1"
            );

        $notification->execute(
            [
                ':user_id' =>
                    $userId,

                ':subscription_id' =>
                    $subscriptionId
            ]
        );

    } catch (Throwable $notificationError) {
        error_log(
            '[LOVEMI PREMIUM NOTIFICATION] ' .
            $notificationError->getMessage()
        );
    }

    premiumDeactivateResponse(
        true,
        'Premium membership deactivated successfully.',
        [
            'subscription_id' =>
                $subscriptionId
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI PREMIUM DEACTIVATE] ' .
        $e->getMessage()
    );

    premiumDeactivateResponse(
        false,
        'Unable to deactivate Premium.',
        [
            'code' =>
                'DEACTIVATION_ERROR'
        ],
        500
    );
}