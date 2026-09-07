<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| LOVEMI NOTIFICATION EMAIL DISPATCHER
|--------------------------------------------------------------------------
| Sends pending notification emails.
|
| IMPORTANT:
| - A notification is claimed before sending.
| - email_sent_at is set only after successful delivery.
| - Claimed notifications cannot be immediately picked by another request.
| - This endpoint accepts both GET and POST because different LOVEMI pages
|   may call it using either method.
|--------------------------------------------------------------------------
*/

require_once __DIR__ . '/../../config/database.php';
require_once __DIR__ . '/../../services/email/main-email-service.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

/*
|--------------------------------------------------------------------------
| START SESSION
|--------------------------------------------------------------------------
*/
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

/*
|--------------------------------------------------------------------------
| JSON RESPONSE
|--------------------------------------------------------------------------
*/
function notificationEmailResponse(
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
                'message' => $message,
            ],
            $data
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}

/*
|--------------------------------------------------------------------------
| REQUEST METHOD
|--------------------------------------------------------------------------
|
| The previous version allowed only GET.
| Some LOVEMI callers can send POST, which caused:
|
| 405 Method Not Allowed
|
| Accept GET and POST here.
|--------------------------------------------------------------------------
*/
$requestMethod = strtoupper(
    trim(
        (string)(
            $_SERVER['REQUEST_METHOD']
            ?? 'GET'
        )
    )
);

if (
    !in_array(
        $requestMethod,
        ['GET', 'POST'],
        true
    )
) {
    notificationEmailResponse(
        false,
        'Only GET and POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED',
        ],
        405
    );
}

/*
|--------------------------------------------------------------------------
| AUTHENTICATED USER
|--------------------------------------------------------------------------
*/
$userId = (int)(
    $_SESSION['lovemi_user_id']
    ?? 0
);

if ($userId <= 0) {
    notificationEmailResponse(
        false,
        'Authentication required.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
        ],
        401
    );
}

/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/
try {

    $pdo = db();

    if (!$pdo instanceof PDO) {
        throw new RuntimeException(
            'Database connection is unavailable.'
        );
    }

    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );

    /*
    |--------------------------------------------------------------------------
    | EMAIL PREFERENCE
    |--------------------------------------------------------------------------
    */
    $preferenceStmt = $pdo->prepare(
        "
        SELECT
            COALESCE(email_notifications, 1)
        FROM notification_preferences
        WHERE user_id = :user_id
        LIMIT 1
        "
    );

    $preferenceStmt->execute(
        [
            ':user_id' => $userId,
        ]
    );

    $emailEnabled = (bool)$preferenceStmt->fetchColumn();

    if (!$emailEnabled) {
        notificationEmailResponse(
            true,
            'Notification email delivery is disabled.',
            [
                'sent' => 0,
                'claimed' => 0,
                'failed' => 0,
                'remaining_ready' => 0,
                'email_enabled' => false,
            ]
        );
    }

    /*
    |--------------------------------------------------------------------------
    | GET USER EMAIL
    |--------------------------------------------------------------------------
    */
    $userStmt = $pdo->prepare(
        "
        SELECT
            id,
            full_names,
            username,
            email
        FROM users
        WHERE id = :user_id
        LIMIT 1
        "
    );

    $userStmt->execute(
        [
            ':user_id' => $userId,
        ]
    );

    $user = $userStmt->fetch(
        PDO::FETCH_ASSOC
    );

    if (!$user) {
        notificationEmailResponse(
            false,
            'User account was not found.',
            [
                'code' => 'USER_NOT_FOUND',
            ],
            404
        );
    }

    $recipientEmail = trim(
        (string)(
            $user['email']
            ?? ''
        )
    );

    if (
        $recipientEmail === ''
        ||
        !filter_var(
            $recipientEmail,
            FILTER_VALIDATE_EMAIL
        )
    ) {
        notificationEmailResponse(
            false,
            'The user does not have a valid email address.',
            [
                'code' => 'INVALID_EMAIL',
            ],
            422
        );
    }

    $recipientName = trim(
        (string)(
            $user['full_names']
            ??
            $user['username']
            ??
            'LOVEMI Member'
        )
    );

    if ($recipientName === '') {
        $recipientName = 'LOVEMI Member';
    }

    /*
    |--------------------------------------------------------------------------
    | DISPATCH SETTINGS
    |--------------------------------------------------------------------------
    |
    | 15 minutes gives the previous worker enough time to finish SMTP.
    | Another request will not immediately pick the same notification.
    |--------------------------------------------------------------------------
    */
    $lockMinutes = 15;
    $maximumPerRequest = 10;

    $sentCount = 0;
    $claimedCount = 0;
    $failedCount = 0;

    $details = [];

    /*
    |--------------------------------------------------------------------------
    | PROCESS NOTIFICATIONS
    |--------------------------------------------------------------------------
    */
    for (
        $loop = 0;
        $loop < $maximumPerRequest;
        $loop++
    ) {

        /*
        |--------------------------------------------------------------------------
        | CLAIM ONE NOTIFICATION
        |--------------------------------------------------------------------------
        */
        $pdo->beginTransaction();

        try {

            $pendingStmt = $pdo->prepare(
                "
                SELECT
                    n.id,
                    n.user_id,
                    n.notification_type_id,
                    n.sender_id,
                    n.title,
                    n.message,
                    n.reference_type,
                    n.reference_id,
                    n.created_at,
                    n.email_sent_at,
                    n.email_attempted_at,
                    n.email_attempts,

                    COALESCE(
                        nt.slug,
                        ''
                    ) AS notification_slug

                FROM notifications n

                LEFT JOIN notification_types nt
                    ON nt.id = n.notification_type_id

                WHERE n.user_id = :user_id

                  AND n.email_sent_at IS NULL

                  AND
                  (
                      n.email_attempted_at IS NULL

                      OR

                      n.email_attempted_at <
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL {$lockMinutes} MINUTE
                      )
                  )

                ORDER BY n.id ASC

                LIMIT 1

                FOR UPDATE
                "
            );

            $pendingStmt->execute(
                [
                    ':user_id' => $userId,
                ]
            );

            $notification = $pendingStmt->fetch(
                PDO::FETCH_ASSOC
            );

            /*
            |--------------------------------------------------------------------------
            | NOTHING READY
            |--------------------------------------------------------------------------
            */
            if (!$notification) {
                $pdo->commit();
                break;
            }

            $notificationId = (int)(
                $notification['id']
                ?? 0
            );

            if ($notificationId <= 0) {
                $pdo->rollBack();
                continue;
            }

            /*
            |--------------------------------------------------------------------------
            | ATOMIC CLAIM
            |--------------------------------------------------------------------------
            |
            | The notification is marked as being processed BEFORE SMTP.
            |
            | This is what prevents repeated sends caused by:
            | - multiple browser tabs
            | - repeated polling
            | - cron + browser running together
            |--------------------------------------------------------------------------
            */
            $claimStmt = $pdo->prepare(
                "
                UPDATE notifications

                SET
                    email_attempted_at =
                        CURRENT_TIMESTAMP,

                    email_attempts =
                        email_attempts + 1,

                    email_last_error =
                        NULL

                WHERE id = :id

                  AND user_id = :user_id

                  AND email_sent_at IS NULL

                  AND
                  (
                      email_attempted_at IS NULL

                      OR

                      email_attempted_at <
                      DATE_SUB(
                          CURRENT_TIMESTAMP,
                          INTERVAL {$lockMinutes} MINUTE
                      )
                  )

                LIMIT 1
                "
            );

            $claimStmt->execute(
                [
                    ':id' => $notificationId,
                    ':user_id' => $userId,
                ]
            );

            /*
            |--------------------------------------------------------------------------
            | Another worker claimed it first.
            |--------------------------------------------------------------------------
            */
            if ($claimStmt->rowCount() !== 1) {
                $pdo->rollBack();
                continue;
            }

            $pdo->commit();

            $claimedCount++;

        } catch (Throwable $claimError) {

            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }

            throw $claimError;
        }

        /*
        |--------------------------------------------------------------------------
        | SEND EMAIL
        |--------------------------------------------------------------------------
        */
        $mailSent = false;
        $mailError = '';

        try {

            $mailSent = sendLovemiNotificationEmail(
                $recipientEmail,
                $recipientName,
                [
                    'id' =>
                        $notificationId,

                    'title' =>
                        (string)(
                            $notification['title']
                            ?? 'LOVEMI Notification'
                        ),

                    'message' =>
                        (string)(
                            $notification['message']
                            ?? ''
                        ),

                    'reference_type' =>
                        (string)(
                            $notification['reference_type']
                            ?? ''
                        ),

                    'reference_id' =>
                        $notification['reference_id']
                        ?? null,

                    'notification_slug' =>
                        (string)(
                            $notification['notification_slug']
                            ?? ''
                        ),

                    'created_at' =>
                        (string)(
                            $notification['created_at']
                            ?? ''
                        ),
                ]
            );

        } catch (Throwable $mailException) {

            $mailSent = false;

            $mailError = $mailException->getMessage();

            error_log(
                '[LOVEMI NOTIFICATION EMAIL] ' .
                'Notification #' .
                $notificationId .
                ': ' .
                $mailError
            );
        }

        /*
        |--------------------------------------------------------------------------
        | SUCCESS
        |--------------------------------------------------------------------------
        |
        | IMPORTANT:
        | email_sent_at gets a value here.
        |
        | Future requests will skip this notification permanently.
        |--------------------------------------------------------------------------
        */
        if ($mailSent === true) {

            $sentStmt = $pdo->prepare(
                "
                UPDATE notifications

                SET
                    email_sent_at =
                        CURRENT_TIMESTAMP,

                    email_last_error =
                        NULL

                WHERE id = :id

                  AND user_id = :user_id

                  AND email_sent_at IS NULL

                LIMIT 1
                "
            );

            $sentStmt->execute(
                [
                    ':id' => $notificationId,
                    ':user_id' => $userId,
                ]
            );

            if ($sentStmt->rowCount() === 1) {

                $sentCount++;

                $details[] = [
                    'notification_id' =>
                        $notificationId,

                    'status' =>
                        'sent',
                ];
            }

            continue;
        }

        /*
        |--------------------------------------------------------------------------
        | FAILURE
        |--------------------------------------------------------------------------
        |
        | Do not set email_sent_at.
        |
        | The notification can be retried after the 15-minute lock expires.
        |--------------------------------------------------------------------------
        */
        if (trim($mailError) === '') {
            $mailError =
                'The email service returned false.';
        }

        $mailError = mb_substr(
            trim($mailError),
            0,
            1000
        );

        $failedStmt = $pdo->prepare(
            "
            UPDATE notifications

            SET
                email_last_error =
                    :error_message

            WHERE id = :id

              AND user_id = :user_id

              AND email_sent_at IS NULL

            LIMIT 1
            "
        );

        $failedStmt->execute(
            [
                ':error_message' => $mailError,
                ':id' => $notificationId,
                ':user_id' => $userId,
            ]
        );

        $failedCount++;

        $details[] = [
            'notification_id' =>
                $notificationId,

            'status' =>
                'failed',

            'message' =>
                'Email delivery failed. It will be retried later.',
        ];
    }

    /*
    |--------------------------------------------------------------------------
    | COUNT REMAINING READY NOTIFICATIONS
    |--------------------------------------------------------------------------
    */
    $remainingStmt = $pdo->prepare(
        "
        SELECT COUNT(*)

        FROM notifications

        WHERE user_id = :user_id

          AND email_sent_at IS NULL

          AND
          (
              email_attempted_at IS NULL

              OR

              email_attempted_at <
              DATE_SUB(
                  CURRENT_TIMESTAMP,
                  INTERVAL {$lockMinutes} MINUTE
              )
          )
        "
    );

    $remainingStmt->execute(
        [
            ':user_id' => $userId,
        ]
    );

    $remainingReady = (int)(
        $remainingStmt->fetchColumn()
        ?? 0
    );

    /*
    |--------------------------------------------------------------------------
    | FINAL RESPONSE
    |--------------------------------------------------------------------------
    */
    notificationEmailResponse(
        true,
        'Notification email dispatcher completed.',
        [
            'sent' =>
                $sentCount,

            'claimed' =>
                $claimedCount,

            'failed' =>
                $failedCount,

            'remaining_ready' =>
                $remainingReady,

            'email_enabled' =>
                true,

            'details' =>
                $details,
        ]
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI NOTIFICATION EMAIL DISPATCHER] ' .
        $e->getMessage()
    );

    notificationEmailResponse(
        false,
        'Unable to process notification emails.',
        [
            'code' =>
                'NOTIFICATION_EMAIL_DISPATCH_FAILED',
        ],
        500
    );
}