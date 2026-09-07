<?php
declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI - NOTIFICATION EMAIL DISPATCHER
 * ============================================================
 *
 * Designed to be called by:
 *
 * - Windows Task Scheduler
 * - Linux cron
 * - manual PHP CLI execution
 *
 * It sends notification emails for users even when they are
 * not currently viewing notifications.html.
 *
 * ============================================================
 */

if (
    PHP_SAPI !== 'cli'
) {

    http_response_code(
        403
    );

    exit(
        "This script is intended to run from the command line.\n"
    );
}


require_once
    __DIR__
    . '/../config/database.php';


require_once
    __DIR__
    . '/../services/email/main-email-service.php';


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

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CRON NOTIFICATION EMAIL DB] '
        . $e->getMessage()
    );

    exit(
        "Database connection failed.\n"
    );
}


/* ============================================================
   USERS WITH PENDING EMAILS
============================================================ */

try {

    $userStmt =
        $pdo->query(
            "
            SELECT DISTINCT
                n.user_id

            FROM notifications n

            INNER JOIN users u
                ON u.id = n.user_id

            LEFT JOIN notification_preferences np
                ON np.user_id = n.user_id

            WHERE n.email_sent_at IS NULL

              AND (
                    n.email_attempted_at IS NULL
                    OR
                    n.email_attempted_at
                    <
                    DATE_SUB(
                        CURRENT_TIMESTAMP,
                        INTERVAL 2 MINUTE
                    )
                  )

              AND (
                    np.email_notifications IS NULL
                    OR np.email_notifications = 1
                  )

              AND u.email IS NOT NULL

              AND u.email <> ''

            ORDER BY n.user_id ASC

            LIMIT 100
            "
        );


    $userIds =
        $userStmt->fetchAll(
            PDO::FETCH_COLUMN
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI CRON NOTIFICATION EMAIL QUERY] '
        . $e->getMessage()
    );

    exit(
        "Unable to read pending users.\n"
    );
}


/* ============================================================
   DISPATCH PER USER
============================================================ */

$totalSent =
    0;


$totalFailed =
    0;


foreach (
    $userIds as $userId
) {

    $userId =
        (int)
        $userId;


    if (
        $userId <= 0
    ) {
        continue;
    }


    try {

        /*
         * User.
         */
        $userStmt =
            $pdo->prepare(
                "
                SELECT
                    id,
                    full_names,
                    username,
                    email

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


        if (
            !$user
        ) {
            continue;
        }


        /*
         * Pending notifications.
         */
        $stmt =
            $pdo->prepare(
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

                    nt.name AS notification_type_name,
                    nt.slug AS notification_type_slug

                FROM notifications n

                LEFT JOIN notification_types nt
                    ON nt.id =
                       n.notification_type_id

                WHERE n.user_id = :user_id

                  AND n.email_sent_at IS NULL

                  AND (
                        n.email_attempted_at IS NULL
                        OR
                        n.email_attempted_at
                        <
                        DATE_SUB(
                            CURRENT_TIMESTAMP,
                            INTERVAL 2 MINUTE
                        )
                      )

                ORDER BY
                    n.created_at ASC,
                    n.id ASC

                LIMIT 20
                "
            );


        $stmt->execute(
            [
                ':user_id' =>
                    $userId
            ]
        );


        $notifications =
            $stmt->fetchAll();


        foreach (
            $notifications as $notification
        ) {

            $notificationId =
                (int)
                $notification['id'];


            /*
             * Claim.
             */
            $claim =
                $pdo->prepare(
                    "
                    UPDATE notifications

                    SET
                        email_attempted_at =
                            CURRENT_TIMESTAMP,

                        email_attempts =
                            COALESCE(
                                email_attempts,
                                0
                            ) + 1

                    WHERE id = :id

                      AND user_id = :user_id

                      AND email_sent_at IS NULL

                      AND (
                            email_attempted_at IS NULL
                            OR
                            email_attempted_at
                            <
                            DATE_SUB(
                                CURRENT_TIMESTAMP,
                                INTERVAL 2 MINUTE
                            )
                          )

                    LIMIT 1
                    "
                );


            $claim->execute(
                [
                    ':id' =>
                        $notificationId,

                    ':user_id' =>
                        $userId
                ]
            );


            if (
                $claim->rowCount() !== 1
            ) {
                continue;
            }


            try {

                $success =
                    sendLovemiNotificationEmail(
                        (string)
                            $user['email'],

                        (string) (
                            $user['full_names']
                            ?: $user['username']
                            ?: 'LOVEMI Member'
                        ),

                        $notification
                    );


                if (
                    $success
                ) {

                    $sent =
                        $pdo->prepare(
                            "
                            UPDATE notifications

                            SET
                                email_sent_at =
                                    CURRENT_TIMESTAMP,

                                email_last_error =
                                    NULL

                            WHERE id = :id

                              AND user_id = :user_id

                            LIMIT 1
                            "
                        );


                    $sent->execute(
                        [
                            ':id' =>
                                $notificationId,

                            ':user_id' =>
                                $userId
                        ]
                    );


                    $totalSent++;

                } else {

                    $totalFailed++;

                }

            } catch (
                Throwable $e
            ) {

                $totalFailed++;


                try {

                    $errorStmt =
                        $pdo->prepare(
                            "
                            UPDATE notifications

                            SET
                                email_last_error = :error

                            WHERE id = :id

                              AND user_id = :user_id

                            LIMIT 1
                            "
                        );


                    $errorStmt->execute(
                        [
                            ':error' =>
                                mb_substr(
                                    $e->getMessage(),
                                    0,
                                    1000
                                ),

                            ':id' =>
                                $notificationId,

                            ':user_id' =>
                                $userId
                        ]
                    );

                } catch (
                    Throwable $saveError
                ) {

                    error_log(
                        '[LOVEMI CRON EMAIL ERROR SAVE] '
                        . $saveError->getMessage()
                    );

                }


                error_log(
                    '[LOVEMI CRON NOTIFICATION EMAIL] '
                    . $e->getMessage()
                );

            }

        }

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI CRON USER NOTIFICATION EMAIL] '
            . $e->getMessage()
        );

        continue;
    }

}


/* ============================================================
   CLI RESULT
============================================================ */

echo
    "LOVEMI notification email dispatch completed.\n";

echo
    "Sent: "
    . $totalSent
    . "\n";

echo
    "Failed: "
    . $totalFailed
    . "\n";