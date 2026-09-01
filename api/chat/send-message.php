<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

ini_set('display_errors', '0');
ini_set('display_startup_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


/* ============================================================
   RESPONSE
============================================================ */

function sendJson(
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


/* ============================================================
   METHOD
============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '')
    !==
    'POST'
) {

    sendJson(
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
   AUTH
============================================================ */

$currentUserId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if (
    $currentUserId <= 0
) {

    sendJson(
        false,
        'Please log in first.',
        [
            'code' =>
                'AUTHENTICATION_REQUIRED'
        ],
        401
    );

}


/* ============================================================
   INPUT
============================================================ */

$chatCode =
    strtolower(
        trim(
            (string)(
                $_POST['chat']
                ??
                ''
            )
        )
    );


$messageText =
    trim(
        (string)(
            $_POST['message_text']
            ??
            ''
        )
    );


$replyToMessageId =
    isset(
        $_POST['reply_to_message_id']
    )
        ?
        (int)
        $_POST['reply_to_message_id']
        :
        0;


if (
    !preg_match(
        '/^[a-f0-9]{64}$/',
        $chatCode
    )
) {

    sendJson(
        false,
        'A valid chat code is required.',
        [
            'code' =>
                'INVALID_CHAT_CODE'
        ],
        422
    );

}


/* ============================================================
   MESSAGE CONTENT CHECK
============================================================ */

$hasFiles =
    isset(
        $_FILES['attachments']
    )
    &&
    is_array(
        $_FILES['attachments']['name']
        ??
        null
    );


if (
    $messageText === ''
    &&
    !$hasFiles
) {

    sendJson(
        false,
        'Write a message or select an attachment.',
        [
            'code' =>
                'EMPTY_MESSAGE'
        ],
        422
    );

}


/* ============================================================
   URL CHECK
============================================================ */

function containsForbiddenLink(
    string $text
): bool {

    if (
        $text === ''
    ) {

        return false;

    }


    $patterns =
        [

            '/https?:\/\//i',

            '/http:\/\//i',

            '/https?:\\\\\/\\\\\//i',

            '/www\./i',

            '/\bwa\.me\b/i',

            '/\bwhatsapp\.com\b/i',

            '/\b[a-z0-9-]+\.(com|net|org|io|co|ke|uk|us|biz|info|xyz)(\/\S*)?\b/i'

        ];


    foreach (
        $patterns as $pattern
    ) {

        if (
            preg_match(
                $pattern,
                $text
            )
        ) {

            return true;

        }

    }


    return false;

}


if (
    containsForbiddenLink(
        $messageText
    )
) {

    sendJson(
        false,
        'Links and website addresses are not allowed in LOVEMI messages.',
        [
            'code' =>
                'LINK_NOT_ALLOWED'
        ],
        422
    );

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SEND MESSAGE DB] '
        .
        $e->getMessage()
    );

    sendJson(
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
   RESOLVE CHAT CODE
============================================================ */

try {

    $conversationStmt =
        $pdo->prepare(
            "
            SELECT

                c.id AS conversation_id,

                c.connection_id,

                c.user_one_id,

                c.user_two_id,

                c.status,

                CASE

                    WHEN c.user_one_id =
                        :current_user_one

                        THEN c.user_two_id

                    ELSE

                        c.user_one_id

                END AS receiver_id

            FROM conversation_access_codes cac

            INNER JOIN conversations c

                ON c.id =
                    cac.conversation_id

            WHERE

                cac.access_code =
                    :access_code

              AND

                (
                    c.user_one_id =
                        :current_user_two

                    OR

                    c.user_two_id =
                        :current_user_three
                )

              AND c.status =
                    'active'

            LIMIT 1
            "
        );


    $conversationStmt->execute(
        [

            ':current_user_one' =>
                $currentUserId,

            ':access_code' =>
                $chatCode,

            ':current_user_two' =>
                $currentUserId,

            ':current_user_three' =>
                $currentUserId

        ]
    );


    $conversation =
        $conversationStmt->fetch(
            PDO::FETCH_ASSOC
        );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SEND MESSAGE CHAT] '
        .
        $e->getMessage()
    );

    sendJson(
        false,
        'Unable to verify the conversation.',
        [
            'code' =>
                'CONVERSATION_LOOKUP_FAILED'
        ],
        500
    );

}


if (
    !$conversation
) {

    sendJson(
        false,
        'Conversation not found or access denied.',
        [
            'code' =>
                'CONVERSATION_NOT_FOUND'
        ],
        404
    );

}


$conversationId =
    (int)
    $conversation['conversation_id'];


$receiverId =
    (int)
    $conversation['receiver_id'];


if (
    $receiverId <= 0
    ||
    $receiverId ===
    $currentUserId
) {

    sendJson(
        false,
        'Invalid conversation participants.',
        [
            'code' =>
                'INVALID_PARTICIPANTS'
        ],
        422
    );

}


/* ============================================================
   IMPORTANT PREMIUM CHECK
============================================================ */

/*
 * ONE active Premium is enough.
 *
 * Current user Premium
 *      OR
 * Other user Premium
 *
 * = SEND ALLOWED
 *
 * Both do NOT need Premium.
 */

$currentUserPremium =
    false;


$otherUserPremium =
    false;


try {

    $premiumStmt =
        $pdo->prepare(
            "
            SELECT

                s.user_id

            FROM subscriptions s

            INNER JOIN services sv

                ON sv.id =
                    s.service_id

            WHERE

                s.user_id IN
                (
                    :current_user,
                    :other_user
                )

              AND LOWER(
                    TRIM(
                        s.status
                    )
                  ) = 'active'

              AND s.end_at IS NOT NULL

              AND s.end_at >
                    CURRENT_TIMESTAMP

              AND LOWER(
                    TRIM(
                        sv.slug
                    )
                  ) = 'lovemi-premium'

              AND sv.is_premium = 1

              AND sv.is_active = 1

            GROUP BY
                s.user_id
            "
        );


    $premiumStmt->execute(
        [

            ':current_user' =>
                $currentUserId,

            ':other_user' =>
                $receiverId

        ]
    );


    while (
        $premiumUserId =
            $premiumStmt->fetchColumn()
    ) {

        $premiumUserId =
            (int)
            $premiumUserId;


        if (
            $premiumUserId ===
            $currentUserId
        ) {

            $currentUserPremium =
                true;

        }


        if (
            $premiumUserId ===
            $receiverId
        ) {

            $otherUserPremium =
                true;

        }

    }

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI SEND PREMIUM CHECK] '
        .
        $e->getMessage()
    );


    sendJson(
        false,
        'Unable to verify Premium access.',
        [
            'code' =>
                'PREMIUM_CHECK_FAILED'
        ],
        500
    );

}


/*
 * THIS IS THE CORRECT RULE.
 */

$canSend =
    $currentUserPremium
    ||
    $otherUserPremium;


if (
    !$canSend
) {

    sendJson(
        false,
        'Messaging is paused because neither connected member currently has active LOVEMI Premium.',
        [

            'code' =>
                'PREMIUM_REQUIRED',

            'current_user_premium' =>
                false,

            'other_user_premium' =>
                false

        ],
        403
    );

}


/* ============================================================
   CHECK WHATSAPP NUMBERS IN TEXT
============================================================ */

if (
    $messageText !== ''
) {

    try {

        $waTable =
            $pdo->query(
                "
                SHOW TABLES LIKE
                    'user_whatsapp_numbers'
                "
            );


        if (
            $waTable
            &&
            $waTable->fetch()
        ) {

            $waStmt =
                $pdo->prepare(
                    "
                    SELECT whatsapp_number

                    FROM user_whatsapp_numbers

                    WHERE

                        user_id IN
                        (
                            :current_user,
                            :other_user
                        )

                      AND is_active = 1
                    "
                );


            $waStmt->execute(
                [

                    ':current_user' =>
                        $currentUserId,

                    ':other_user' =>
                        $receiverId

                ]
            );


            $numbers =
                $waStmt->fetchAll(
                    PDO::FETCH_COLUMN
                );


            $messageDigits =
                preg_replace(
                    '/\D+/',
                    '',
                    $messageText
                );


            foreach (
                $numbers as $number
            ) {

                $numberDigits =
                    preg_replace(
                        '/\D+/',
                        '',
                        (string)
                        $number
                    );


                if (
                    $numberDigits !== ''
                    &&
                    strlen(
                        $numberDigits
                    ) >= 8
                    &&
                    str_contains(
                        $messageDigits,
                        $numberDigits
                    )
                ) {

                    sendJson(
                        false,
                        'WhatsApp numbers cannot be sent through LOVEMI chat.',
                        [
                            'code' =>
                                'WHATSAPP_NUMBER_NOT_ALLOWED'
                        ],
                        422
                    );

                }

            }

        }

    } catch (
        Throwable $e
    ) {

        /*
         * Do not block a normal message if the optional
         * WhatsApp table is unavailable.
         */

        error_log(
            '[LOVEMI WHATSAPP CHECK] '
            .
            $e->getMessage()
        );

    }

}


/* ============================================================
   REPLY VALIDATION
============================================================ */

if (
    $replyToMessageId > 0
) {

    try {

        $replyStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM messages

                WHERE

                    id =
                        :message_id

                  AND conversation_id =
                        :conversation_id

                  AND
                    (
                        sender_id =
                            :user_one

                        OR

                        receiver_id =
                            :user_two
                    )

                LIMIT 1
                "
            );


        $replyStmt->execute(
            [

                ':message_id' =>
                    $replyToMessageId,

                ':conversation_id' =>
                    $conversationId,

                ':user_one' =>
                    $currentUserId,

                ':user_two' =>
                    $currentUserId

            ]
        );


        if (
            !$replyStmt->fetchColumn()
        ) {

            $replyToMessageId =
                0;

        }

    } catch (
        Throwable $e
    ) {

        $replyToMessageId =
            0;

    }

}


/* ============================================================
   ATTACHMENT VALIDATION
============================================================ */

$allowedMimeTypes =
    [

        'image/jpeg' =>
            'image',

        'image/png' =>
            'image',

        'image/gif' =>
            'image',

        'image/webp' =>
            'image',

        'image/heic' =>
            'image',

        'video/mp4' =>
            'video',

        'video/webm' =>
            'video',

        'video/quicktime' =>
            'video',

        'audio/mpeg' =>
            'audio',

        'audio/mp3' =>
            'audio',

        'audio/wav' =>
            'audio',

        'audio/x-wav' =>
            'audio',

        'audio/ogg' =>
            'audio',

        'audio/mp4' =>
            'audio',

        'application/pdf' =>
            'document',

        'text/plain' =>
            'document',

        'text/csv' =>
            'document',

        'application/rtf' =>
            'document',

        'application/msword' =>
            'document',

        'application/vnd.openxmlformats-officedocument.wordprocessingml.document' =>
            'document',

        'application/vnd.ms-excel' =>
            'document',

        'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' =>
            'document',

        'application/vnd.ms-powerpoint' =>
            'document',

        'application/vnd.openxmlformats-officedocument.presentationml.presentation' =>
            'document',

        'application/zip' =>
            'document'

    ];


$maxFileSize =
    25 *
    1024 *
    1024;


$files =
    [];


if (
    isset(
        $_FILES['attachments']
    )
    &&
    is_array(
        $_FILES['attachments']['name']
        ??
        null
    )
) {

    $fileCount =
        count(
            $_FILES['attachments']['name']
        );


    if (
        $fileCount >
        5
    ) {

        sendJson(
            false,
            'You can attach a maximum of 5 files at once.',
            [
                'code' =>
                    'TOO_MANY_ATTACHMENTS'
            ],
            422
        );

    }


    $finfo =
        new finfo(
            FILEINFO_MIME_TYPE
        );


    for (
        $index = 0;
        $index < $fileCount;
        $index++
    ) {

        $error =
            (int)(
                $_FILES['attachments']['error'][$index]
                ??
                UPLOAD_ERR_NO_FILE
            );


        if (
            $error ===
            UPLOAD_ERR_NO_FILE
        ) {

            continue;

        }


        if (
            $error !==
            UPLOAD_ERR_OK
        ) {

            sendJson(
                false,
                'An attachment could not be uploaded.',
                [
                    'code' =>
                        'UPLOAD_ERROR'
                ],
                422
            );

        }


        $temporaryPath =
            (string)
            $_FILES['attachments']['tmp_name'][$index];


        $size =
            (int)(
                $_FILES['attachments']['size'][$index]
                ??
                0
            );


        if (
            $size <= 0
            ||
            $size >
            $maxFileSize
        ) {

            sendJson(
                false,
                'Each attachment must not exceed 25 MB.',
                [
                    'code' =>
                        'FILE_SIZE_NOT_ALLOWED'
                ],
                422
            );

        }


        $originalName =
            basename(
                (string)(
                    $_FILES['attachments']['name'][$index]
                    ??
                    'attachment'
                )
            );


        $mime =
            $finfo->file(
                $temporaryPath
            );


        if (
            !is_string(
                $mime
            )
            ||
            !isset(
                $allowedMimeTypes[$mime]
            )
        ) {

            sendJson(
                false,
                'This file type is not allowed.',
                [
                    'code' =>
                        'FILE_TYPE_NOT_ALLOWED',

                    'file' =>
                        $originalName
                ],
                422
            );

        }


        $files[] =
            [

                'tmp_name' =>
                    $temporaryPath,

                'original_name' =>
                    $originalName,

                'mime' =>
                    $mime,

                'category' =>
                    $allowedMimeTypes[$mime],

                'size' =>
                    $size

            ];

    }

}


/* ============================================================
   DETERMINE MESSAGE TYPE
============================================================ */

$messageType =
    'text';


if (
    count(
        $files
    )
    >
    0
) {

    $messageType =
        $files[0]['category'];

}


/* ============================================================
   UPLOAD DIRECTORY
============================================================ */

$uploadDirectory =
    __DIR__
    .
    '/../../uploads/chat';


if (
    !is_dir(
        $uploadDirectory
    )
) {

    if (
        !mkdir(
            $uploadDirectory,
            0750,
            true
        )
    ) {

        sendJson(
            false,
            'Unable to prepare attachment storage.',
            [
                'code' =>
                    'UPLOAD_DIRECTORY_FAILED'
            ],
            500
        );

    }

}


/* ============================================================
   TRANSACTION
============================================================ */

try {

    $pdo->beginTransaction();


    $uploadedFiles =
        [];


    foreach (
        $files as $file
    ) {

        $extension =
            strtolower(
                pathinfo(
                    $file['original_name'],
                    PATHINFO_EXTENSION
                )
            );


        $randomName =
            bin2hex(
                random_bytes(
                    20
                )
            );


        if (
            $extension !== ''
        ) {

            $cleanExtension =
                preg_replace(
                    '/[^a-z0-9]+/i',
                    '',
                    $extension
                );


            if (
                is_string(
                    $cleanExtension
                )
                &&
                $cleanExtension !== ''
            ) {

                $randomName .=
                    '.'
                    .
                    $cleanExtension;

            }

        }


        $destination =
            $uploadDirectory
            .
            DIRECTORY_SEPARATOR
            .
            $randomName;


        if (
            !move_uploaded_file(
                $file['tmp_name'],
                $destination
            )
        ) {

            throw new RuntimeException(
                'Unable to save attachment.'
            );

        }


        @chmod(
            $destination,
            0640
        );


        $uploadedFiles[] =
            [

                'path' =>
                    'uploads/chat/'
                    .
                    $randomName,

                'name' =>
                    $file['original_name'],

                'mime' =>
                    $file['mime'],

                'category' =>
                    $file['category']

            ];

    }


    /*
     * Ensure the optional reply table exists.
     */

    if (
        $replyToMessageId >
        0
    ) {

        try {

            $pdo->exec(
                "
                CREATE TABLE IF NOT EXISTS message_replies
                (
                    message_id BIGINT UNSIGNED NOT NULL,

                    reply_to_message_id BIGINT UNSIGNED NOT NULL,

                    created_at DATETIME NOT NULL
                        DEFAULT CURRENT_TIMESTAMP,

                    PRIMARY KEY (message_id),

                    KEY idx_reply_target
                        (reply_to_message_id)

                )
                ENGINE=InnoDB

                DEFAULT CHARSET=utf8mb4

                COLLATE=utf8mb4_unicode_ci
                "
            );

        } catch (
            Throwable $e
        ) {

            $replyToMessageId =
                0;

        }

    }


    /* ========================================================
       TEXT ONLY
    ======================================================== */

    if (
        count(
            $uploadedFiles
        )
        ===
        0
    ) {

        $insert =
            $pdo->prepare(
                "
                INSERT INTO messages
                (
                    conversation_id,
                    sender_id,
                    receiver_id,
                    message_type,
                    message_text,
                    attachment_path,
                    attachment_name,
                    attachment_mime,
                    is_read,
                    created_at
                )

                VALUES
                (
                    :conversation_id,
                    :sender_id,
                    :receiver_id,
                    :message_type,
                    :message_text,
                    NULL,
                    NULL,
                    NULL,
                    0,
                    CURRENT_TIMESTAMP
                )
                "
            );


        $insert->execute(
            [

                ':conversation_id' =>
                    $conversationId,

                ':sender_id' =>
                    $currentUserId,

                ':receiver_id' =>
                    $receiverId,

                ':message_type' =>
                    'text',

                ':message_text' =>
                    $messageText !== ''
                        ?
                        $messageText
                        :
                        null

            ]
        );


        $messageId =
            (int)
            $pdo->lastInsertId();


        if (
            $replyToMessageId >
            0
        ) {

            try {

                $replyInsert =
                    $pdo->prepare(
                        "
                        INSERT INTO message_replies
                        (
                            message_id,
                            reply_to_message_id
                        )

                        VALUES
                        (
                            :message_id,
                            :reply_to_message_id
                        )
                        "
                    );


                $replyInsert->execute(
                    [

                        ':message_id' =>
                            $messageId,

                        ':reply_to_message_id' =>
                            $replyToMessageId

                    ]
                );

            } catch (
                Throwable $e
            ) {

                error_log(
                    '[LOVEMI REPLY INSERT] '
                    .
                    $e->getMessage()
                );

            }

        }


    } else {

        /* ====================================================
           ATTACHMENTS
        ==================================================== */

        $messageId =
            0;


        $firstAttachment =
            true;


        foreach (
            $uploadedFiles
            as $uploaded
        ) {

            $insert =
                $pdo->prepare(
                    "
                    INSERT INTO messages
                    (
                        conversation_id,
                        sender_id,
                        receiver_id,
                        message_type,
                        message_text,
                        attachment_path,
                        attachment_name,
                        attachment_mime,
                        is_read,
                        created_at
                    )

                    VALUES
                    (
                        :conversation_id,
                        :sender_id,
                        :receiver_id,
                        :message_type,
                        :message_text,
                        :attachment_path,
                        :attachment_name,
                        :attachment_mime,
                        0,
                        CURRENT_TIMESTAMP
                    )
                    "
                );


            $insert->execute(
                [

                    ':conversation_id' =>
                        $conversationId,

                    ':sender_id' =>
                        $currentUserId,

                    ':receiver_id' =>
                        $receiverId,

                    ':message_type' =>
                        $uploaded[
                            'category'
                        ],

                    ':message_text' =>
                        $firstAttachment
                        &&
                        $messageText !== ''
                            ?
                            $messageText
                            :
                            null,

                    ':attachment_path' =>
                        $uploaded[
                            'path'
                        ],

                    ':attachment_name' =>
                        $uploaded[
                            'name'
                        ],

                    ':attachment_mime' =>
                        $uploaded[
                            'mime'
                        ]

                ]
            );


            $messageId =
                (int)
                $pdo->lastInsertId();


            if (
                $firstAttachment
                &&
                $replyToMessageId >
                0
            ) {

                try {

                    $replyInsert =
                        $pdo->prepare(
                            "
                            INSERT INTO message_replies
                            (
                                message_id,
                                reply_to_message_id
                            )

                            VALUES
                            (
                                :message_id,
                                :reply_to_message_id
                            )
                            "
                        );


                    $replyInsert->execute(
                        [

                            ':message_id' =>
                                $messageId,

                            ':reply_to_message_id' =>
                                $replyToMessageId

                        ]
                    );

                } catch (
                    Throwable $e
                ) {

                    error_log(
                        '[LOVEMI ATTACHMENT REPLY INSERT] '
                        .
                        $e->getMessage()
                    );

                }

            }


            $firstAttachment =
                false;

        }

    }


    /*
     * Update conversation activity.
     */

    $conversationUpdate =
        $pdo->prepare(
            "
            UPDATE conversations

            SET updated_at =
                CURRENT_TIMESTAMP

            WHERE id =
                :conversation_id

            LIMIT 1
            "
        );


    $conversationUpdate->execute(
        [

            ':conversation_id' =>
                $conversationId

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
        '[LOVEMI SEND MESSAGE INSERT] '
        .
        $e->getMessage()
    );


    sendJson(
        false,
        'The message could not be sent.',
        [
            'code' =>
                'MESSAGE_INSERT_FAILED'
        ],
        500
    );

}


/* ============================================================
   CREATE MESSAGE NOTIFICATION
============================================================ */

try {

    $audioId =
        null;


    $audioTable =
        $pdo->query(
            "
            SHOW TABLES LIKE
                'notification_audio'
            "
        );


    if (
        $audioTable
        &&
        $audioTable->fetch()
    ) {

        $audioStmt =
            $pdo->prepare(
                "
                SELECT id

                FROM notification_audio

                WHERE

                    file_name =
                        'notification4.mp3'

                  AND is_active = 1

                LIMIT 1
                "
            );


        $audioStmt->execute();


        $audioId =
            $audioStmt->fetchColumn();

    }


    $notificationTable =
        $pdo->query(
            "
            SHOW TABLES LIKE
                'notifications'
            "
        );


    if (
        $notificationTable
        &&
        $notificationTable->fetch()
    ) {

        $notificationStmt =
            $pdo->prepare(
                "
                INSERT INTO notifications
                (
                    user_id,
                    sender_id,
                    title,
                    message,
                    reference_type,
                    reference_id,
                    audio_id,
                    is_read,
                    created_at
                )

                VALUES
                (
                    :user_id,
                    :sender_id,
                    'New Message',
                    'You received a new LOVEMI message.',
                    'new_message',
                    :reference_id,
                    :audio_id,
                    0,
                    CURRENT_TIMESTAMP
                )
                "
            );


        $notificationStmt->execute(
            [

                ':user_id' =>
                    $receiverId,

                ':sender_id' =>
                    $currentUserId,

                ':reference_id' =>
                    $messageId,

                ':audio_id' =>
                    $audioId
                    ?
                    (int)
                    $audioId
                    :
                    null

            ]
        );

    }

} catch (
    Throwable $e
) {

    /*
     * Message was already sent.
     * Notification failure must not undo it.
     */

    error_log(
        '[LOVEMI MESSAGE NOTIFICATION] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

sendJson(
    true,
    'Message sent successfully.',
    [

        'message_id' =>
            $messageId,

        'conversation_id' =>
            $conversationId,

        'receiver_id' =>
            $receiverId,

        'premium_access' =>
            [

                'current_user_premium' =>
                    $currentUserPremium,

                'other_user_premium' =>
                    $otherUserPremium,

                'can_send' =>
                    true

            ]

    ]
);