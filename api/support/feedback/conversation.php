<?php declare(strict_types=1);

/**
 * ============================================================
 * LOVEMI SUPPORT - SECURE CONVERSATIONS API
 * ============================================================
 *
 * Actions:
 *
 * ?action=list
 * Return all support tickets belonging to the verified
 * LOVEMI account.
 *
 * ?action=messages&ticket_id=123
 * Return the complete message history for one ticket.
 *
 * ?action=current
 * Return the ticket represented by the secure token and
 * its complete message history.
 *
 * Security:
 *
 * - Requires a valid secure support token.
 * - Never trusts a user_id supplied by the browser.
 * - Account users can only access tickets belonging to the
 *   same authenticated account.
 * - Account users must have completed support email and
 *   support 2FA verification.
 * - Guest users can access only the ticket represented by
 *   their secure token.
 *
 * ============================================================
 */

require_once __DIR__ . '/common.php';

/* ============================================================
   METHOD
   ============================================================ */

if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET'
) {
    fb_out(
        false,
        'Only GET requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}

/* ============================================================
   DATABASE
   ============================================================ */

try {
    $pdo = fb_pdo();

    /*
     * Make sure the support tables/columns required by the
     * current support system exist.
     */
    fb_schema($pdo);

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUPPORT CONVERSATION DB ERROR] ' .
        $e->getMessage()
    );

    fb_out(
        false,
        'The support conversation service is temporarily unavailable.',
        [
            'code' => 'DATABASE_ERROR'
        ],
        500
    );
}

/* ============================================================
   INPUT
   ============================================================ */

$action = strtolower(
    fb_clean(
        $_GET['action'] ?? 'current',
        30
    )
);

$token = trim(
    (string)(
        $_GET['token'] ?? ''
    )
);

$requestedTicketId = isset($_GET['ticket_id'])
    ? (int) $_GET['ticket_id']
    : 0;

/* ============================================================
   VALIDATE TOKEN
   ============================================================ */

if ($token === '') {

    fb_out(
        false,
        'A secure support ticket token is required.',
        [
            'code' => 'TOKEN_REQUIRED'
        ],
        401
    );
}

/* ============================================================
   LOAD TOKEN TICKET
   ============================================================ */

try {

    $tokenTicket = fb_access(
        $pdo,
        $token
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUPPORT TOKEN LOOKUP ERROR] ' .
        $e->getMessage()
    );

    fb_out(
        false,
        'The secure support link could not be checked.',
        [
            'code' => 'TOKEN_LOOKUP_ERROR'
        ],
        500
    );
}

if (!$tokenTicket) {

    fb_out(
        false,
        'This support link is invalid or has expired.',
        [
            'code' => 'INVALID_TICKET_LINK'
        ],
        404
    );
}

/* ============================================================
   AUTHORIZE SECURE SUPPORT SESSION
   ============================================================ */

try {

    $authorization = fb_authorized(
        $pdo,
        $tokenTicket
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUPPORT AUTHORIZATION ERROR] ' .
        $e->getMessage()
    );

    fb_out(
        false,
        'Support verification could not be completed.',
        [
            'code' => 'AUTHORIZATION_ERROR'
        ],
        500
    );
}

if (!($authorization['ok'] ?? false)) {

    /*
     * Do not return conversation data before the required
     * verification has completed.
     */

    fb_out(
        true,
        'Support verification is required.',
        [
            'access_granted' => false,

            'verification_required' =>
                $authorization['reason'] ?? 'email',

            'ticket' => [
                'id' =>
                    (int) $tokenTicket['ticket_id'],

                'subject' =>
                    (string) $tokenTicket['subject'],

                'source' =>
                    (string) $tokenTicket['source'],

                'source_label' =>
                    strtolower(
                        (string) $tokenTicket['source']
                    ) === 'contact'
                        ? 'Contact Center'
                        : 'Help Center'
            ]
        ],
        200
    );
}

/* ============================================================
   SUPPORT ACCESS GRANTED
   ============================================================ */

$accessType = strtolower(
    (string)(
        $tokenTicket['access_type'] ?? 'guest'
    )
);

$currentTicketId = (int)(
    $tokenTicket['ticket_id'] ?? 0
);

$currentUserId = (int)(
    $tokenTicket['user_id'] ?? 0
);

/* ============================================================
   GUEST ACCESS
   ============================================================ */

if (
    $accessType === 'guest' ||
    $currentUserId <= 0
) {

    /*
     * A guest is intentionally limited to the exact ticket
     * represented by the secure token.
     */

    if (
        $action === 'list' ||
        $action === 'current' ||
        $action === 'messages'
    ) {

        if (
            $requestedTicketId > 0 &&
            $requestedTicketId !== $currentTicketId
        ) {

            fb_out(
                false,
                'This support link can only access its own conversation.',
                [
                    'code' =>
                        'GUEST_TICKET_ACCESS_DENIED'
                ],
                403
            );
        }

        $guestMessages = fb_messages(
            $pdo,
            $currentTicketId
        );

        $guestTicket = [

            'id' =>
                $currentTicketId,

            'ticket_id' =>
                $currentTicketId,

            'user_id' =>
                null,

            'name' =>
                (string) $tokenTicket['name'],

            'email' =>
                (string) $tokenTicket['email'],

            'category' =>
                (string) $tokenTicket['category'],

            'subject' =>
                (string) $tokenTicket['subject'],

            'message' =>
                (string) $tokenTicket['message'],

            'status' =>
                (string) $tokenTicket['status'],

            'status_label' =>
                match (
                    strtolower(
                        (string) $tokenTicket['status']
                    )
                ) {
                    'awaiting_admin' =>
                        'Awaiting Support',

                    'awaiting_user' =>
                        'Awaiting User',

                    'solved' =>
                        'Solved',

                    'closed' =>
                        'Closed',

                    'received' =>
                        'Received',

                    default =>
                        'Open'
                },

            'source' =>
                (string) $tokenTicket['source'],

            'source_label' =>
                strtolower(
                    (string) $tokenTicket['source']
                ) === 'contact'
                    ? 'Contact Center'
                    : 'Help Center',

            'created_at' =>
                $tokenTicket['created_at'],

            'updated_at' =>
                $tokenTicket['updated_at'],

            'last_user_reply_at' =>
                $tokenTicket['last_user_reply_at'],

            'last_admin_reply_at' =>
                $tokenTicket['last_admin_reply_at'],

            'last_message_at' =>
                $tokenTicket['last_message_at'],

            'close_at' =>
                $tokenTicket['close_at'],

            'solved_at' =>
                $tokenTicket['solved_at'],

            'closed_at' =>
                $tokenTicket['closed_at'],

            'access_type' =>
                'guest',

            'preview' =>
                count($guestMessages) > 0
                    ? (string)(
                        $guestMessages[
                            count($guestMessages) - 1
                        ]['body'] ?? ''
                    )
                    : (string) $tokenTicket['message']
        ];

        /*
         * Return one conversation for guests.
         */

        if ($action === 'list') {

            fb_out(
                true,
                'Support conversation loaded.',
                [
                    'access_granted' =>
                        true,

                    'access_type' =>
                        'guest',

                    'conversations' =>
                        [
                            $guestTicket
                        ],

                    'selected_ticket_id' =>
                        $currentTicketId
                ]
            );
        }

        fb_out(
            true,
            'Support messages loaded.',
            [
                'access_granted' =>
                    true,

                'access_type' =>
                    'guest',

                'ticket' =>
                    $guestTicket,

                'messages' =>
                    $guestMessages
            ]
        );
    }

    fb_out(
        false,
        'Unsupported support conversation action.',
        [
            'code' =>
                'INVALID_ACTION'
        ],
        422
    );
}

/* ============================================================
   ACCOUNT ACCESS
   ============================================================ */

/*
 * The current token was verified through:
 *
 * fb_email_ok()
 * fb_2fa_ok()
 *
 * and fb_authorized() returned "granted".
 *
 * We now get the actual authenticated session.
 */

try {

    $sessionUser = fb_session_user(
        $pdo
    );

} catch (Throwable $e) {

    error_log(
        '[LOVEMI SUPPORT SESSION LOOKUP ERROR] ' .
        $e->getMessage()
    );

    fb_out(
        false,
        'Your LOVEMI session could not be verified.',
        [
            'code' =>
                'SESSION_LOOKUP_ERROR'
        ],
        401
    );
}

if (!$sessionUser) {

    fb_out(
        false,
        'Please sign in to the LOVEMI account that owns this support ticket.',
        [
            'code' =>
                'LOGIN_REQUIRED'
        ],
        401
    );
}

$sessionUserId = (int)(
    $sessionUser['user_id'] ?? 0
);

if ($sessionUserId <= 0) {

    fb_out(
        false,
        'Your LOVEMI account could not be identified.',
        [
            'code' =>
                'ACCOUNT_NOT_FOUND'
        ],
        401
    );
}

/*
 * The secure token ticket must belong to the same account
 * as the current authenticated LOVEMI account.
 */

if ($currentUserId !== $sessionUserId) {

    fb_out(
        false,
        'This support ticket belongs to a different LOVEMI account.',
        [
            'code' =>
                'ACCOUNT_TICKET_MISMATCH'
        ],
        403
    );
}

/* ============================================================
   ACCOUNT TICKET PAYLOAD HELPER
   ============================================================ */

function conversationTicketPayload(
    array $ticket,
    ?string $preview = null
): array {

    $status = strtolower(
        (string)(
            $ticket['status'] ?? 'open'
        )
    );

    $source = strtolower(
        (string)(
            $ticket['source'] ?? 'help'
        )
    );

    if ($preview === null) {

        $preview = (string)(
            $ticket['message'] ?? ''
        );
    }

    return [

        'id' =>
            (int)(
                $ticket['id']
                ?? $ticket['ticket_id']
                ?? 0
            ),

        'ticket_id' =>
            (int)(
                $ticket['id']
                ?? $ticket['ticket_id']
                ?? 0
            ),

        'user_id' =>
            isset($ticket['user_id'])
                ? (int)$ticket['user_id']
                : null,

        'name' =>
            (string)(
                $ticket['name'] ?? ''
            ),

        'email' =>
            (string)(
                $ticket['email'] ?? ''
            ),

        'category' =>
            (string)(
                $ticket['category']
                ?? 'other'
            ),

        'subject' =>
            (string)(
                $ticket['subject']
                ?? 'Support ticket'
            ),

        'message' =>
            (string)(
                $ticket['message'] ?? ''
            ),

        'preview' =>
            $preview,

        'status' =>
            $status,

        'status_label' =>
            match ($status) {

                'awaiting_admin' =>
                    'Awaiting Support',

                'awaiting_user' =>
                    'Awaiting User',

                'solved' =>
                    'Solved',

                'closed' =>
                    'Closed',

                'received' =>
                    'Received',

                default =>
                    'Open'
            },

        'source' =>
            $source,

        'source_label' =>
            $source === 'contact'
                ? 'Contact Center'
                : 'Help Center',

        'created_at' =>
            $ticket['created_at'] ?? null,

        'updated_at' =>
            $ticket['updated_at'] ?? null,

        'last_user_reply_at' =>
            $ticket['last_user_reply_at'] ?? null,

        'last_admin_reply_at' =>
            $ticket['last_admin_reply_at'] ?? null,

        'last_message_at' =>
            $ticket['last_message_at'] ?? null,

        'close_at' =>
            $ticket['close_at'] ?? null,

        'solved_at' =>
            $ticket['solved_at'] ?? null,

        'closed_at' =>
            $ticket['closed_at'] ?? null,

        'access_type' =>
            'account'
    ];
}

/* ============================================================
   LIST ALL ACCOUNT CONVERSATIONS
   ============================================================ */

if ($action === 'list') {

    try {

        /*
         * Load every support ticket belonging to the currently
         * authenticated LOVEMI user.
         *
         * We do NOT accept user_id from GET.
         */

        $stmt = $pdo->prepare(
            "
            SELECT t.*
            FROM support_tickets t
            WHERE t.user_id = :user_id
            ORDER BY
                COALESCE(
                    t.last_message_at,
                    t.updated_at,
                    t.created_at
                ) DESC,
                t.id DESC
            "
        );

        $stmt->execute(
            [
                ':user_id' =>
                    $sessionUserId
            ]
        );

        $rows = $stmt->fetchAll(
            PDO::FETCH_ASSOC
        );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI SUPPORT CONVERSATION LIST ERROR] ' .
            $e->getMessage()
        );

        fb_out(
            false,
            'Unable to load your previous support conversations.',
            [
                'code' =>
                    'CONVERSATION_LIST_ERROR'
            ],
            500
        );
    }

    $conversations = [];

    foreach ($rows as $row) {

        $ticketId = (int)(
            $row['id'] ?? 0
        );

        if ($ticketId <= 0) {
            continue;
        }

        /*
         * Get the latest message as sidebar preview.
         */

        try {

            $previewStmt = $pdo->prepare(
                "
                SELECT body, created_at
                FROM support_ticket_messages
                WHERE ticket_id = :ticket_id
                ORDER BY id DESC
                LIMIT 1
                "
            );

            $previewStmt->execute(
                [
                    ':ticket_id' =>
                        $ticketId
                ]
            );

            $latest = $previewStmt->fetch(
                PDO::FETCH_ASSOC
            );

        } catch (Throwable $e) {

            $latest = false;

            error_log(
                '[LOVEMI SUPPORT PREVIEW ERROR] ' .
                $e->getMessage()
            );
        }

        $preview = $latest
            ? (string)(
                $latest['body'] ?? ''
            )
            : (string)(
                $row['message'] ?? ''
            );

        $conversations[] =
            conversationTicketPayload(
                $row,
                $preview
            );
    }

    /*
     * Make sure the ticket used to authenticate this page is
     * present even if the database was recently updated.
     */

    $containsCurrent = false;

    foreach (
        $conversations as $item
    ) {

        if (
            (int)$item['id'] ===
            $currentTicketId
        ) {

            $containsCurrent = true;
            break;
        }
    }

    if (!$containsCurrent) {

        $conversations[] =
            conversationTicketPayload(
                $tokenTicket
            );
    }

    /*
     * Sort again after possible insertion.
     */

    usort(
        $conversations,
        static function (
            array $a,
            array $b
        ): int {

            $aDate = strtotime(
                (string)(
                    $a['last_message_at']
                    ?? $a['updated_at']
                    ?? $a['created_at']
                    ?? ''
                )
            );

            $bDate = strtotime(
                (string)(
                    $b['last_message_at']
                    ?? $b['updated_at']
                    ?? $b['created_at']
                    ?? ''
                )
            );

            if ($aDate === $bDate) {

                return (
                    (int)$b['id']
                    <=>
                    (int)$a['id']
                );
            }

            return (
                $bDate
                <=>
                $aDate
            );
        }
    );

    fb_out(
        true,
        'Support conversations loaded.',
        [
            'access_granted' =>
                true,

            'access_type' =>
                'account',

            'current_ticket_id' =>
                $currentTicketId,

            'selected_ticket_id' =>
                $requestedTicketId > 0
                    ? $requestedTicketId
                    : $currentTicketId,

            'total' =>
                count($conversations),

            'conversations' =>
                $conversations
        ]
    );
}

/* ============================================================
   CURRENT TICKET
   ============================================================ */

if ($action === 'current') {

    $messages = fb_messages(
        $pdo,
        $currentTicketId
    );

    $currentPayload =
        conversationTicketPayload(
            $tokenTicket,
            count($messages) > 0
                ? (string)(
                    $messages[
                        count($messages) - 1
                    ]['body'] ?? ''
                )
                : (string)$tokenTicket['message']
        );

    fb_out(
        true,
        'Support conversation loaded.',
        [
            'access_granted' =>
                true,

            'access_type' =>
                'account',

            'ticket' =>
                $currentPayload,

            'messages' =>
                $messages
        ]
    );
}

/* ============================================================
   LOAD SPECIFIC TICKET MESSAGES
   ============================================================ */

if ($action === 'messages') {

    if ($requestedTicketId <= 0) {

        fb_out(
            false,
            'A valid ticket ID is required.',
            [
                'code' =>
                    'TICKET_ID_REQUIRED'
            ],
            422
        );
    }

    /*
     * IMPORTANT:
     *
     * Only retrieve the requested ticket if it belongs to
     * the authenticated account.
     */

    try {

        $ticketStmt = $pdo->prepare(
            "
            SELECT t.*
            FROM support_tickets t
            WHERE t.id = :ticket_id
              AND t.user_id = :user_id
            LIMIT 1
            "
        );

        $ticketStmt->execute(
            [
                ':ticket_id' =>
                    $requestedTicketId,

                ':user_id' =>
                    $sessionUserId
            ]
        );

        $selectedTicket =
            $ticketStmt->fetch(
                PDO::FETCH_ASSOC
            );

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI SUPPORT SELECTED TICKET ERROR] ' .
            $e->getMessage()
        );

        fb_out(
            false,
            'Unable to load the selected support ticket.',
            [
                'code' =>
                    'SELECTED_TICKET_ERROR'
            ],
            500
        );
    }

    if (!$selectedTicket) {

        fb_out(
            false,
            'That support conversation does not belong to this account or no longer exists.',
            [
                'code' =>
                    'TICKET_ACCESS_DENIED'
            ],
            403
        );
    }

    $messages = fb_messages(
        $pdo,
        $requestedTicketId
    );

    /*
     * Use the newest actual message as the preview.
     */

    $preview =
        count($messages) > 0
            ? (string)(
                $messages[
                    count($messages) - 1
                ]['body'] ?? ''
            )
            : (string)(
                $selectedTicket['message']
                ?? ''
            );

    $ticketPayload =
        conversationTicketPayload(
            $selectedTicket,
            $preview
        );

    fb_out(
        true,
        'Support messages loaded.',
        [
            'access_granted' =>
                true,

            'access_type' =>
                'account',

            'ticket' =>
                $ticketPayload,

            'messages' =>
                $messages
        ]
    );
}

/* ============================================================
   INVALID ACTION
   ============================================================ */

fb_out(
    false,
    'Unsupported support conversation action.',
    [
        'code' =>
            'INVALID_ACTION',

        'allowed_actions' =>
            [
                'list',
                'current',
                'messages'
            ]
    ],
    422
);