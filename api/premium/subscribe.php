<?php
declare(strict_types=1);

/**
 * LOVEMI Premium Subscription Creation
 *
 * Creates a secure pending payment and subscription.
 * The browser NEVER supplies the price or currency.
 * All payment amounts are calculated from the database.
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

require_once __DIR__ . '/../../config/database.php';


/* ============================================================
   RESPONSE
   ============================================================ */

function premiumSubscribeResponse(
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
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    exit;
}


/* ============================================================
   REQUEST METHOD
   ============================================================ */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    premiumSubscribeResponse(
        false,
        'Only POST requests are allowed.',
        [
            'code' => 'METHOD_NOT_ALLOWED'
        ],
        405
    );
}


/* ============================================================
   AUTHENTICATION
   ============================================================ */

$userId = (int) ($_SESSION['lovemi_user_id'] ?? 0);

if ($userId <= 0) {
    premiumSubscribeResponse(
        false,
        'Please log in before subscribing.',
        [
            'code' => 'AUTHENTICATION_REQUIRED',
            'redirect' => 'login.html?return=premium.html'
        ],
        401
    );
}


/* ============================================================
   READ JSON
   ============================================================ */

$rawInput = file_get_contents('php://input');

if ($rawInput === false || trim($rawInput) === '') {
    $rawInput = '{}';
}

try {
    $input = json_decode(
        $rawInput,
        true,
        512,
        JSON_THROW_ON_ERROR
    );
} catch (Throwable $e) {
    premiumSubscribeResponse(
        false,
        'The payment request contains invalid data.',
        [
            'code' => 'INVALID_JSON'
        ],
        400
    );
}

if (!is_array($input)) {
    premiumSubscribeResponse(
        false,
        'The payment request contains invalid data.',
        [
            'code' => 'INVALID_REQUEST'
        ],
        400
    );
}


/* ============================================================
   INPUT VALUES
   ============================================================ */

$serviceId = filter_var(
    $input['service_id'] ?? null,
    FILTER_VALIDATE_INT
);

$paymentMethod = strtolower(
    trim((string) ($input['payment_method'] ?? ''))
);


/*
 * Accept both names because older versions of premium.html
 * sent "return" while newer versions use "return_path".
 */
$returnPath = trim(
    (string) (
        $input['return_path']
        ?? $input['return']
        ?? 'dashboard.html'
    )
);

if (
    $serviceId === false
    || $serviceId === null
    || $serviceId <= 0
) {
    premiumSubscribeResponse(
        false,
        'Please select a valid Premium service.',
        [
            'code' => 'INVALID_SERVICE'
        ],
        422
    );
}


if (!in_array(
    $paymentMethod,
    [
        'mpesa',
        'paypal',
        'card'
    ],
    true
)) {
    premiumSubscribeResponse(
        false,
        'Please select M-Pesa, PayPal or Card.',
        [
            'code' => 'INVALID_PAYMENT_METHOD'
        ],
        422
    );
}


/* ============================================================
   SAFE RETURN PATH
   ============================================================ */

function safePremiumReturnPath(string $path): string
{
    $fallback = 'dashboard.html';

    $path = trim($path);

    if ($path === '') {
        return $fallback;
    }

    /*
     * Prevent protocol URLs and protocol-relative URLs.
     */
    if (
        preg_match('/[\r\n]/', $path)
        || preg_match('#^[a-z][a-z0-9+\-.]*:#i', $path)
        || str_starts_with($path, '//')
        || preg_match('#^https?://#i', $path)
    ) {
        return $fallback;
    }

    /*
     * Remove the leading slash so all return paths remain inside
     * the LOVEMI application.
     */
    $path = ltrim($path, '/');

    /*
     * Do not allow directory traversal.
     */
    if (
        str_contains($path, '../')
        || str_contains($path, '..\\')
    ) {
        return $fallback;
    }

    return $path;
}

$returnPath = safePremiumReturnPath($returnPath);


/* ============================================================
   PAYMENT PAGE
   ============================================================ */

function premiumPaymentPage(string $method): string
{
    switch ($method) {
        case 'mpesa':
            return 'mpesa-pay.html';

        case 'paypal':
            return 'paypal-pay.html';

        case 'card':
            return 'card-pay.html';

        default:
            return 'premium.html';
    }
}


/* ============================================================
   SECURE PAYMENT CODE
   ============================================================ */

function createSecureCode(): string
{
    return bin2hex(random_bytes(32));
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


    /*
     * ==========================================================
     * SELF-HEALING SECURITY TABLES
     * ==========================================================
     *
     * This prevents the common error where the UI works but the
     * migration containing payment_access_tokens has not yet been
     * imported.
     */


    /*
     * Secure payment access tokens.
     *
     * One active token is maintained for each payment.
     */
    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS payment_access_tokens (
            id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
            payment_id BIGINT UNSIGNED NOT NULL,
            token_hash CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            UNIQUE KEY uq_payment_access_payment
                (payment_id),

            UNIQUE KEY uq_payment_access_token
                (token_hash),

            KEY idx_payment_access_expiry
                (expires_at),

            KEY idx_payment_access_payment
                (payment_id)

        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );


    /*
     * Return route for the payment.
     */
    $pdo->exec(
        "
        CREATE TABLE IF NOT EXISTS payment_return_routes (
            payment_id BIGINT UNSIGNED NOT NULL,
            return_path VARCHAR(500) NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                ON UPDATE CURRENT_TIMESTAMP,

            PRIMARY KEY (payment_id),

            KEY idx_payment_return_path
                (return_path)

        ) ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
        "
    );


    /*
     * ==========================================================
     * START TRANSACTION
     * ==========================================================
     */

    $pdo->beginTransaction();


    /* ==========================================================
       USER
       ========================================================== */

    $userStmt = $pdo->prepare(
        "
        SELECT
            u.id,
            u.full_names,
            u.email,
            u.email_verified,
            u.is_active,
            u.is_suspended,
            u.is_deleted,
            u.account_status,

            c.iso2,
            c.name AS country_name

        FROM users u

        LEFT JOIN countries c
            ON c.id = u.country_id

        WHERE u.id = :user_id

        LIMIT 1

        FOR UPDATE
        "
    );

    $userStmt->execute([
        ':user_id' => $userId
    ]);

    $user = $userStmt->fetch();

    if (!$user) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'Your user account could not be found.',
            [
                'code' => 'USER_NOT_FOUND'
            ],
            404
        );
    }


    /* ==========================================================
       ACCOUNT STATUS
       ========================================================== */

    if ((int) $user['email_verified'] !== 1) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'Please complete email verification before purchasing Premium.',
            [
                'code' => 'EMAIL_NOT_VERIFIED'
            ],
            403
        );
    }


    if (
        (int) $user['is_active'] !== 1
        || (int) $user['is_suspended'] === 1
        || (int) $user['is_deleted'] === 1
        || strtolower((string) $user['account_status']) !== 'approved'
    ) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'Your account is currently unavailable for Premium.',
            [
                'code' => 'ACCOUNT_UNAVAILABLE'
            ],
            403
        );
    }


    /* ==========================================================
       CURRENT ACTIVE PREMIUM COUNT
       ========================================================== */

    $activeStmt = $pdo->prepare(
        "
        SELECT
            s.id,
            s.service_id,
            s.status,
            s.start_at,
            s.end_at,
            sv.name AS service_name

        FROM subscriptions s

        INNER JOIN services sv
            ON sv.id = s.service_id

        WHERE s.user_id = :user_id

          AND s.status = 'active'

          AND s.start_at IS NOT NULL

          AND s.end_at IS NOT NULL

          AND s.end_at > CURRENT_TIMESTAMP

        ORDER BY s.end_at ASC

        FOR UPDATE
        "
    );

    $activeStmt->execute([
        ':user_id' => $userId
    ]);

    $activeSubscriptions = $activeStmt->fetchAll();


    $activeCount = count($activeSubscriptions);


    /*
     * LOVEMI allows a maximum of TWO simultaneously active
     * Premium services.
     */
    if ($activeCount >= 2) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'You already have 2 active Premium memberships. Deactivate one before purchasing another.',
            [
                'code' => 'PREMIUM_LIMIT_REACHED',

                'active_count' => $activeCount,

                'active_subscriptions' => $activeSubscriptions
            ],
            409
        );
    }


    /*
     * The same Premium service cannot be purchased while it is
     * already active.
     */
    foreach ($activeSubscriptions as $activeSubscription) {

        if (
            (int) $activeSubscription['service_id']
            === (int) $serviceId
        ) {
            $pdo->rollBack();

            premiumSubscribeResponse(
                false,
                'This Premium service is already active.',
                [
                    'code' => 'PREMIUM_ALREADY_ACTIVE',

                    'subscription_id' =>
                        (int) $activeSubscription['id']
                ],
                409
            );
        }
    }


    /* ==========================================================
       SERVICE
       ========================================================== */

    $serviceStmt = $pdo->prepare(
        "
        SELECT
            id,
            name,
            slug,
            description,
            service_type,
            base_price_usd,
            duration_days,
            max_usage,
            is_premium,
            is_active

        FROM services

        WHERE id = :service_id

          AND is_active = 1

          AND is_premium = 1

        LIMIT 1

        FOR UPDATE
        "
    );

    $serviceStmt->execute([
        ':service_id' => (int) $serviceId
    ]);

    $service = $serviceStmt->fetch();

    if (!$service) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'The selected Premium service is unavailable.',
            [
                'code' => 'SERVICE_NOT_FOUND'
            ],
            404
        );
    }


    /* ==========================================================
       VALIDATE SERVICE PRICE
       ========================================================== */

    $baseAmountUsd = round(
        (float) $service['base_price_usd'],
        2
    );

    if ($baseAmountUsd <= 0) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'The selected Premium service does not have a valid price.',
            [
                'code' => 'INVALID_SERVICE_PRICE'
            ],
            500
        );
    }


    $durationDays = max(
        1,
        (int) $service['duration_days']
    );


    /* ==========================================================
       PAYMENT CURRENCY
       ========================================================== */

    /*
     * Kenya = KES.
     * All other countries = USD.
     */
    $countryIso = strtoupper(
        trim((string) ($user['iso2'] ?? ''))
    );

    $targetCurrency =
        $countryIso === 'KE'
            ? 'KES'
            : 'USD';


    /* ==========================================================
       CURRENCY
       ========================================================== */

    $currencyStmt = $pdo->prepare(
        "
        SELECT
            id,
            code,
            name,
            symbol,
            decimal_places,
            is_active

        FROM currencies

        WHERE code = :code

          AND is_active = 1

        LIMIT 1

        FOR UPDATE
        "
    );

    $currencyStmt->execute([
        ':code' => $targetCurrency
    ]);

    $currency = $currencyStmt->fetch();

    if (!$currency) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'Payment currency is not configured in LOVEMI.',
            [
                'code' => 'CURRENCY_NOT_FOUND',
                'currency' => $targetCurrency
            ],
            500
        );
    }


    /* ==========================================================
       EXCHANGE RATE
       ========================================================== */

    $exchangeRate = 1.0;


    if ($targetCurrency !== 'USD') {

        $rateStmt = $pdo->prepare(
            "
            SELECT
                er.id,
                er.rate,
                er.effective_at

            FROM exchange_rates er

            INNER JOIN currencies base_currency
                ON base_currency.id = er.base_currency_id

            INNER JOIN currencies target_currency
                ON target_currency.id = er.target_currency_id

            WHERE base_currency.code = 'USD'

              AND target_currency.code = :target_currency

              AND er.is_active = 1

            ORDER BY
                er.effective_at DESC,
                er.id DESC

            LIMIT 1

            FOR UPDATE
            "
        );

        $rateStmt->execute([
            ':target_currency' => $targetCurrency
        ]);

        $rateRow = $rateStmt->fetch();

        if (
            !$rateRow
            || !is_numeric($rateRow['rate'])
            || (float) $rateRow['rate'] <= 0
        ) {
            $pdo->rollBack();

            premiumSubscribeResponse(
                false,
                'The current exchange rate is unavailable. Please ask the administrator to run the FX refresh.',
                [
                    'code' => 'EXCHANGE_RATE_UNAVAILABLE',
                    'currency' => $targetCurrency
                ],
                503
            );
        }

        $exchangeRate = (float) $rateRow['rate'];
    }


    /* ==========================================================
       FINAL AMOUNT
       ========================================================== */

    $expectedAmount = $baseAmountUsd * $exchangeRate;


    /*
     * Respect currency decimal places.
     */
    $decimalPlaces = max(
        0,
        min(
            4,
            (int) $currency['decimal_places']
        )
    );

    $expectedAmount = round(
        $expectedAmount,
        $decimalPlaces
    );


    if ($expectedAmount <= 0) {
        $pdo->rollBack();

        premiumSubscribeResponse(
            false,
            'The calculated Premium payment amount is invalid.',
            [
                'code' => 'INVALID_PAYMENT_AMOUNT'
            ],
            500
        );
    }


    /* ==========================================================
       CHECK DUPLICATE PENDING PAYMENT
       ========================================================== */

    /*
     * Prevent the user from repeatedly clicking the button and
     * creating many pending orders for the same Premium service.
     */
    $pendingStmt = $pdo->prepare(
        "
        SELECT
            p.id,
            p.payment_reference,
            p.payment_method,
            p.amount_expected,
            p.currency_id,
            s.id AS subscription_id,
            s.status AS subscription_status

        FROM payments p

        INNER JOIN subscriptions s
            ON s.payment_id = p.id

        WHERE p.user_id = :user_id

          AND p.service_id = :service_id

          AND p.status = 'pending'

          AND s.status = 'pending'

          AND s.end_at IS NULL

        ORDER BY p.created_at DESC, p.id DESC

        LIMIT 1

        FOR UPDATE
        "
    );

    $pendingStmt->execute([
        ':user_id' => $userId,
        ':service_id' => (int) $serviceId
    ]);

    $existingPending = $pendingStmt->fetch();


    /*
     * Reuse an existing pending payment when available.
     */
    if ($existingPending) {

        $paymentId = (int) $existingPending['id'];

        $subscriptionId = (int) $existingPending['subscription_id'];

        $paymentReference =
            (string) $existingPending['payment_reference'];


        /*
         * Make sure the payment access-token table contains a
         * working secure code.
         */
        $accessCode = createSecureCode();

        $accessHash = hash(
            'sha256',
            $accessCode
        );


        $tokenStmt = $pdo->prepare(
            "
            INSERT INTO payment_access_tokens
            (
                payment_id,
                token_hash,
                expires_at
            )
            VALUES
            (
                :payment_id,
                :token_hash,
                DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY)
            )

            ON DUPLICATE KEY UPDATE
                token_hash = VALUES(token_hash),
                expires_at = VALUES(expires_at)
            "
        );

        $tokenStmt->execute([
            ':payment_id' => $paymentId,
            ':token_hash' => $accessHash
        ]);


        /*
         * Refresh the return path.
         */
        $returnStmt = $pdo->prepare(
            "
            INSERT INTO payment_return_routes
            (
                payment_id,
                return_path
            )
            VALUES
            (
                :payment_id,
                :return_path
            )

            ON DUPLICATE KEY UPDATE
                return_path = VALUES(return_path),
                updated_at = CURRENT_TIMESTAMP
            "
        );

        $returnStmt->execute([
            ':payment_id' => $paymentId,
            ':return_path' => $returnPath
        ]);


        $pdo->commit();


        $paymentUrl =
            premiumPaymentPage($paymentMethod)
            . '?code='
            . rawurlencode($accessCode)
            . '&return='
            . rawurlencode($returnPath);


        premiumSubscribeResponse(
            true,
            'Your existing Premium payment is ready. Continue to payment.',
            [
                'status' => 'pending',

                'service_id' =>
                    (int) $service['id'],

                'service_name' =>
                    (string) $service['name'],

                'subscription_id' =>
                    $subscriptionId,

                'payment_id' =>
                    $paymentId,

                'payment_reference' =>
                    $paymentReference,

                'payment_code' =>
                    $accessCode,

                'payment_url' =>
                    $paymentUrl,

                'currency' =>
                    (string) $currency['code'],

                'currency_symbol' =>
                    (string) $currency['symbol'],

                'amount_expected' =>
                    number_format(
                        $expectedAmount,
                        $decimalPlaces,
                        '.',
                        ''
                    ),

                'base_amount_usd' =>
                    number_format(
                        $baseAmountUsd,
                        2,
                        '.',
                        ''
                    ),

                'exchange_rate' =>
                    number_format(
                        $exchangeRate,
                        10,
                        '.',
                        ''
                    ),

                'duration_days' =>
                    $durationDays,

                'return_url' =>
                    $returnPath,

                'reused_pending_payment' =>
                    true
            ],
            200
        );
    }


    /* ==========================================================
       CREATE NEW PAYMENT
       ========================================================== */

    $paymentReference =
        'LVM-'
        . date('YmdHis')
        . '-'
        . $userId
        . '-'
        . strtoupper(
            bin2hex(
                random_bytes(6)
            )
        );


    /*
     * Secure code:
     *
     * Raw code is sent to the authenticated browser.
     * Only SHA-256 is stored in the database.
     */
    $paymentCode = createSecureCode();

    $paymentCodeHash = hash(
        'sha256',
        $paymentCode
    );


    /* ==========================================================
       CREATE PAYMENT
       ========================================================== */

    $paymentStmt = $pdo->prepare(
        "
        INSERT INTO payments
        (
            user_id,
            service_id,
            subscription_id,
            payment_reference,
            gateway,
            gateway_transaction_id,
            payment_method,
            status,
            currency_id,
            base_amount_usd,
            exchange_rate,
            amount_expected,
            amount_paid,
            gateway_fee,
            phone_number,
            checkout_reference,
            paid_at,
            created_at,
            updated_at
        )
        VALUES
        (
            :user_id,
            :service_id,
            NULL,
            :payment_reference,
            :gateway,
            NULL,
            :payment_method,
            'pending',
            :currency_id,
            :base_amount_usd,
            :exchange_rate,
            :amount_expected,
            0,
            0,
            NULL,
            NULL,
            NULL,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        "
    );


    /*
     * For now gateway and payment method use the same provider
     * value. Provider-specific initiate APIs can update the gateway
     * later when the real external checkout is started.
     */
    $paymentStmt->execute([
        ':user_id' =>
            $userId,

        ':service_id' =>
            (int) $service['id'],

        ':payment_reference' =>
            $paymentReference,

        ':gateway' =>
            $paymentMethod,

        ':payment_method' =>
            $paymentMethod,

        ':currency_id' =>
            (int) $currency['id'],

        ':base_amount_usd' =>
            $baseAmountUsd,

        ':exchange_rate' =>
            $exchangeRate,

        ':amount_expected' =>
            $expectedAmount
    ]);


    $paymentId = (int) $pdo->lastInsertId();


    /* ==========================================================
       CREATE PENDING SUBSCRIPTION
       ========================================================== */

    $usageLimit = null;

    if (
        $service['max_usage'] !== null
        && $service['max_usage'] !== ''
    ) {
        $usageLimit = max(
            0,
            (int) $service['max_usage']
        );
    }


    $subscriptionStmt = $pdo->prepare(
        "
        INSERT INTO subscriptions
        (
            user_id,
            service_id,
            status,
            start_at,
            end_at,
            base_amount_usd,
            amount_paid,
            currency_id,
            exchange_rate,
            payment_id,
            usage_limit,
            usage_used,
            created_at,
            updated_at
        )
        VALUES
        (
            :user_id,
            :service_id,
            'pending',
            NULL,
            NULL,
            :base_amount_usd,
            0,
            :currency_id,
            :exchange_rate,
            :payment_id,
            :usage_limit,
            0,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        "
    );


    $subscriptionStmt->execute([
        ':user_id' =>
            $userId,

        ':service_id' =>
            (int) $service['id'],

        ':base_amount_usd' =>
            $baseAmountUsd,

        ':currency_id' =>
            (int) $currency['id'],

        ':exchange_rate' =>
            $exchangeRate,

        ':payment_id' =>
            $paymentId,

        ':usage_limit' =>
            $usageLimit
    ]);


    $subscriptionId = (int) $pdo->lastInsertId();


    /* ==========================================================
       CONNECT PAYMENT TO SUBSCRIPTION
       ========================================================== */

    $linkPaymentStmt = $pdo->prepare(
        "
        UPDATE payments

        SET
            subscription_id = :subscription_id,
            updated_at = CURRENT_TIMESTAMP

        WHERE id = :payment_id

        LIMIT 1
        "
    );

    $linkPaymentStmt->execute([
        ':subscription_id' =>
            $subscriptionId,

        ':payment_id' =>
            $paymentId
    ]);


    /* ==========================================================
       SECURE PAYMENT ACCESS TOKEN
       ========================================================== */

    $accessTokenStmt = $pdo->prepare(
        "
        INSERT INTO payment_access_tokens
        (
            payment_id,
            token_hash,
            expires_at
        )
        VALUES
        (
            :payment_id,
            :token_hash,
            DATE_ADD(CURRENT_TIMESTAMP, INTERVAL 7 DAY)
        )
        "
    );

    $accessTokenStmt->execute([
        ':payment_id' =>
            $paymentId,

        ':token_hash' =>
            $paymentCodeHash
    ]);


    /* ==========================================================
       RETURN ROUTE
       ========================================================== */

    $returnRouteStmt = $pdo->prepare(
        "
        INSERT INTO payment_return_routes
        (
            payment_id,
            return_path
        )
        VALUES
        (
            :payment_id,
            :return_path
        )

        ON DUPLICATE KEY UPDATE
            return_path = VALUES(return_path),
            updated_at = CURRENT_TIMESTAMP
        "
    );

    $returnRouteStmt->execute([
        ':payment_id' =>
            $paymentId,

        ':return_path' =>
            $returnPath
    ]);


    /* ==========================================================
       COMMIT
       ========================================================== */

    $pdo->commit();


    /* ==========================================================
       PAYMENT PAGE URL
       ========================================================== */

    $paymentUrl =
        premiumPaymentPage($paymentMethod)
        . '?code='
        . rawurlencode($paymentCode)
        . '&return='
        . rawurlencode($returnPath);


    /* ==========================================================
       SUCCESS RESPONSE
       ========================================================== */

    premiumSubscribeResponse(
        true,
        'Your secure Premium payment has been created. Continue to payment.',
        [
            'status' =>
                'pending',

            'service_id' =>
                (int) $service['id'],

            'service_name' =>
                (string) $service['name'],

            'subscription_id' =>
                $subscriptionId,

            'payment_id' =>
                $paymentId,

            'payment_reference' =>
                $paymentReference,

            'payment_code' =>
                $paymentCode,

            'payment_url' =>
                $paymentUrl,

            'currency' =>
                (string) $currency['code'],

            'currency_symbol' =>
                (string) $currency['symbol'],

            'amount_expected' =>
                number_format(
                    $expectedAmount,
                    $decimalPlaces,
                    '.',
                    ''
                ),

            'base_amount_usd' =>
                number_format(
                    $baseAmountUsd,
                    2,
                    '.',
                    ''
                ),

            'exchange_rate' =>
                number_format(
                    $exchangeRate,
                    10,
                    '.',
                    ''
                ),

            'duration_days' =>
                $durationDays,

            'return_url' =>
                $returnPath
        ],
        201
    );

} catch (Throwable $e) {

    /*
     * Roll back any unfinished transaction.
     */
    if (
        isset($pdo)
        && $pdo instanceof PDO
        && $pdo->inTransaction()
    ) {
        try {
            $pdo->rollBack();
        } catch (Throwable $rollbackError) {
            error_log(
                '[LOVEMI PREMIUM SUBSCRIBE ROLLBACK] '
                . $rollbackError->getMessage()
            );
        }
    }


    /*
     * Log the real server error so it can be diagnosed from the
     * Apache/PHP error log, while keeping sensitive SQL details
     * away from the browser.
     */
    error_log(
        '[LOVEMI PREMIUM SUBSCRIBE] '
        . $e->getMessage()
        . ' | File: '
        . $e->getFile()
        . ' | Line: '
        . $e->getLine()
    );


    premiumSubscribeResponse(
        false,
        'The Premium payment request could not be created.',
        [
            'code' =>
                'SUBSCRIPTION_CREATE_FAILED'
        ],
        500
    );
}