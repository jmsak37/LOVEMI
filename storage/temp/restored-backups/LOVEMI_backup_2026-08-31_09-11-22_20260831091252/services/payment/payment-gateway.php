<?php
/**
 * ============================================================
 * LOVEMI PAYMENT GATEWAY CORE
 * ============================================================
 *
 * Common payment-gateway utilities used by:
 *
 *     mpesa.php
 *     card.php
 *     paypal.php
 *
 * This file does NOT:
 *     - activate Premium
 *     - mark payments as paid
 *     - trust browser amounts
 *     - store raw card numbers
 *
 * Those decisions belong to the payment APIs/database.
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   GENERIC GATEWAY EXCEPTION
============================================================ */

class PaymentGatewayException extends RuntimeException
{
}


/* ============================================================
   GENERIC RESULT OBJECT
============================================================ */

final class PaymentGatewayResult
{
    public bool $success;

    public string $status;

    public string $message;

    public ?string $transactionId;

    public ?string $checkoutReference;

    public ?string $redirectUrl;

    public array $raw;

    public function __construct(
        bool $success,
        string $status,
        string $message = '',
        ?string $transactionId = null,
        ?string $checkoutReference = null,
        ?string $redirectUrl = null,
        array $raw = []
    ) {

        $this->success =
            $success;

        $this->status =
            $status;

        $this->message =
            $message;

        $this->transactionId =
            $transactionId;

        $this->checkoutReference =
            $checkoutReference;

        $this->redirectUrl =
            $redirectUrl;

        $this->raw =
            $raw;
    }


    public function toArray(): array
    {
        return [

            'success' =>
                $this->success,

            'status' =>
                $this->status,

            'message' =>
                $this->message,

            'transaction_id' =>
                $this->transactionId,

            'checkout_reference' =>
                $this->checkoutReference,

            'redirect_url' =>
                $this->redirectUrl,

            'raw' =>
                $this->raw

        ];
    }
}


/* ============================================================
   PAYMENT ORDER DATA
============================================================ */

final class PaymentOrder
{
    public int $paymentId;

    public int $userId;

    public int $serviceId;

    public string $paymentReference;

    public string $currencyCode;

    public float $amountExpected;

    public float $baseAmountUsd;

    public float $exchangeRate;

    public string $paymentMethod;

    public ?string $phoneNumber;

    public ?string $description;

    public function __construct(
        int $paymentId,
        int $userId,
        int $serviceId,
        string $paymentReference,
        string $currencyCode,
        float $amountExpected,
        float $baseAmountUsd,
        float $exchangeRate,
        string $paymentMethod,
        ?string $phoneNumber = null,
        ?string $description = null
    ) {

        $this->paymentId =
            $paymentId;

        $this->userId =
            $userId;

        $this->serviceId =
            $serviceId;

        $this->paymentReference =
            $paymentReference;

        $this->currencyCode =
            strtoupper(
                trim(
                    $currencyCode
                )
            );

        $this->amountExpected =
            $amountExpected;

        $this->baseAmountUsd =
            $baseAmountUsd;

        $this->exchangeRate =
            $exchangeRate;

        $this->paymentMethod =
            strtolower(
                trim(
                    $paymentMethod
                )
            );

        $this->phoneNumber =
            $phoneNumber !== null
                ?
                trim(
                    $phoneNumber
                )
                :
                null;

        $this->description =
            $description;
    }


    public function amountAsMinorUnit(
        int $decimalPlaces = 2
    ): int {

        return (int)
            round(
                $this->amountExpected
                *
                (10 ** $decimalPlaces)
            );
    }


    public function toArray(): array
    {
        return [

            'payment_id' =>
                $this->paymentId,

            'user_id' =>
                $this->userId,

            'service_id' =>
                $this->serviceId,

            'payment_reference' =>
                $this->paymentReference,

            'currency_code' =>
                $this->currencyCode,

            'amount_expected' =>
                $this->amountExpected,

            'base_amount_usd' =>
                $this->baseAmountUsd,

            'exchange_rate' =>
                $this->exchangeRate,

            'payment_method' =>
                $this->paymentMethod,

            'phone_number' =>
                $this->phoneNumber,

            'description' =>
                $this->description

        ];
    }
}


/* ============================================================
   GATEWAY INTERFACE
============================================================ */

interface PaymentGatewayInterface
{
    public function name(): string;

    public function isConfigured(): bool;

    public function initiate(
        PaymentOrder $order
    ): PaymentGatewayResult;

    public function verify(
        PaymentOrder $order,
        ?string $reference = null
    ): PaymentGatewayResult;
}


/* ============================================================
   ENVIRONMENT VALUE
============================================================ */

function paymentEnv(
    string $name,
    string $default = ''
): string {

    $value =
        getenv(
            $name
        );


    if (
        $value === false
    ) {

        return $default;

    }


    return trim(
        (string)
        $value
    );
}


/* ============================================================
   BOOLEAN ENV
============================================================ */

function paymentEnvBool(
    string $name,
    bool $default = false
): bool {

    $value =
        paymentEnv(
            $name
        );


    if (
        $value === ''
    ) {

        return $default;

    }


    return in_array(
        strtolower(
            $value
        ),
        [
            '1',
            'true',
            'yes',
            'on'
        ],
        true
    );
}


/* ============================================================
   CURL REQUEST
============================================================ */

function paymentHttpRequest(
    string $url,
    string $method = 'GET',
    ?array $headers = null,
    mixed $body = null,
    int $timeout = 30
): array {

    $method =
        strtoupper(
            trim(
                $method
            )
        );


    $ch =
        curl_init(
            $url
        );


    if (
        $ch === false
    ) {

        throw new PaymentGatewayException(
            'Unable to initialize HTTP client.'
        );

    }


    $curlHeaders =
        $headers
        ??
        [];


    $options = [

        CURLOPT_RETURNTRANSFER =>
            true,

        CURLOPT_FOLLOWLOCATION =>
            false,

        CURLOPT_MAXREDIRS =>
            0,

        CURLOPT_CONNECTTIMEOUT =>
            10,

        CURLOPT_TIMEOUT =>
            max(
                5,
                $timeout
            ),

        CURLOPT_CUSTOMREQUEST =>
            $method,

        CURLOPT_HTTPHEADER =>
            $curlHeaders,

        CURLOPT_HEADER =>
            false,

        CURLOPT_SSL_VERIFYPEER =>
            true,

        CURLOPT_SSL_VERIFYHOST =>
            2

    ];


    if (
        $body !== null
    ) {

        if (
            is_array($body)
        ) {

            $body =
                json_encode(
                    $body,
                    JSON_UNESCAPED_UNICODE |
                    JSON_UNESCAPED_SLASHES |
                    JSON_THROW_ON_ERROR
                );

        }


        $options[
            CURLOPT_POSTFIELDS
        ] =
            $body;

    }


    curl_setopt_array(
        $ch,
        $options
    );


    $responseBody =
        curl_exec(
            $ch
        );


    $curlError =
        curl_error(
            $ch
        );


    $httpCode =
        (int)
        curl_getinfo(
            $ch,
            CURLINFO_HTTP_CODE
        );


    $contentType =
        (string)
        (
            curl_getinfo(
                $ch,
                CURLINFO_CONTENT_TYPE
            )
            ??
            ''
        );


    curl_close(
        $ch
    );


    if (
        $responseBody === false
    ) {

        throw new PaymentGatewayException(
            'Gateway connection failed.'
            .
            (
                $curlError !== ''
                    ?
                    ' ' . $curlError
                    :
                    ''
            )
        );

    }


    $decoded =
        null;


    if (
        str_contains(
            strtolower(
                $contentType
            ),
            'json'
        )
    ) {

        $decoded =
            json_decode(
                (string)
                $responseBody,
                true
            );

    } else {

        /*
         * Some providers return JSON without declaring
         * application/json correctly.
         */

        $decoded =
            json_decode(
                (string)
                $responseBody,
                true
            );

    }


    return [

        'http_code' =>
            $httpCode,

        'content_type' =>
            $contentType,

        'body' =>
            (string)
            $responseBody,

        'json' =>
            is_array(
                $decoded
            )
                ?
                $decoded
                :
                null

    ];
}


/* ============================================================
   JSON REQUEST
============================================================ */

function paymentJsonRequest(
    string $url,
    string $method,
    array $headers = [],
    array $body = [],
    int $timeout = 30
): array {

    $headers[] =
        'Content-Type: application/json';


    $headers[] =
        'Accept: application/json';


    return paymentHttpRequest(
        $url,
        $method,
        $headers,
        $body,
        $timeout
    );
}


/* ============================================================
   URL
============================================================ */

function paymentJoinUrl(
    string $base,
    string $path
): string {

    return rtrim(
        $base,
        '/'
    )
    .
    '/'
    .
    ltrim(
        $path,
        '/'
    );
}


/* ============================================================
   SAFE JSON
============================================================ */

function paymentJsonDecode(
    string $body
): array {

    $decoded =
        json_decode(
            $body,
            true
        );


    if (
        !is_array(
            $decoded
        )
    ) {

        return [];

    }


    return $decoded;
}


/* ============================================================
   MASK SECRET / PRIVATE VALUE
============================================================ */

function paymentMask(
    ?string $value,
    int $visibleEnd = 4
): string {

    if (
        $value === null
        ||
        $value === ''
    ) {

        return '';

    }


    $length =
        strlen(
            $value
        );


    if (
        $length <=
        $visibleEnd
    ) {

        return str_repeat(
            '*',
            $length
        );

    }


    return str_repeat(
        '*',
        max(
            4,
            $length -
            $visibleEnd
        )
    )
    .
    substr(
        $value,
        -$visibleEnd
    );
}


/* ============================================================
   NORMALIZE PHONE
============================================================ */

function paymentNormalizePhone(
    string $phone,
    string $defaultCountryCode = '254'
): string {

    $phone =
        trim(
            $phone
        );


    $phone =
        preg_replace(
            '/[^0-9+]/',
            '',
            $phone
        );


    if (
        !is_string($phone)
    ) {

        return '';

    }


    if (
        str_starts_with(
            $phone,
            '+'
        )
    ) {

        return ltrim(
            $phone,
            '+'
        );

    }


    if (
        str_starts_with(
            $phone,
            '0'
        )
    ) {

        return
            $defaultCountryCode
            .
            substr(
                $phone,
                1
            );

    }


    if (
        str_starts_with(
            $phone,
            $defaultCountryCode
        )
    ) {

        return $phone;

    }


    return
        $defaultCountryCode
        .
        $phone;
}


/* ============================================================
   UUID-LIKE REFERENCE
============================================================ */

function paymentRandomReference(
    string $prefix = 'LVM'
): string {

    try {

        $random =
            strtoupper(
                bin2hex(
                    random_bytes(
                        6
                    )
                )
            );

    } catch (
        Throwable $e
    ) {

        $random =
            strtoupper(
                dechex(
                    random_int(
                        100000000,
                        999999999
                    )
                )
            );

    }


    return
        strtoupper(
            trim(
                $prefix
            )
        )
        .
        '-'
        .
        date('YmdHis')
        .
        '-'
        .
        $random;
}


/* ============================================================
   GATEWAY AVAILABILITY
============================================================ */

function paymentGatewayAvailable(
    string $gateway
): bool {

    $gateway =
        strtolower(
            trim(
                $gateway
            )
        );


    return match (
        $gateway
    ) {

        'mpesa' =>
            paymentEnv('MPESA_CONSUMER_KEY') !== ''
            &&
            paymentEnv('MPESA_CONSUMER_SECRET') !== ''
            &&
            paymentEnv('MPESA_SHORTCODE') !== ''
            &&
            paymentEnv('MPESA_PASSKEY') !== ''
            &&
            paymentEnv('MPESA_CALLBACK_URL') !== ''
            &&
            paymentEnv('MPESA_CALLBACK_SECRET') !== '',

        'card' =>
            paymentEnv('CARD_PROVIDER_URL') !== ''
            &&
            paymentEnv('CARD_PUBLIC_KEY') !== '',

        'paypal' =>
            paymentEnv('PAYPAL_CLIENT_ID') !== ''
            &&
            paymentEnv('PAYPAL_CLIENT_SECRET') !== '',

        default =>
            false

    };
}


/* ============================================================
   DEFAULT DESCRIPTION
============================================================ */

function paymentDescription(
    PaymentOrder $order
): string {

    if (
        $order->description !== null
        &&
        trim(
            $order->description
        ) !== ''
    ) {

        return trim(
            $order->description
        );

    }


    return
        'LOVEMI Premium - '
        .
        $order->paymentReference;
}