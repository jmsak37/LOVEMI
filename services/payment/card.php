<?php
/**
 * ============================================================
 * LOVEMI - CARD PAYMENT SERVICE
 * ============================================================
 *
 * Generic hosted-card-payment adapter.
 *
 * SECURITY:
 *   LOVEMI NEVER stores:
 *
 *       - full card number
 *       - CVV
 *       - PIN
 *       - card security code
 *
 * The card provider must host the payment form or provide
 * a tokenization mechanism.
 *
 * Configure your selected provider with:
 *
 *   CARD_PROVIDER_URL
 *   CARD_PUBLIC_KEY
 *   CARD_SECRET_KEY
 *   CARD_RETURN_URL
 *   CARD_WEBHOOK_URL
 *
 * Provider-specific request formatting can be adapted inside
 * buildProviderPayload().
 * ============================================================
 */

declare(strict_types=1);


require_once
    __DIR__
    .
    DIRECTORY_SEPARATOR
    .
    'payment-gateway.php';


final class CardGateway
    implements PaymentGatewayInterface
{

    private string $providerUrl;

    private string $publicKey;

    private string $secretKey;

    private string $returnUrl;

    private string $webhookUrl;


    public function __construct()
    {

        $this->providerUrl =
            paymentEnv(
                'CARD_PROVIDER_URL'
            );


        $this->publicKey =
            paymentEnv(
                'CARD_PUBLIC_KEY'
            );


        $this->secretKey =
            paymentEnv(
                'CARD_SECRET_KEY'
            );


        $this->returnUrl =
            paymentEnv(
                'CARD_RETURN_URL'
            );


        $this->webhookUrl =
            paymentEnv(
                'CARD_WEBHOOK_URL'
            );

    }


    /* ========================================================
       NAME
    ========================================================= */

    public function name(): string
    {

        return 'card';

    }


    /* ========================================================
       CONFIGURED
    ========================================================= */

    public function isConfigured(): bool
    {

        return
            $this->providerUrl !== ''
            &&
            $this->publicKey !== ''
            &&
            $this->secretKey !== ''
            &&
            $this->returnUrl !== ''
            &&
            $this->webhookUrl !== '';

    }


    /* ========================================================
       PROVIDER PAYLOAD
    ========================================================= */

    private function buildProviderPayload(
        PaymentOrder $order
    ): array {

        /*
         * Generic hosted-checkout structure.
         *
         * Change only this adapter when choosing a specific
         * provider. The rest of LOVEMI does not need to change.
         */

        return [

            'reference' =>
                $order->paymentReference,

            'amount' =>
                $order->amountExpected,

            'currency' =>
                $order->currencyCode,

            'description' =>
                paymentDescription(
                    $order
                ),

            'return_url' =>
                $this->returnUrl
                .
                (
                    str_contains(
                        $this->returnUrl,
                        '?'
                    )
                        ?
                        '&'
                        :
                        '?'
                )
                .
                'payment_id='
                .
                rawurlencode(
                    (string)
                    $order->paymentId
                ),

            'webhook_url' =>
                $this->webhookUrl,

            'metadata' => [

                'lovemi_payment_id' =>
                    $order->paymentId,

                'lovemi_user_id' =>
                    $order->userId,

                'lovemi_service_id' =>
                    $order->serviceId

            ]

        ];

    }


    /* ========================================================
       INITIATE
    ========================================================= */

    public function initiate(
        PaymentOrder $order
    ): PaymentGatewayResult
    {

        if (
            !$this->isConfigured()
        ) {

            return new PaymentGatewayResult(

                false,

                'not_configured',

                'Card payment gateway is not configured.'

            );

        }


        if (
            $order->amountExpected <= 0
        ) {

            return new PaymentGatewayResult(

                false,

                'invalid_amount',

                'Card payment amount is invalid.'

            );

        }


        /*
         * Create provider checkout request.
         */

        try {

            $payload =
                $this->buildProviderPayload(
                    $order
                );


            $response =
                paymentJsonRequest(
                    $this->providerUrl,
                    'POST',
                    [

                        'Authorization: Bearer '
                        .
                        $this->secretKey

                    ],
                    $payload,
                    30
                );


            $json =
                $response['json']
                ??
                paymentJsonDecode(
                    $response['body']
                );


            if (
                $response['http_code'] < 200
                ||
                $response['http_code'] >= 300
            ) {

                return new PaymentGatewayResult(

                    false,

                    'provider_error',

                    (string)
                    (
                        $json['message']
                        ??
                        $json['error']
                        ??
                        'The card payment provider rejected the request.'
                    ),

                    null,
                    null,
                    null,
                    [
                        'provider_http_code' =>
                            $response['http_code']
                    ]

                );

            }


            /*
             * Generic provider response fields.
             *
             * Different providers use different names, so
             * support several common names.
             */

            $checkoutId =
                trim(
                    (string)
                    (
                        $json['checkout_id']
                        ??
                        $json['checkout_reference']
                        ??
                        $json['reference']
                        ??
                        $json['id']
                        ??
                        ''
                    )
                );


            $redirectUrl =
                trim(
                    (string)
                    (
                        $json['checkout_url']
                        ??
                        $json['payment_url']
                        ??
                        $json['redirect_url']
                        ??
                        ''
                    )
                );


            if (
                $redirectUrl === ''
            ) {

                return new PaymentGatewayResult(

                    false,

                    'invalid_provider_response',

                    'The card provider did not return a hosted payment URL.',

                    null,

                    $checkoutId !== ''
                        ?
                        $checkoutId
                        :
                        null,

                    null,

                    [
                        'provider_response' =>
                            $json
                    ]

                );

            }


            return new PaymentGatewayResult(

                true,

                'pending',

                'Secure card payment page created.',

                null,

                $checkoutId !== ''
                    ?
                    $checkoutId
                    :
                    null,

                $redirectUrl,

                [
                    'provider_response' =>
                        [
                            'status' =>
                                $json['status']
                                ??
                                null
                        ]

                ]

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI CARD INITIATE] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to contact the card payment provider.'

            );

        }

    }


    /* ========================================================
       VERIFY
    ========================================================= */

    public function verify(
        PaymentOrder $order,
        ?string $reference = null
    ): PaymentGatewayResult
    {

        if (
            !$this->isConfigured()
        ) {

            return new PaymentGatewayResult(

                false,

                'not_configured',

                'Card payment gateway is not configured.'

            );

        }


        if (
            !$reference
        ) {

            return new PaymentGatewayResult(

                false,

                'reference_required',

                'Card payment reference is required.'

            );

        }


        /*
         * Generic status endpoint:
         *
         * CARD_PROVIDER_URL/{reference}
         *
         * Adjust this path inside this adapter for the exact
         * provider chosen by the project.
         */

        $url =
            paymentJoinUrl(
                $this->providerUrl,
                rawurlencode(
                    $reference
                )
            );


        try {

            $response =
                paymentHttpRequest(
                    $url,
                    'GET',
                    [

                        'Authorization: Bearer '
                        .
                        $this->secretKey,

                        'Accept: application/json'

                    ],
                    null,
                    30
                );


            $json =
                $response['json']
                ??
                paymentJsonDecode(
                    $response['body']
                );


            if (
                $response['http_code'] < 200
                ||
                $response['http_code'] >= 300
            ) {

                return new PaymentGatewayResult(

                    false,

                    'provider_error',

                    'Unable to verify the card transaction.',

                    null,

                    $reference,

                    null,

                    [
                        'provider_http_code' =>
                            $response['http_code']
                    ]

                );

            }


            $providerStatus =
                strtolower(
                    trim(
                        (string)
                        (
                            $json['status']
                            ??
                            ''
                        )
                    )
                );


            if (
                in_array(
                    $providerStatus,
                    [
                        'paid',
                        'success',
                        'successful',
                        'completed',
                        'succeeded'
                    ],
                    true
                )
            ) {

                return new PaymentGatewayResult(

                    true,

                    'paid',

                    'Card payment verified.',

                    (string)
                    (
                        $json['transaction_id']
                        ??
                        $json['id']
                        ??
                        $reference
                    ),

                    $reference,

                    null,

                    [
                        'provider_status' =>
                            $providerStatus

                    ]

                );

            }


            if (
                in_array(
                    $providerStatus,
                    [
                        'failed',
                        'cancelled',
                        'canceled',
                        'declined'
                    ],
                    true
                )
            ) {

                return new PaymentGatewayResult(

                    true,

                    'failed',

                    'Card payment was not completed.',

                    null,

                    $reference,

                    null,

                    [
                        'provider_status' =>
                            $providerStatus
                    ]

                );

            }


            return new PaymentGatewayResult(

                true,

                'pending',

                'Card payment is awaiting confirmation.',

                null,

                $reference,

                null,

                [
                    'provider_status' =>
                        $providerStatus

                ]

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI CARD VERIFY] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to verify the card payment.',

                null,

                $reference

            );

        }

    }

}