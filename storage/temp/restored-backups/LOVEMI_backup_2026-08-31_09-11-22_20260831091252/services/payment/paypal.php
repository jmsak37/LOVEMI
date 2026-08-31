<?php
/**
 * ============================================================
 * LOVEMI - PAYPAL PAYMENT SERVICE
 * ============================================================
 *
 * PayPal Orders API adapter.
 *
 * Environment:
 *
 *   PAYPAL_CLIENT_ID
 *   PAYPAL_CLIENT_SECRET
 *   PAYPAL_BASE_URL
 *   PAYPAL_RETURN_URL
 *   PAYPAL_CANCEL_URL
 *
 * Sandbox:
 *   https://api-m.sandbox.paypal.com
 *
 * Production:
 *   https://api-m.paypal.com
 *
 * ============================================================
 */

declare(strict_types=1);


require_once
    __DIR__
    .
    DIRECTORY_SEPARATOR
    .
    'payment-gateway.php';


final class PaypalGateway
    implements PaymentGatewayInterface
{

    private string $clientId;

    private string $clientSecret;

    private string $baseUrl;

    private string $returnUrl;

    private string $cancelUrl;


    public function __construct()
    {

        $this->clientId =
            paymentEnv(
                'PAYPAL_CLIENT_ID'
            );


        $this->clientSecret =
            paymentEnv(
                'PAYPAL_CLIENT_SECRET'
            );


        $this->baseUrl =
            paymentEnv(
                'PAYPAL_BASE_URL',
                'https://api-m.sandbox.paypal.com'
            );


        $this->returnUrl =
            paymentEnv(
                'PAYPAL_RETURN_URL'
            );


        $this->cancelUrl =
            paymentEnv(
                'PAYPAL_CANCEL_URL'
            );

    }


    /* ========================================================
       NAME
    ========================================================= */

    public function name(): string
    {

        return 'paypal';

    }


    /* ========================================================
       CONFIGURED
    ========================================================= */

    public function isConfigured(): bool
    {

        return
            $this->clientId !== ''
            &&
            $this->clientSecret !== ''
            &&
            $this->returnUrl !== ''
            &&
            $this->cancelUrl !== '';

    }


    /* ========================================================
       ACCESS TOKEN
    ========================================================= */

    private function accessToken(): string
    {

        if (
            !$this->isConfigured()
        ) {

            throw new PaymentGatewayException(
                'PayPal is not fully configured.'
            );

        }


        $credentials =
            base64_encode(
                $this->clientId
                .
                ':'
                .
                $this->clientSecret
            );


        $url =
            paymentJoinUrl(
                $this->baseUrl,
                'v1/oauth2/token'
            );


        $response =
            paymentHttpRequest(
                $url,
                'POST',
                [

                    'Authorization: Basic '
                    .
                    $credentials,

                    'Accept: application/json',

                    'Content-Type: application/x-www-form-urlencoded'

                ],
                'grant_type=client_credentials',
                30
            );


        if (
            $response['http_code'] < 200
            ||
            $response['http_code'] >= 300
        ) {

            throw new PaymentGatewayException(
                'PayPal authentication failed.'
            );

        }


        $json =
            $response['json']
            ??
            paymentJsonDecode(
                $response['body']
            );


        $token =
            trim(
                (string)
                (
                    $json['access_token']
                    ??
                    ''
                )
            );


        if (
            $token === ''
        ) {

            throw new PaymentGatewayException(
                'PayPal access token was not returned.'
            );

        }


        return $token;

    }


    /* ========================================================
       INITIATE ORDER
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

                'PayPal is not configured on the server.'

            );

        }


        /*
         * PayPal can process several currencies, but our
         * Premium amount must come from the LOVEMI database.
         */

        $currency =
            strtoupper(
                $order->currencyCode
            );


        if (
            !preg_match(
                '/^[A-Z]{3}$/',
                $currency
            )
        ) {

            return new PaymentGatewayResult(

                false,

                'invalid_currency',

                'The PayPal currency code is invalid.'

            );

        }


        /*
         * PayPal order amount normally requires two decimal
         * places.
         */

        $amount =
            number_format(
                $order->amountExpected,
                2,
                '.',
                ''
            );


        try {

            $token =
                $this->accessToken();


            $payload = [

                'intent' =>
                    'CAPTURE',

                'purchase_units' => [

                    [

                        'reference_id' =>
                            (string)
                            $order->paymentReference,

                        'description' =>
                            paymentDescription(
                                $order
                            ),

                        'amount' => [

                            'currency_code' =>
                                $currency,

                            'value' =>
                                $amount

                        ]

                    ]

                ],

                'application_context' => [

                    'brand_name' =>
                        'LOVEMI',

                    'landing_page' =>
                        'LOGIN',

                    'user_action' =>
                        'PAY_NOW',

                    'return_url' =>
                        $this->appendQuery(
                            $this->returnUrl,
                            [
                                'payment_id' =>
                                    $order->paymentId
                            ]
                        ),

                    'cancel_url' =>
                        $this->appendQuery(
                            $this->cancelUrl,
                            [
                                'payment_id' =>
                                    $order->paymentId
                            ]
                        )

                ]

            ];


            $url =
                paymentJoinUrl(
                    $this->baseUrl,
                    'v2/checkout/orders'
                );


            $response =
                paymentJsonRequest(
                    $url,
                    'POST',
                    [

                        'Authorization: Bearer '
                        .
                        $token,

                        'PayPal-Request-Id: '
                        .
                        $order->paymentReference

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

                    'PayPal could not create the payment order.',

                    null,
                    null,
                    null,

                    [
                        'provider_http_code' =>
                            $response['http_code'],

                        'provider_response' =>
                            $json
                    ]

                );

            }


            $orderId =
                trim(
                    (string)
                    (
                        $json['id']
                        ??
                        ''
                    )
                );


            if (
                $orderId === ''
            ) {

                return new PaymentGatewayResult(

                    false,

                    'invalid_provider_response',

                    'PayPal did not return an order ID.'

                );

            }


            $approvalUrl =
                '';


            $links =
                $json['links']
                ??
                [];


            if (
                is_array(
                    $links
                )
            ) {

                foreach (
                    $links as $link
                ) {

                    if (
                        !is_array(
                            $link
                        )
                    ) {

                        continue;

                    }


                    if (
                        ($link['rel'] ?? '')
                        ===
                        'approve'
                    ) {

                        $approvalUrl =
                            trim(
                                (string)
                                (
                                    $link['href']
                                    ??
                                    ''
                                )
                            );


                        break;

                    }

                }

            }


            if (
                $approvalUrl === ''
            ) {

                return new PaymentGatewayResult(

                    false,

                    'approval_url_missing',

                    'PayPal did not return an approval URL.',

                    $orderId,

                    $orderId

                );

            }


            return new PaymentGatewayResult(

                true,

                'pending',

                'PayPal payment order created.',

                $orderId,

                $orderId,

                $approvalUrl,

                [

                    'paypal_order_id' =>
                        $orderId,

                    'approval_url' =>
                        $approvalUrl

                ]

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI PAYPAL INITIATE] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to contact PayPal.'

            );

        }

    }


    /* ========================================================
       VERIFY / CAPTURE
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

                'PayPal is not configured.'

            );

        }


        $paypalOrderId =
            trim(
                (string)
                (
                    $reference
                    ??
                    ''
                )
            );


        if (
            $paypalOrderId === ''
        ) {

            return new PaymentGatewayResult(

                false,

                'reference_required',

                'PayPal order ID is required.'

            );

        }


        try {

            $token =
                $this->accessToken();


            /*
             * First retrieve the PayPal order.
             */

            $orderUrl =
                paymentJoinUrl(
                    $this->baseUrl,
                    'v2/checkout/orders/'
                    .
                    rawurlencode(
                        $paypalOrderId
                    )
                );


            $orderResponse =
                paymentHttpRequest(
                    $orderUrl,
                    'GET',
                    [

                        'Authorization: Bearer '
                        .
                        $token,

                        'Accept: application/json'

                    ],
                    null,
                    30
                );


            $paypalOrder =
                $orderResponse['json']
                ??
                paymentJsonDecode(
                    $orderResponse['body']
                );


            if (
                $orderResponse['http_code'] < 200
                ||
                $orderResponse['http_code'] >= 300
            ) {

                return new PaymentGatewayResult(

                    false,

                    'provider_error',

                    'Unable to retrieve PayPal order status.',

                    $paypalOrderId,

                    $paypalOrderId

                );

            }


            $status =
                strtoupper(
                    trim(
                        (string)
                        (
                            $paypalOrder['status']
                            ??
                            ''
                        )
                    )
                );


            /*
             * Capture an approved order.
             *
             * This must be done only for the specific order that
             * belongs to the user's LOVEMI payment record.
             */

            if (
                $status === 'APPROVED'
            ) {

                $captureUrl =
                    paymentJoinUrl(
                        $this->baseUrl,
                        'v2/checkout/orders/'
                        .
                        rawurlencode(
                            $paypalOrderId
                        )
                        .
                        '/capture'
                    );


                $captureResponse =
                    paymentJsonRequest(
                        $captureUrl,
                        'POST',
                        [

                            'Authorization: Bearer '
                            .
                            $token,

                            'PayPal-Request-Id: '
                            .
                            $order->paymentReference

                        ],
                        [],
                        30
                    );


                $captured =
                    $captureResponse['json']
                    ??
                    paymentJsonDecode(
                        $captureResponse['body']
                    );


                if (
                    $captureResponse['http_code'] < 200
                    ||
                    $captureResponse['http_code'] >= 300
                ) {

                    return new PaymentGatewayResult(

                        false,

                        'capture_failed',

                        'PayPal payment capture failed.',

                        $paypalOrderId,

                        $paypalOrderId,

                        null,

                        [
                            'provider_response' =>
                                $captured
                        ]

                    );

                }


                $captureStatus =
                    strtoupper(
                        trim(
                            (string)
                            (
                                $captured['status']
                                ??
                                ''
                            )
                        )
                    );


                if (
                    $captureStatus ===
                    'COMPLETED'
                ) {

                    $captureId =
                        $this->extractCaptureId(
                            $captured
                        );


                    return new PaymentGatewayResult(

                        true,

                        'paid',

                        'PayPal payment captured successfully.',

                        $captureId
                        ??
                        $paypalOrderId,

                        $paypalOrderId,

                        null,

                        [

                            'paypal_order_id' =>
                                $paypalOrderId,

                            'capture_id' =>
                                $captureId,

                            'paypal_status' =>
                                $captureStatus

                        ]

                    );

                }


                return new PaymentGatewayResult(

                    true,

                    'pending',

                    'PayPal payment is awaiting completion.',

                    null,

                    $paypalOrderId

                );

            }


            if (
                $status === 'COMPLETED'
            ) {

                $captureId =
                    $this->extractCaptureId(
                        $paypalOrder
                    );


                return new PaymentGatewayResult(

                    true,

                    'paid',

                    'PayPal payment is completed.',

                    $captureId
                    ??
                    $paypalOrderId,

                    $paypalOrderId

                );

            }


            if (
                in_array(
                    $status,
                    [
                        'VOIDED',
                        'DECLINED'
                    ],
                    true
                )
            ) {

                return new PaymentGatewayResult(

                    true,

                    'failed',

                    'PayPal payment was not completed.',

                    null,

                    $paypalOrderId

                );

            }


            return new PaymentGatewayResult(

                true,

                'pending',

                'PayPal payment is awaiting confirmation.',

                null,

                $paypalOrderId

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI PAYPAL VERIFY] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to verify the PayPal payment.',

                null,

                $paypalOrderId

            );

        }

    }


    /* ========================================================
       CAPTURE ID
    ========================================================= */

    private function extractCaptureId(
        array $paypalResponse
    ): ?string {

        $purchaseUnits =
            $paypalResponse['purchase_units']
            ??
            [];


        if (
            !is_array(
                $purchaseUnits
            )
        ) {

            return null;

        }


        foreach (
            $purchaseUnits
            as $purchaseUnit
        ) {

            if (
                !is_array(
                    $purchaseUnit
                )
            ) {

                continue;

            }


            $payments =
                $purchaseUnit['payments']
                ??
                [];


            if (
                !is_array(
                    $payments
                )
            ) {

                continue;

            }


            $captures =
                $payments['captures']
                ??
                [];


            if (
                !is_array(
                    $captures
                )
            ) {

                continue;

            }


            foreach (
                $captures
                as $capture
            ) {

                if (
                    !is_array(
                        $capture
                    )
                ) {

                    continue;

                }


                $id =
                    trim(
                        (string)
                        (
                            $capture['id']
                            ??
                            ''
                        )
                    );


                if (
                    $id !== ''
                ) {

                    return $id;

                }

            }

        }


        return null;
    }


    /* ========================================================
       APPEND QUERY
    ========================================================= */

    private function appendQuery(
        string $url,
        array $params
    ): string {

        $separator =
            str_contains(
                $url,
                '?'
            )
                ?
                '&'
                :
                '?';


        return
            $url
            .
            $separator
            .
            http_build_query(
                $params
            );

    }

}