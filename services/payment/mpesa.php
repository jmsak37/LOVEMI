<?php
/**
 * ============================================================
 * LOVEMI - M-PESA PAYMENT SERVICE
 * ============================================================
 *
 * Safaricom Daraja integration.
 *
 * Responsibilities:
 *     - obtain OAuth token
 *     - create STK Push
 *     - query STK Push status
 *
 * Does NOT:
 *     - activate Premium directly
 *     - modify payment database records
 *     - trust client amount
 *
 * Database updates belong in api/payments/*.php.
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


final class MpesaGateway
    implements PaymentGatewayInterface
{

    private string $consumerKey;

    private string $consumerSecret;

    private string $shortCode;

    private string $passKey;

    private string $baseUrl;

    private string $callbackUrl;

    private string $callbackSecret;


    public function __construct()
    {

        $this->consumerKey =
            paymentEnv(
                'MPESA_CONSUMER_KEY'
            );


        $this->consumerSecret =
            paymentEnv(
                'MPESA_CONSUMER_SECRET'
            );


        $this->shortCode =
            paymentEnv(
                'MPESA_SHORTCODE'
            );


        $this->passKey =
            paymentEnv(
                'MPESA_PASSKEY'
            );


        $this->baseUrl =
            paymentEnv(
                'MPESA_BASE_URL',
                'https://sandbox.safaricom.co.ke'
            );


        $this->callbackUrl =
            paymentEnv(
                'MPESA_CALLBACK_URL'
            );


        $this->callbackSecret =
            paymentEnv(
                'MPESA_CALLBACK_SECRET'
            );

    }


    /* ========================================================
       NAME
    ========================================================= */

    public function name(): string
    {

        return 'mpesa';

    }


    /* ========================================================
       CONFIGURED
    ========================================================= */

    public function isConfigured(): bool
    {

        return
            $this->consumerKey !== ''
            &&
            $this->consumerSecret !== ''
            &&
            $this->shortCode !== ''
            &&
            $this->passKey !== ''
            &&
            $this->callbackUrl !== ''
            &&
            $this->callbackSecret !== '';

    }


    /* ========================================================
       GET ACCESS TOKEN
    ========================================================= */

    private function accessToken(): string
    {

        if (
            !$this->isConfigured()
        ) {

            throw new PaymentGatewayException(
                'M-Pesa is not fully configured.'
            );

        }


        $credentials =
            base64_encode(
                $this->consumerKey
                .
                ':'
                .
                $this->consumerSecret
            );


        $url =
            paymentJoinUrl(
                $this->baseUrl,
                'oauth/v1/generate'
            )
            .
            '?grant_type=client_credentials';


        $response =
            paymentHttpRequest(
                $url,
                'GET',
                [

                    'Authorization: Basic '
                    .
                    $credentials,

                    'Accept: application/json'

                ],
                null,
                30
            );


        if (
            $response['http_code'] < 200
            ||
            $response['http_code'] >= 300
        ) {

            throw new PaymentGatewayException(
                'M-Pesa authorization failed.'
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
                'M-Pesa authorization token was not returned.'
            );

        }


        return $token;
    }


    /* ========================================================
       CALLBACK URL
    ========================================================= */

    private function callbackUrl(): string
    {

        $separator =
            str_contains(
                $this->callbackUrl,
                '?'
            )
                ?
                '&'
                :
                '?';


        return
            $this->callbackUrl
            .
            $separator
            .
            'token='
            .
            rawurlencode(
                $this->callbackSecret
            );

    }


    /* ========================================================
       INITIATE STK PUSH
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

                'M-Pesa is not configured on the server.'

            );

        }


        if (
            $order->currencyCode !== 'KES'
        ) {

            return new PaymentGatewayResult(

                false,

                'invalid_currency',

                'M-Pesa payments must be made in KES.'

            );

        }


        if (
            !$order->phoneNumber
        ) {

            return new PaymentGatewayResult(

                false,

                'phone_required',

                'A phone number is required for M-Pesa.'

            );

        }


        $phone =
            paymentNormalizePhone(
                $order->phoneNumber
            );


        if (
            !preg_match(
                '/^2547\d{8}$/',
                $phone
            )
        ) {

            return new PaymentGatewayResult(

                false,

                'invalid_phone',

                'The Kenyan M-Pesa phone number is invalid.'

            );

        }


        $amount =
            (int)
            ceil(
                $order->amountExpected
            );


        if (
            $amount <= 0
        ) {

            return new PaymentGatewayResult(

                false,

                'invalid_amount',

                'The M-Pesa amount is invalid.'

            );

        }


        try {

            $token =
                $this->accessToken();


            $timestamp =
                gmdate(
                    'YmdHis'
                );


            $password =
                base64_encode(
                    $this->shortCode
                    .
                    $this->passKey
                    .
                    $timestamp
                );


            $payload = [

                'BusinessShortCode' =>
                    $this->shortCode,

                'Password' =>
                    $password,

                'Timestamp' =>
                    $timestamp,

                'TransactionType' =>
                    'CustomerPayBillOnline',

                'Amount' =>
                    $amount,

                'PartyA' =>
                    $phone,

                'PartyB' =>
                    $this->shortCode,

                'PhoneNumber' =>
                    $phone,

                'CallBackURL' =>
                    $this->callbackUrl(),

                'AccountReference' =>
                    $order->paymentReference,

                'TransactionDesc' =>
                    paymentDescription(
                        $order
                    )

            ];


            $url =
                paymentJoinUrl(
                    $this->baseUrl,
                    'mpesa/stkpush/v1/processrequest'
                );


            $response =
                paymentJsonRequest(
                    $url,
                    'POST',
                    [

                        'Authorization: Bearer '
                        .
                        $token

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


            $responseCode =
                (string)
                (
                    $json['ResponseCode']
                    ??
                    ''
                );


            if (
                $response['http_code'] < 200
                ||
                $response['http_code'] >= 300
                ||
                $responseCode !== '0'
            ) {

                $message =
                    (string)
                    (
                        $json['errorMessage']
                        ??
                        $json['ResponseDescription']
                        ??
                        'M-Pesa STK Push failed.'
                    );


                return new PaymentGatewayResult(

                    false,

                    'failed',

                    $message,

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


            $checkoutRequestId =
                trim(
                    (string)
                    (
                        $json['CheckoutRequestID']
                        ??
                        ''
                    )
                );


            $merchantRequestId =
                trim(
                    (string)
                    (
                        $json['MerchantRequestID']
                        ??
                        ''
                    )
                );


            if (
                $checkoutRequestId === ''
            ) {

                return new PaymentGatewayResult(

                    false,

                    'invalid_response',

                    'M-Pesa did not return a checkout reference.',

                    null,
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

                (string)
                (
                    $json['CustomerMessage']
                    ??
                    $json['ResponseDescription']
                    ??
                    'M-Pesa payment request sent.'
                ),

                $merchantRequestId !== ''
                    ?
                    $merchantRequestId
                    :
                    null,

                $checkoutRequestId,

                null,

                [

                    'merchant_request_id' =>
                        $merchantRequestId,

                    'checkout_request_id' =>
                        $checkoutRequestId,

                    'response_code' =>
                        $responseCode

                ]

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI MPESA INITIATE] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to contact M-Pesa.'

            );

        }

    }


    /* ========================================================
       VERIFY / QUERY STK
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

                'M-Pesa is not configured.'

            );

        }


        $checkoutRequestId =
            trim(
                (string)
                (
                    $reference
                    ??
                    ''
                )
            );


        if (
            $checkoutRequestId === ''
        ) {

            return new PaymentGatewayResult(

                false,

                'reference_required',

                'The M-Pesa checkout reference is required.'

            );

        }


        try {

            $token =
                $this->accessToken();


            $timestamp =
                gmdate(
                    'YmdHis'
                );


            $password =
                base64_encode(
                    $this->shortCode
                    .
                    $this->passKey
                    .
                    $timestamp
                );


            $payload = [

                'BusinessShortCode' =>
                    $this->shortCode,

                'Password' =>
                    $password,

                'Timestamp' =>
                    $timestamp,

                'CheckoutRequestID' =>
                    $checkoutRequestId

            ];


            $url =
                paymentJoinUrl(
                    $this->baseUrl,
                    'mpesa/stkpushquery/v1/query'
                );


            $response =
                paymentJsonRequest(
                    $url,
                    'POST',
                    [

                        'Authorization: Bearer '
                        .
                        $token

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


            $resultCode =
                (string)
                (
                    $json['ResultCode']
                    ??
                    ''
                );


            $resultDescription =
                (string)
                (
                    $json['ResultDesc']
                    ??
                    ''
                );


            if (
                $response['http_code'] < 200
                ||
                $response['http_code'] >= 300
            ) {

                return new PaymentGatewayResult(

                    false,

                    'provider_error',

                    'M-Pesa status query failed.',

                    null,

                    $checkoutRequestId,

                    null,

                    [
                        'provider_response' =>
                            $json
                    ]

                );

            }


            /*
             * ResultCode 0 means successfully completed.
             */

            if (
                $resultCode === '0'
            ) {

                return new PaymentGatewayResult(

                    true,

                    'paid',

                    $resultDescription
                    !== ''
                        ?
                        $resultDescription
                        :
                        'M-Pesa payment completed.',

                    $checkoutRequestId,

                    $checkoutRequestId,

                    null,

                    [
                        'result_code' =>
                            $resultCode,

                        'result_description' =>
                            $resultDescription

                    ]

                );

            }


            /*
             * A non-zero ResultCode from the query can mean
             * cancelled, insufficient funds, timeout, etc.
             *
             * We return the provider result without changing
             * the LOVEMI database ourselves.
             */

            return new PaymentGatewayResult(

                true,

                'pending',

                $resultDescription
                !== ''
                    ?
                    $resultDescription
                    :
                    'M-Pesa payment is not yet confirmed.',

                null,

                $checkoutRequestId,

                null,

                [
                    'result_code' =>
                        $resultCode,

                    'result_description' =>
                        $resultDescription

                ]

            );


        } catch (
            Throwable $e
        ) {

            error_log(
                '[LOVEMI MPESA VERIFY] '
                .
                $e->getMessage()
            );


            return new PaymentGatewayResult(

                false,

                'connection_error',

                'Unable to verify the M-Pesa transaction.',

                null,

                $checkoutRequestId

            );

        }

    }

}