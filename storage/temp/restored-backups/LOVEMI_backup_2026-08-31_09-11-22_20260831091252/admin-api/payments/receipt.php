<?php

declare(strict_types=1);


/*
|--------------------------------------------------------------------------
| LOVEMI ADMIN - PAYMENT RECEIPT
|--------------------------------------------------------------------------
*/

require_once
    __DIR__
    . '/../../config/database.php';


header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);

ini_set(
    'display_errors',
    '0'
);


/*
|--------------------------------------------------------------------------
| SESSION
|--------------------------------------------------------------------------
*/

$isHttps =
    !empty($_SERVER['HTTPS'])
    &&
    $_SERVER['HTTPS'] !== 'off';


session_set_cookie_params(
    [
        'lifetime' => 0,
        'path' => '/',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Lax'
    ]
);


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_start();

}


/*
|--------------------------------------------------------------------------
| JSON ERROR
|--------------------------------------------------------------------------
*/

function receiptError(
    string $message,
    int $status = 400
): never {

    http_response_code(
        $status
    );


    header(
        'Content-Type: application/json; charset=utf-8'
    );


    echo json_encode(
        [
            'success' =>
                false,

            'message' =>
                $message
        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
    );


    exit;

}


/*
|--------------------------------------------------------------------------
| DATABASE
|--------------------------------------------------------------------------
*/

try {

    $pdo =
        db();

} catch (
    Throwable $e
) {

    receiptError(
        'Database connection failed.',
        500
    );

}


/*
|--------------------------------------------------------------------------
| ADMIN AUTH
|--------------------------------------------------------------------------
*/

$adminId =
    (int)(
        $_SESSION['lovemi_user_id']
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION['lovemi_database_session_id']
        ??
        0
    );


$sessionToken =
    (string)(
        $_SESSION['lovemi_session_token']
        ??
        ''
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    receiptError(
        'You must log in first.',
        401
    );

}


$tokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/*
|--------------------------------------------------------------------------
| AUTHORIZATION
|--------------------------------------------------------------------------
*/

try {

    $auth =
        $pdo->prepare(
            "
            SELECT u.id

            FROM users u

            INNER JOIN roles r
                ON r.id = u.role_id

            INNER JOIN user_sessions s
                ON s.user_id = u.id

            INNER JOIN role_permissions rp
                ON rp.role_id = r.id

            INNER JOIN permissions pm
                ON pm.id = rp.permission_id

            WHERE

                u.id = :admin_id

                AND s.id = :session_id

                AND s.session_token_hash = :token_hash

                AND s.two_factor_passed = 1

                AND s.revoked_at IS NULL

                AND s.expires_at > CURRENT_TIMESTAMP

                AND u.is_active = 1

                AND u.is_suspended = 0

                AND u.is_deleted = 0

                AND r.is_admin_role = 1

                AND pm.slug = 'payments.manage'

            LIMIT 1
            "
        );


    $auth->execute(
        [
            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':token_hash' =>
                $tokenHash
        ]
    );


    if (
        !$auth->fetch()
    ) {

        receiptError(
            'You do not have permission to view payment receipts.',
            403
        );

    }

} catch (
    Throwable $e
) {

    receiptError(
        'Unable to verify administrator access.',
        500
    );

}


/*
|--------------------------------------------------------------------------
| PAYMENT ID
|--------------------------------------------------------------------------
*/

$paymentId =
    (int)(
        $_GET['payment_id']
        ??
        $_GET['id']
        ??
        0
    );


if (
    $paymentId <= 0
) {

    receiptError(
        'A valid payment ID is required.',
        422
    );

}


/*
|--------------------------------------------------------------------------
| PAYMENT
|--------------------------------------------------------------------------
*/

try {

    $stmt =
        $pdo->prepare(
            "
            SELECT

                p.id,

                p.payment_reference,

                p.gateway,

                p.gateway_transaction_id,

                p.payment_method,

                p.status,

                p.base_amount_usd,

                p.exchange_rate,

                p.amount_expected,

                p.amount_paid,

                p.gateway_fee,

                p.phone_number,

                p.checkout_reference,

                p.paid_at,

                p.created_at,

                u.username,

                u.full_names,

                u.email,

                sv.name AS service_name,

                c.code AS currency_code,

                c.name AS currency_name,

                c.symbol AS currency_symbol

            FROM payments p

            INNER JOIN users u
                ON u.id = p.user_id

            LEFT JOIN services sv
                ON sv.id = p.service_id

            LEFT JOIN currencies c
                ON c.id = p.currency_id

            WHERE
                p.id = :payment_id

            LIMIT 1
            "
        );


    $stmt->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    $payment =
        $stmt->fetch();

} catch (
    Throwable $e
) {

    receiptError(
        'Unable to load payment information.',
        500
    );

}


if (
    !$payment
) {

    receiptError(
        'Payment not found.',
        404
    );

}


/*
|--------------------------------------------------------------------------
| RECEIPT
|--------------------------------------------------------------------------
*/

try {

    $receiptStmt =
        $pdo->prepare(
            "
            SELECT

                id,

                receipt_number,

                receipt_path,

                issued_at

            FROM payment_receipts

            WHERE
                payment_id = :payment_id

            ORDER BY id DESC

            LIMIT 1
            "
        );


    $receiptStmt->execute(
        [
            ':payment_id' =>
                $paymentId
        ]
    );


    $receipt =
        $receiptStmt->fetch();

} catch (
    Throwable $e
) {

    receiptError(
        'Unable to load receipt information.',
        500
    );

}


/*
|--------------------------------------------------------------------------
| EXISTING FILE
|--------------------------------------------------------------------------
*/

if (
    $receipt
    &&
    !empty(
        $receipt['receipt_path']
    )
) {

    $relative =
        ltrim(
            str_replace(
                '\\',
                '/',
                (string)
                $receipt['receipt_path']
            ),
            '/'
        );


    $root =
        dirname(
            __DIR__,
            2
        );


    $absolute =
        realpath(
            $root
            .
            DIRECTORY_SEPARATOR
            .
            str_replace(
                '/',
                DIRECTORY_SEPARATOR,
                $relative
            )
        );


    /*
     * Only serve files inside the LOVEMI project.
     */

    $realRoot =
        realpath(
            $root
        );


    if (
        $absolute
        &&
        $realRoot
        &&
        str_starts_with(
            $absolute,
            $realRoot
        )
        &&
        is_file(
            $absolute
        )
    ) {

        $extension =
            strtolower(
                pathinfo(
                    $absolute,
                    PATHINFO_EXTENSION
                )
            );


        $contentTypes = [

            'pdf' =>
                'application/pdf',

            'html' =>
                'text/html; charset=utf-8',

            'htm' =>
                'text/html; charset=utf-8'

        ];


        if (
            isset(
                $contentTypes[
                    $extension
                ]
            )
        ) {

            header(
                'Content-Type: '
                .
                $contentTypes[
                    $extension
                ]
            );

            header(
                'Content-Disposition: inline; filename="'
                .
                basename(
                    $absolute
                )
                .
                '"'
            );

            readfile(
                $absolute
            );

            exit;

        }

    }

}


/*
|--------------------------------------------------------------------------
| HTML RECEIPT FALLBACK
|--------------------------------------------------------------------------
*/

header(
    'Content-Type: text/html; charset=utf-8'
);


header(
    'Content-Disposition: inline; filename="LOVEMI-Receipt-'
    .
    $paymentId
    .
    '.html"'
);


function h(
    mixed $value
): string {

    return htmlspecialchars(
        (string)(
            $value
            ??
            ''
        ),
        ENT_QUOTES,
        'UTF-8'
    );

}


$currency =
    $payment['currency_code']
    ||
    'USD';


$symbol =
    $payment['currency_symbol']
    ||
    '';


$receiptNumber =
    $receipt['receipt_number']
    ??
    (
        'LOVEMI-'
        .
        $paymentId
        .
        '-'
        .
        date(
            'Ymd',
            strtotime(
                (string)
                $payment['created_at']
            )
        )
    );


?>
<!DOCTYPE html>
<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta name="viewport"
          content="width=device-width, initial-scale=1.0">

    <title>
        LOVEMI Payment Receipt
    </title>

    <style>

        * {
            box-sizing:border-box;
        }

        body {

            margin:0;

            padding:35px;

            font-family:
                Arial,
                Helvetica,
                sans-serif;

            color:#18181b;

            background:#f5f5f8;

        }

        .receipt {

            width:
                min(
                    100%,
                    760px
                );

            margin:auto;

            padding:35px;

            background:white;

            border:1px solid #e5e7eb;

            border-radius:18px;

            box-shadow:
                0 20px 50px
                rgba(0,0,0,.08);

        }

        .brand {

            display:flex;

            align-items:center;

            justify-content:space-between;

            gap:20px;

            padding-bottom:22px;

            border-bottom:
                1px solid #ececf1;

        }

        .brand h1 {

            margin:0;

            color:#6d28d9;

            font-size:28px;

        }

        .brand span {

            color:#73737d;

            font-size:13px;

        }

        h2 {

            margin-top:28px;

            font-size:19px;

        }

        .grid {

            display:grid;

            grid-template-columns:
                repeat(
                    2,
                    1fr
                );

            gap:12px;

            margin-top:18px;

        }

        .item {

            padding:13px;

            background:#fafafa;

            border:
                1px solid #ececf1;

            border-radius:10px;

        }

        .item small {

            display:block;

            margin-bottom:4px;

            color:#8a8a94;

            font-size:10px;

            text-transform:uppercase;

        }

        .item strong {

            font-size:13px;

            word-break:break-word;

        }

        .amount {

            margin-top:24px;

            padding:18px;

            color:white;

            background:
                linear-gradient(
                    135deg,
                    #6d28d9,
                    #db2777
                );

            border-radius:14px;

        }

        .amount span {

            display:block;

            font-size:11px;

            opacity:.85;

        }

        .amount strong {

            display:block;

            margin-top:4px;

            font-size:27px;

        }

        .footer {

            margin-top:28px;

            padding-top:18px;

            color:#8a8a94;

            border-top:
                1px solid #ececf1;

            font-size:10px;

            line-height:1.6;

        }

        @media (max-width:600px) {

            body {
                padding:12px;
            }

            .receipt {
                padding:20px;
            }

            .grid {
                grid-template-columns:1fr;
            }

        }

    </style>

</head>

<body>


<div class="receipt">


    <div class="brand">

        <div>

            <h1>
                LOVEMI
            </h1>

            <span>
                Official Payment Receipt
            </span>

        </div>


        <strong>
            <?= h($receiptNumber) ?>
        </strong>

    </div>


    <h2>
        Payment Information
    </h2>


    <div class="grid">


        <div class="item">

            <small>
                Customer
            </small>

            <strong>
                <?= h($payment['full_names']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Username
            </small>

            <strong>
                @<?= h($payment['username']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Email
            </small>

            <strong>
                <?= h($payment['email']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Service
            </small>

            <strong>
                <?= h(
                    $payment['service_name']
                    ??
                    'LOVEMI Service'
                ) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Payment Reference
            </small>

            <strong>
                <?= h($payment['payment_reference']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Gateway
            </small>

            <strong>
                <?= h($payment['gateway']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Payment Method
            </small>

            <strong>
                <?= h(
                    $payment['payment_method']
                    ??
                    '—'
                ) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Status
            </small>

            <strong>
                <?= h($payment['status']) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Gateway Transaction
            </small>

            <strong>
                <?= h(
                    $payment['gateway_transaction_id']
                    ??
                    '—'
                ) ?>
            </strong>

        </div>


        <div class="item">

            <small>
                Paid At
            </small>

            <strong>
                <?= h(
                    $payment['paid_at']
                    ??
                    '—'
                ) ?>
            </strong>

        </div>


    </div>


    <div class="amount">

        <span>
            Amount Paid
        </span>

        <strong>

            <?= h($symbol) ?>

            <?= number_format(
                (float)
                $payment['amount_paid'],
                2
            ) ?>

            <?= h($currency) ?>

        </strong>

    </div>


    <div class="footer">

        This receipt was generated by LOVEMI.
        Receipt number:
        <strong>
            <?= h($receiptNumber) ?>
        </strong>.

        <br>

        Generated:
        <?= h(
            $receipt['issued_at']
            ??
            date('Y-m-d H:i:s')
        ) ?>

    </div>


</div>


</body>

</html>