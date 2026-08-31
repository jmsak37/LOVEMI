<?php

declare(strict_types=1);

/**
 * LOVEMI application configuration.
 */

const APP_NAME = 'LOVEMI';


function getApplicationEncryptionKey(): string
{
    $key =
        'LOVEMI_SecKey_#9k8v7x6z5w4y3m2n1p0q9r8s7t6u5v4w3x2y1z!';


    if (
        !is_string($key)
        ||
        trim($key) === ''
    ) {

        throw new RuntimeException(
            'LOVEMI_APP_KEY is not configured.'
        );
    }


    return hash(
        'sha256',
        $key,
        true
    );
}