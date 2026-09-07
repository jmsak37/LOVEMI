<?php
/**
 * ============================================================
 * LOVEMI - GOOGLE IDENTITY CONFIGURATION
 * ============================================================
 *
 * IMPORTANT:
 * - Client ID may be exposed to the browser.
 * - Client Secret MUST remain server-side.
 * - Do not put the Client Secret in HTML or JavaScript.
 * ============================================================
 */

declare(strict_types=1);

/*
 * Your Google OAuth Web Client ID.
 */
const LOVEMI_GOOGLE_CLIENT_ID =
    '164710232403-0eausg7qm3oqud85l223a9l4g4a17ob7.apps.googleusercontent.com';


/*
 * Optional environment override.
 *
 * This allows production hosting to replace the value
 * without editing the PHP source.
 */
function lovemiGoogleClientId(): string
{
    $environmentClientId =
        getenv('LOVEMI_GOOGLE_CLIENT_ID');

    if (
        is_string($environmentClientId)
        &&
        trim($environmentClientId) !== ''
    ) {

        return trim($environmentClientId);

    }

    return LOVEMI_GOOGLE_CLIENT_ID;
}