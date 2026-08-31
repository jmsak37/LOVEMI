<?php
/**
 * ============================================================
 * LOVEMI - DATABASE CONNECTION
 * ============================================================
 *
 * File:
 * C:\xampp\htdocs\LOVEMI\config\database.php
 *
 * Database:
 * lovemi
 *
 * Environment:
 * XAMPP / MySQL / MariaDB
 *
 * IMPORTANT:
 * - This file uses PDO.
 * - Database credentials are kept in one place.
 * - Errors are logged instead of exposing database details
 *   to visitors.
 * - All project APIs should include this file.
 *
 * Example:
 *
 * require_once __DIR__ . '/../../config/database.php';
 *
 * ============================================================
 */

declare(strict_types=1);


/* ============================================================
   DATABASE CONFIGURATION
   ============================================================ */

const DB_HOST = '127.0.0.1';

const DB_PORT = '3306';

const DB_NAME = 'lovemi';

const DB_USER = 'root';

/*
 * On a normal fresh XAMPP installation, MySQL root often has
 * an empty password.
 *
 * If your MySQL root account has a password, change this to:
 *
 * const DB_PASS = 'YOUR_PASSWORD';
 */
const DB_PASS = '';

const DB_CHARSET = 'utf8mb4';


/* ============================================================
   PDO CONNECTION
   ============================================================ */

/*
 * Keep one PDO connection during the current PHP request.
 */
function db(): PDO
{
    static $pdo = null;


    /*
     * Reuse existing connection.
     */
    if ($pdo instanceof PDO) {
        return $pdo;
    }


    /*
     * Build DSN.
     */
    $dsn =
        'mysql:'
        . 'host=' . DB_HOST . ';'
        . 'port=' . DB_PORT . ';'
        . 'dbname=' . DB_NAME . ';'
        . 'charset=' . DB_CHARSET;


    try {

        $pdo = new PDO(
            $dsn,
            DB_USER,
            DB_PASS,
            [
                /*
                 * Throw exceptions for database errors.
                 */
                PDO::ATTR_ERRMODE =>
                    PDO::ERRMODE_EXCEPTION,

                /*
                 * Always return associative arrays by default.
                 */
                PDO::ATTR_DEFAULT_FETCH_MODE =>
                    PDO::FETCH_ASSOC,

                /*
                 * Use native prepared statements.
                 */
                PDO::ATTR_EMULATE_PREPARES =>
                    false,

                /*
                 * Keep persistent connections disabled.
                 * This is simpler and safer for the initial
                 * XAMPP deployment.
                 */
                PDO::ATTR_PERSISTENT =>
                    false,

                /*
                 * Converts numeric database values to PHP
                 * integer/float where appropriate.
                 */
                PDO::ATTR_STRINGIFY_FETCHES =>
                    false,

                /*
                 * MySQL specific timeout.
                 */
                PDO::ATTR_TIMEOUT =>
                    10
            ]
        );


        /*
         * Set additional MySQL session settings.
         */
        $pdo->exec(
            "SET SESSION sql_mode = "
            . "'STRICT_TRANS_TABLES,"
            . "ERROR_FOR_DIVISION_BY_ZERO,"
            . "NO_ENGINE_SUBSTITUTION'"
        );


        return $pdo;


    } catch (PDOException $e) {

        /*
         * Log the real database error on the server.
         *
         * Do NOT return the username/password/database details
         * to the browser.
         */
        error_log(
            '[LOVEMI DATABASE ERROR] '
            . $e->getMessage()
        );


        /*
         * Return a generic exception to the application.
         */
        throw new RuntimeException(
            'Unable to connect to the LOVEMI database.'
        );

    }
}


/* ============================================================
   OPTIONAL ALIAS
   ============================================================ */

/*
 * Some future LOVEMI files may use:
 *
 * $pdo = getDatabase();
 *
 * This function simply returns the same PDO connection.
 */

function getDatabase(): PDO
{
    return db();
}


/* ============================================================
   DATABASE HEALTH CHECK
   ============================================================ */

/**
 * Check whether the LOVEMI database is available.
 *
 * Returns TRUE when the connection works.
 */
function databaseIsAvailable(): bool
{
    try {

        $pdo = db();

        $pdo->query('SELECT 1');

        return true;

    } catch (Throwable $e) {

        error_log(
            '[LOVEMI DATABASE HEALTH CHECK] '
            . $e->getMessage()
        );

        return false;
    }
}


/* ============================================================
   TRANSACTION HELPERS
   ============================================================ */

/**
 * Start a database transaction safely.
 */
function dbBegin(): void
{
    $pdo = db();

    if (!$pdo->inTransaction()) {
        $pdo->beginTransaction();
    }
}


/**
 * Commit current database transaction.
 */
function dbCommit(): void
{
    $pdo = db();

    if ($pdo->inTransaction()) {
        $pdo->commit();
    }
}


/**
 * Roll back current database transaction.
 */
function dbRollback(): void
{
    $pdo = db();

    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
}


/* ============================================================
   SAFE TRANSACTION RUNNER
   ============================================================ */

/**
 * Execute several database operations in one transaction.
 *
 * Example:
 *
 * dbTransaction(function (PDO $pdo) {
 *
 *     $stmt = $pdo->prepare(
 *         "INSERT INTO example_table (name)
 *          VALUES (:name)"
 *     );
 *
 *     $stmt->execute([
 *         ':name' => 'Example'
 *     ]);
 *
 * });
 */
function dbTransaction(
    callable $callback
): mixed {

    $pdo = db();


    try {

        $pdo->beginTransaction();


        $result =
            $callback($pdo);


        $pdo->commit();


        return $result;


    } catch (Throwable $e) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        error_log(
            '[LOVEMI DATABASE TRANSACTION ERROR] '
            . $e->getMessage()
        );


        throw $e;
    }
}


/* ============================================================
   CONNECTION TEST WHEN DIRECTLY OPENED
   ============================================================ */

/*
 * If someone directly opens this file in a browser, do not
 * expose database credentials or technical information.
 *
 * This block simply performs a connection test and returns a
 * generic response.
 *
 * In production you can remove this block completely.
 */

if (
    isset($_GET['health'])
    && $_GET['health'] === '1'
) {

    header(
        'Content-Type: application/json; charset=utf-8'
    );

    header(
        'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
    );

    try {

        $pdo = db();


        $result = $pdo->query(
            'SELECT DATABASE() AS database_name'
        )->fetch();


        echo json_encode(
            [
                'success' => true,
                'database' => $result['database_name'] ?? DB_NAME,
                'message' => 'LOVEMI database connection is working.'
            ],
            JSON_UNESCAPED_SLASHES
        );


    } catch (Throwable $e) {

        http_response_code(500);


        echo json_encode(
            [
                'success' => false,
                'message' => 'LOVEMI database connection failed.'
            ],
            JSON_UNESCAPED_SLASHES
        );

    }

    exit;
}