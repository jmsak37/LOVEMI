<?php

declare(strict_types=1);


/* ============================================================
   ERROR HANDLING
============================================================ */

error_reporting(E_ALL);

ini_set(
    'display_errors',
    '0'
);

ini_set(
    'display_startup_errors',
    '0'
);


/* ============================================================
   DATABASE
============================================================ */

require_once
    __DIR__
    . '/../../config/database.php';


/* ============================================================
   HEADERS
============================================================ */

header(
    'Content-Type: application/json; charset=utf-8'
);

header(
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   RESPONSE
============================================================ */

function backupCreateResponse(
    bool $success,
    string $message,
    array $data = [],
    int $status = 200
): never {

    while (
        ob_get_level() > 0
    ) {

        @ob_end_clean();

    }


    http_response_code(
        $status
    );


    echo json_encode(
        [

            'success' =>
                $success,

            'message' =>
                $message,

            'data' =>
                $data

        ],
        JSON_UNESCAPED_UNICODE
        |
        JSON_UNESCAPED_SLASHES
        |
        JSON_INVALID_UTF8_SUBSTITUTE
    );


    exit;

}


/* ============================================================
   SESSION
============================================================ */

$isHttps =
    !empty(
        $_SERVER['HTTPS']
    )
    &&
    $_SERVER['HTTPS'] !== 'off';


if (
    session_status()
    !==
    PHP_SESSION_ACTIVE
) {

    session_set_cookie_params(
        [

            'lifetime' =>
                0,

            'path' =>
                '/',

            'secure' =>
                $isHttps,

            'httponly' =>
                true,

            'samesite' =>
                'Lax'

        ]
    );


    session_start();

}


/* ============================================================
   DATABASE
============================================================ */

try {

    $pdo =
        db();


    $pdo->setAttribute(
        PDO::ATTR_ERRMODE,
        PDO::ERRMODE_EXCEPTION
    );


    $pdo->setAttribute(
        PDO::ATTR_DEFAULT_FETCH_MODE,
        PDO::FETCH_ASSOC
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BACKUP CREATE DB] '
        .
        $e->getMessage()
    );


    backupCreateResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


/* ============================================================
   ADMIN SESSION
============================================================ */

$adminId =
    (int)(
        $_SESSION[
            'lovemi_user_id'
        ]
        ??
        0
    );


$sessionId =
    (int)(
        $_SESSION[
            'lovemi_database_session_id'
        ]
        ??
        0
    );


$sessionToken =
    trim(
        (string)(
            $_SESSION[
                'lovemi_session_token'
            ]
            ??
            ''
        )
    );


if (
    $adminId <= 0
    ||
    $sessionId <= 0
    ||
    $sessionToken === ''
) {

    backupCreateResponse(
        false,
        'Your administrator session has expired. Please log in again.',
        [
            'code' =>
                'NOT_AUTHENTICATED'
        ],
        401
    );

}


$sessionTokenHash =
    hash(
        'sha256',
        $sessionToken
    );


/* ============================================================
   ADMIN + BACKUP PERMISSION
============================================================ */

try {

    $authStmt =
        $pdo->prepare(
            "
            SELECT

                u.id,

                u.username,

                u.full_names,

                u.email,

                r.id AS role_id,

                r.name AS role_name,

                r.slug AS role_slug

            FROM users u

            INNER JOIN roles r
                ON r.id =
                    u.role_id

            INNER JOIN user_sessions s
                ON s.user_id =
                    u.id

            INNER JOIN role_permissions rp
                ON rp.role_id =
                    r.id

            INNER JOIN permissions p
                ON p.id =
                    rp.permission_id

            WHERE

                u.id =
                    :admin_id

                AND s.id =
                    :session_id

                AND s.session_token_hash =
                    :session_token_hash

                AND s.two_factor_passed =
                    1

                AND s.revoked_at IS NULL

                AND s.expires_at >
                    CURRENT_TIMESTAMP

                AND u.is_active =
                    1

                AND u.is_suspended =
                    0

                AND u.is_deleted =
                    0

                AND r.is_admin_role =
                    1

                AND p.slug =
                    'backups.manage'

            LIMIT 1
            "
        );


    $authStmt->execute(
        [

            ':admin_id' =>
                $adminId,

            ':session_id' =>
                $sessionId,

            ':session_token_hash' =>
                $sessionTokenHash

        ]
    );


    $admin =
        $authStmt->fetch();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BACKUP CREATE AUTH] '
        .
        $e->getMessage()
    );


    backupCreateResponse(
        false,
        'Unable to verify administrator access.',
        [],
        500
    );

}


if (
    !$admin
) {

    backupCreateResponse(
        false,
        'You do not have permission to manage backups.',
        [
            'code' =>
                'PERMISSION_DENIED'
        ],
        403
    );

}


/* ============================================================
   INPUT
============================================================ */

$rawBody =
    file_get_contents(
        'php://input'
    );


$input =
    json_decode(
        (string)
        $rawBody,
        true
    );


if (
    !is_array(
        $input
    )
) {

    $input =
        $_POST;

}


$action =
    strtolower(
        trim(
            (string)(
                $input['action']
                ??
                ''
            )
        )
    );


if (
    $action === ''
) {

    backupCreateResponse(
        false,
        'Backup action is required.',
        [],
        422
    );

}


/* ============================================================
   PATHS
============================================================ */

$projectRoot =
    realpath(
        dirname(
            __DIR__,
            2
        )
    );


if (
    $projectRoot === false
) {

    backupCreateResponse(
        false,
        'The LOVEMI project root could not be resolved.',
        [],
        500
    );

}


$localBackupRoot =
    $projectRoot
    .
    DIRECTORY_SEPARATOR
    .
    'storage'
    .
    DIRECTORY_SEPARATOR
    .
    'backups';


$restoreRoot =
    $projectRoot
    .
    DIRECTORY_SEPARATOR
    .
    'storage'
    .
    DIRECTORY_SEPARATOR
    .
    'temp'
    .
    DIRECTORY_SEPARATOR
    .
    'restored-backups';


$githubOwner =
    'jmsak37';


$githubRepository =
    'LOVEMI-back-up-files';


$githubRemote =
    'https://github.com/'
    .
    $githubOwner
    .
    '/'
    .
    $githubRepository
    .
    '.git';


$githubCloneRoot =
    $projectRoot
    .
    DIRECTORY_SEPARATOR
    .
    'storage'
    .
    DIRECTORY_SEPARATOR
    .
    'temp'
    .
    DIRECTORY_SEPARATOR
    .
    $githubRepository;


/* ============================================================
   DIRECTORY HELPER
============================================================ */

function backupEnsureDirectory(
    string $path
): void {

    if (
        is_dir(
            $path
        )
    ) {

        return;

    }


    if (
        !@mkdir(
            $path,
            0775,
            true
        )
        &&
        !is_dir(
            $path
        )
    ) {

        throw new RuntimeException(
            'Unable to create directory: '
            .
            $path
        );

    }

}


/* ============================================================
   FILE COUNT + SIZE
============================================================ */

function backupScanDirectory(
    string $directory
): array {

    $fileCount =
        0;

    $totalSize =
        0;


    if (
        !is_dir(
            $directory
        )
    ) {

        return [

            'files' =>
                0,

            'size' =>
                0

        ];

    }


    $iterator =
        new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $directory,
                FilesystemIterator::SKIP_DOTS
            ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );


    foreach (
        $iterator
        as $file
    ) {

        if (
            !$file->isFile()
        ) {

            continue;

        }


        $fileCount++;


        $totalSize +=
            (int)
            $file->getSize();

    }


    return [

        'files' =>
            $fileCount,

        'size' =>
            $totalSize

    ];

}


/* ============================================================
   EXCLUDED PATH CHECK
============================================================ */

function backupShouldExclude(
    string $path,
    string $projectRoot,
    string $backupRoot,
    string $githubRoot
): bool {

    $normalized =
        str_replace(
            '\\',
            '/',
            $path
        );


    $normalizedRoot =
        rtrim(
            str_replace(
                '\\',
                '/',
                $projectRoot
            ),
            '/'
        );


    $relative =
        ltrim(
            substr(
                $normalized,
                strlen(
                    $normalizedRoot
                )
            ),
            '/'
        );


    if (
        $relative === ''
    ) {

        return false;

    }


    $first =
        strtolower(
            explode(
                '/',
                $relative
            )[0]
        );


    /*
     * Never recursively back up backup files themselves,
     * Git metadata or the temporary Git clone.
     */

    if (
        $first ===
        '.git'
    ) {

        return true;

    }


    if (
        $first ===
        'storage'
    ) {

        $lower =
            strtolower(
                $relative
            );


        if (
            str_starts_with(
                $lower,
                'storage/backups'
            )
            ||
            str_starts_with(
                $lower,
                'storage/temp/lovemi-back-up-files'
            )
            ||
            str_starts_with(
                $lower,
                'storage/temp/restored-backups'
            )
        ) {

            return true;

        }

    }


    return false;

}


/* ============================================================
   COPY PROJECT
============================================================ */

function backupCopyProject(
    string $source,
    string $destination,
    string $projectRoot,
    string $backupRoot,
    string $githubRoot
): void {

    backupEnsureDirectory(
        $destination
    );


    $iterator =
        new FilesystemIterator(
            $source,
            FilesystemIterator::SKIP_DOTS
        );


    foreach (
        $iterator
        as $item
    ) {

        $sourcePath =
            $item->getPathname();


        if (
            backupShouldExclude(
                $sourcePath,
                $projectRoot,
                $backupRoot,
                $githubRoot
            )
        ) {

            continue;

        }


        $relative =
            substr(
                $sourcePath,
                strlen(
                    $projectRoot
                )
            );


        $relative =
            ltrim(
                $relative,
                DIRECTORY_SEPARATOR
            );


        $targetPath =
            $destination
            .
            DIRECTORY_SEPARATOR
            .
            $relative;


        if (
            $item->isDir()
        ) {

            backupEnsureDirectory(
                $targetPath
            );


            backupCopyProject(
                $sourcePath,
                $destination,
                $projectRoot,
                $backupRoot,
                $githubRoot
            );

        } else {

            backupEnsureDirectory(
                dirname(
                    $targetPath
                )
            );


            if (
                !@copy(
                    $sourcePath,
                    $targetPath
                )
            ) {

                throw new RuntimeException(
                    'Unable to copy file: '
                    .
                    $relative
                );

            }

        }

    }

}


/* ============================================================
   ZIP DIRECTORY
============================================================ */

function backupZipDirectory(
    string $source,
    string $zipFile
): void {

    if (
        !class_exists(
            'ZipArchive'
        )
    ) {

        throw new RuntimeException(
            'PHP ZipArchive is not enabled.'
        );

    }


    $zip =
        new ZipArchive();


    if (
        $zip->open(
            $zipFile,
            ZipArchive::CREATE
            |
            ZipArchive::OVERWRITE
        )
        !==
        true
    ) {

        throw new RuntimeException(
            'Unable to create ZIP archive.'
        );

    }


    $iterator =
        new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator(
                $source,
                FilesystemIterator::SKIP_DOTS
            ),
            RecursiveIteratorIterator::LEAVES_ONLY
        );


    foreach (
        $iterator
        as $file
    ) {

        if (
            !$file->isFile()
        ) {

            continue;

        }


        $realPath =
            $file->getRealPath();


        if (
            $realPath === false
        ) {

            continue;

        }


        $relative =
            substr(
                $realPath,
                strlen(
                    $source
                )
            );


        $relative =
            ltrim(
                str_replace(
                    DIRECTORY_SEPARATOR,
                    '/',
                    $relative
                ),
                '/'
            );


        $zip->addFile(
            $realPath,
            $relative
        );

    }


    $zip->close();

}


/* ============================================================
   SAFE REMOVE
============================================================ */

function backupDeletePath(
    string $path
): void {

    if (
        is_file(
            $path
        )
    ) {

        if (
            !@unlink(
                $path
            )
        ) {

            throw new RuntimeException(
                'Unable to delete file: '
                .
                $path
            );

        }


        return;

    }


    if (
        is_dir(
            $path
        )
    ) {

        $iterator =
            new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(
                    $path,
                    FilesystemIterator::SKIP_DOTS
                ),
                RecursiveIteratorIterator::CHILD_FIRST
            );


        foreach (
            $iterator
            as $item
        ) {

            if (
                $item->isDir()
            ) {

                @rmdir(
                    $item->getPathname()
                );

            } else {

                @unlink(
                    $item->getPathname()
                );

            }

        }


        @rmdir(
            $path
        );

    }

}


/* ============================================================
   CREATE BACKUP
============================================================ */

if (
    $action ===
    'create'
) {

    try {

        backupEnsureDirectory(
            $localBackupRoot
        );


        $timestamp =
            date(
                'Y-m-d_H-i-s'
            );


        $workingDirectory =
            $localBackupRoot
            .
            DIRECTORY_SEPARATOR
            .
            'LOVEMI_backup_'
            .
            $timestamp;


        backupEnsureDirectory(
            $workingDirectory
        );


        /*
         * Copy all project files except:
         *
         * - .git
         * - existing backup storage
         * - GitHub clone
         * - restore temp area
         */

        backupCopyProject(
            $projectRoot,
            $workingDirectory,
            $projectRoot,
            $localBackupRoot,
            $githubCloneRoot
        );


        $scan =
            backupScanDirectory(
                $workingDirectory
            );


        /*
         * Requirement:
         *
         * More than 10 files -> ZIP.
         *
         * Ten or fewer -> leave as folder.
         */

        $isZip =
            $scan['files'] > 10;


        $finalPath =
            $workingDirectory;


        $fileName =
            basename(
                $workingDirectory
            );


        if (
            $isZip
        ) {

            $zipPath =
                $localBackupRoot
                .
                DIRECTORY_SEPARATOR
                .
                $fileName
                .
                '.zip';


            backupZipDirectory(
                $workingDirectory,
                $zipPath
            );


            backupDeletePath(
                $workingDirectory
            );


            $finalPath =
                $zipPath;


            $fileName =
                basename(
                    $zipPath
                );

        }


        $finalSize =
            is_file(
                $finalPath
            )
            ?
            (int)
            filesize(
                $finalPath
            )
            :
            $scan['size'];


        /*
         * Save database record.
         */

        $insert =
            $pdo->prepare(
                "
                INSERT INTO backup_logs
                (
                    created_by,
                    file_name,
                    file_path,
                    status,
                    file_size
                )
                VALUES
                (
                    :created_by,
                    :file_name,
                    :file_path,
                    'created',
                    :file_size
                )
                "
            );


        $insert->execute(
            [

                ':created_by' =>
                    $adminId,

                ':file_name' =>
                    $fileName,

                ':file_path' =>
                    $finalPath,

                ':file_size' =>
                    $finalSize

            ]
        );


        $backupId =
            (int)
            $pdo->lastInsertId();


        /*
         * Audit log.
         */

        try {

            $audit =
                $pdo->prepare(
                    "
                    INSERT INTO audit_logs
                    (
                        user_id,
                        action,
                        entity_type,
                        entity_id,
                        old_values,
                        new_values,
                        ip_address,
                        user_agent
                    )
                    VALUES
                    (
                        :user_id,
                        'admin_create_backup',
                        'backup',
                        :entity_id,
                        NULL,
                        :new_values,
                        :ip,
                        :agent
                    )
                    "
                );


            $audit->execute(
                [

                    ':user_id' =>
                        $adminId,

                    ':entity_id' =>
                        $backupId,

                    ':new_values' =>
                        json_encode(
                            [

                                'file_name' =>
                                    $fileName,

                                'file_path' =>
                                    $finalPath,

                                'file_count' =>
                                    $scan['files'],

                                'file_size' =>
                                    $finalSize,

                                'zip' =>
                                    $isZip

                            ],
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':ip' =>
                        $_SERVER['REMOTE_ADDR']
                        ??
                        null,

                    ':agent' =>
                        $_SERVER['HTTP_USER_AGENT']
                        ??
                        null

                ]
            );

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI BACKUP AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        backupCreateResponse(
            true,
            'LOVEMI backup created successfully.',
            [

                'backup_id' =>
                    $backupId,

                'file_name' =>
                    $fileName,

                'file_path' =>
                    $finalPath,

                'file_count' =>
                    $scan['files'],

                'file_size' =>
                    $finalSize,

                'zipped' =>
                    $isZip

            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI BACKUP CREATE] '
            .
            $e->getMessage()
        );


        if (
            isset(
                $workingDirectory
            )
            &&
            is_dir(
                $workingDirectory
            )
        ) {

            try {

                backupDeletePath(
                    $workingDirectory
                );

            } catch (
                Throwable $cleanupError
            ) {

                error_log(
                    '[LOVEMI BACKUP CLEANUP] '
                    .
                    $cleanupError->getMessage()
                );

            }

        }


        backupCreateResponse(
            false,
            $e->getMessage(),
            [
                'code' =>
                    'BACKUP_CREATE_ERROR'
            ],
            500
        );

    }

}


/* ============================================================
   DELETE LOCAL
============================================================ */

if (
    $action ===
    'delete_local'
) {

    $backupId =
        (int)(
            $input['id']
            ??
            0
        );


    if (
        $backupId <= 0
    ) {

        backupCreateResponse(
            false,
            'Invalid backup ID.',
            [],
            422
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    file_name,

                    file_path,

                    file_size,

                    status

                FROM backup_logs

                WHERE
                    id =
                    :id

                LIMIT 1

                FOR UPDATE
                "
            );


        $pdo->beginTransaction();


        $stmt->execute(
            [
                ':id' =>
                    $backupId
            ]
        );


        $backup =
            $stmt->fetch();


        if (
            !$backup
        ) {

            throw new RuntimeException(
                'Backup record not found.'
            );

        }


        $targetPath =
            realpath(
                (string)
                $backup['file_path']
            );


        $backupRootReal =
            realpath(
                $localBackupRoot
            );


        if (
            $targetPath === false
            ||
            $backupRootReal === false
        ) {

            throw new RuntimeException(
                'The local backup file no longer exists.'
            );

        }


        $prefix =
            rtrim(
                $backupRootReal,
                DIRECTORY_SEPARATOR
            )
            .
            DIRECTORY_SEPARATOR;


        if (
            strpos(
                $targetPath,
                $prefix
            )
            !==
            0
        ) {

            throw new RuntimeException(
                'Invalid local backup path.'
            );

        }


        backupDeletePath(
            $targetPath
        );


        $deleteStmt =
            $pdo->prepare(
                "
                DELETE FROM backup_logs

                WHERE
                    id =
                    :id

                LIMIT 1
                "
            );


        $deleteStmt->execute(
            [
                ':id' =>
                    $backupId
            ]
        );


        try {

            $audit =
                $pdo->prepare(
                    "
                    INSERT INTO audit_logs
                    (
                        user_id,
                        action,
                        entity_type,
                        entity_id,
                        old_values,
                        new_values,
                        ip_address,
                        user_agent
                    )
                    VALUES
                    (
                        :user_id,
                        'admin_delete_backup',
                        'backup',
                        :entity_id,
                        :old_values,
                        NULL,
                        :ip,
                        :agent
                    )
                    "
                );


            $audit->execute(
                [

                    ':user_id' =>
                        $adminId,

                    ':entity_id' =>
                        $backupId,

                    ':old_values' =>
                        json_encode(
                            $backup,
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':ip' =>
                        $_SERVER['REMOTE_ADDR']
                        ??
                        null,

                    ':agent' =>
                        $_SERVER['HTTP_USER_AGENT']
                        ??
                        null

                ]
            );

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI BACKUP DELETE AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        $pdo->commit();


        backupCreateResponse(
            true,
            'Local backup deleted successfully.',
            [
                'backup_id' =>
                    $backupId
            ]
        );

    } catch (
        Throwable $e
    ) {

        if (
            $pdo->inTransaction()
        ) {

            $pdo->rollBack();

        }


        error_log(
            '[LOVEMI BACKUP DELETE LOCAL] '
            .
            $e->getMessage()
        );


        backupCreateResponse(
            false,
            $e->getMessage(),
            [],
            500
        );

    }

}


/* ============================================================
   RESTORE LOCAL ZIP
============================================================ */

if (
    $action ===
    'restore_local'
) {

    $backupId =
        (int)(
            $input['id']
            ??
            0
        );


    if (
        $backupId <= 0
    ) {

        backupCreateResponse(
            false,
            'Invalid backup ID.',
            [],
            422
        );

    }


    if (
        !class_exists(
            'ZipArchive'
        )
    ) {

        backupCreateResponse(
            false,
            'PHP ZipArchive is not enabled on this server.',
            [],
            500
        );

    }


    try {

        $stmt =
            $pdo->prepare(
                "
                SELECT

                    id,

                    file_name,

                    file_path

                FROM backup_logs

                WHERE
                    id =
                    :id

                LIMIT 1
                "
            );


        $stmt->execute(
            [
                ':id' =>
                    $backupId
            ]
        );


        $backup =
            $stmt->fetch();


        if (
            !$backup
        ) {

            backupCreateResponse(
                false,
                'Backup record not found.',
                [],
                404
            );

        }


        $backupPath =
            realpath(
                (string)
                $backup['file_path']
            );


        $backupRootReal =
            realpath(
                $localBackupRoot
            );


        if (
            $backupPath === false
            ||
            !is_file(
                $backupPath
            )
            ||
            $backupRootReal === false
        ) {

            backupCreateResponse(
                false,
                'Backup archive does not exist.',
                [],
                404
            );

        }


        $prefix =
            rtrim(
                $backupRootReal,
                DIRECTORY_SEPARATOR
            )
            .
            DIRECTORY_SEPARATOR;


        if (
            strpos(
                $backupPath,
                $prefix
            )
            !==
            0
        ) {

            backupCreateResponse(
                false,
                'Invalid backup path.',
                [],
                403
            );

        }


        if (
            strtolower(
                pathinfo(
                    $backupPath,
                    PATHINFO_EXTENSION
                )
            )
            !==
            'zip'
        ) {

            backupCreateResponse(
                false,
                'Only ZIP backups can be restored.',
                [],
                422
            );

        }


        backupEnsureDirectory(
            $restoreRoot
        );


        $restoreDirectory =
            $restoreRoot
            .
            DIRECTORY_SEPARATOR
            .
            pathinfo(
                (string)
                $backup['file_name'],
                PATHINFO_FILENAME
            )
            .
            '_'
            .
            date(
                'YmdHis'
            );


        backupEnsureDirectory(
            $restoreDirectory
        );


        $zip =
            new ZipArchive();


        if (
            $zip->open(
                $backupPath
            )
            !==
            true
        ) {

            throw new RuntimeException(
                'Unable to open backup archive.'
            );

        }


        /*
         * ZIP path traversal protection.
         */

        for (
            $i = 0;
            $i < $zip->numFiles;
            $i++
        ) {

            $name =
                $zip->getNameIndex(
                    $i
                );


            if (
                $name === false
            ) {

                continue;

            }


            $normalized =
                str_replace(
                    '\\',
                    '/',
                    $name
                );


            if (
                str_contains(
                    $normalized,
                    '../'
                )
                ||
                str_starts_with(
                    $normalized,
                    '/'
                )
            ) {

                $zip->close();


                throw new RuntimeException(
                    'Unsafe ZIP archive detected.'
                );

            }

        }


        if (
            !$zip->extractTo(
                $restoreDirectory
            )
        ) {

            $zip->close();


            throw new RuntimeException(
                'Unable to extract backup archive.'
            );

        }


        $zip->close();


        try {

            $audit =
                $pdo->prepare(
                    "
                    INSERT INTO audit_logs
                    (
                        user_id,
                        action,
                        entity_type,
                        entity_id,
                        old_values,
                        new_values,
                        ip_address,
                        user_agent
                    )
                    VALUES
                    (
                        :user_id,
                        'admin_restore_backup',
                        'backup',
                        :entity_id,
                        NULL,
                        :new_values,
                        :ip,
                        :agent
                    )
                    "
                );


            $audit->execute(
                [

                    ':user_id' =>
                        $adminId,

                    ':entity_id' =>
                        $backupId,

                    ':new_values' =>
                        json_encode(
                            [
                                'restore_directory' =>
                                    $restoreDirectory
                            ],
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':ip' =>
                        $_SERVER['REMOTE_ADDR']
                        ??
                        null,

                    ':agent' =>
                        $_SERVER['HTTP_USER_AGENT']
                        ??
                        null

                ]
            );

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI BACKUP RESTORE AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        backupCreateResponse(
            true,
            'Backup restored successfully into the protected restore directory.',
            [

                'backup_id' =>
                    $backupId,

                'restore_directory' =>
                    $restoreDirectory

            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI BACKUP RESTORE] '
            .
            $e->getMessage()
        );


        backupCreateResponse(
            false,
            $e->getMessage(),
            [],
            500
        );

    }

}


/* ============================================================
   SYNC WITH GITHUB
============================================================ */

if (
    $action ===
    'sync_github'
) {

    try {

        backupEnsureDirectory(
            dirname(
                $githubCloneRoot
            )
        );


        /*
         * First clone if needed.
         */

        if (
            !is_dir(
                $githubCloneRoot
            )
        ) {

            $cloneCommand =
                'git clone '
                .
                escapeshellarg(
                    $githubRemote
                )
                .
                ' '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' 2>&1';


            $cloneOutput =
                shell_exec(
                    $cloneCommand
                );


            if (
                !is_dir(
                    $githubCloneRoot
                )
            ) {

                error_log(
                    '[LOVEMI GITHUB CLONE] '
                    .
                    (string)
                    $cloneOutput
                );


                backupCreateResponse(
                    false,
                    'GitHub repository could not be cloned. Configure Git authentication on the server first.',
                    [
                        'repository' =>
                            $githubRemote
                    ],
                    500
                );

            }

        } else {

            $pullCommand =
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' pull --ff-only origin main 2>&1';


            shell_exec(
                $pullCommand
            );

        }


        $githubBackupDirectory =
            $githubCloneRoot
            .
            DIRECTORY_SEPARATOR
            .
            'backups';


        backupEnsureDirectory(
            $githubBackupDirectory
        );


        /*
         * Copy each local backup into GitHub backup storage.
         *
         * Folder backups are zipped before Git synchronization
         * because GitHub secondary storage is intended to hold
         * discrete backup files.
         */

        $localIterator =
            new FilesystemIterator(
                $localBackupRoot,
                FilesystemIterator::SKIP_DOTS
            );


        $synced =
            [];


        foreach (
            $localIterator
            as $localItem
        ) {

            $localName =
                $localItem->getFilename();


            $localPath =
                $localItem->getPathname();


            /*
             * Skip any unexpected directories that are not
             * backup records.
             */

            if (
                $localName === ''
            ) {

                continue;

            }


            if (
                $localItem->isDir()
            ) {

                $gitFile =
                    $githubBackupDirectory
                    .
                    DIRECTORY_SEPARATOR
                    .
                    $localName
                    .
                    '.zip';


                backupZipDirectory(
                    $localPath,
                    $gitFile
                );

            } else {

                $gitFile =
                    $githubBackupDirectory
                    .
                    DIRECTORY_SEPARATOR
                    .
                    $localName;


                if (
                    !@copy(
                        $localPath,
                        $gitFile
                    )
                ) {

                    throw new RuntimeException(
                        'Unable to copy backup into GitHub staging directory: '
                        .
                        $localName
                    );

                }

            }


            $synced[] =
                basename(
                    $gitFile
                );

        }


        /*
         * Stage, commit and push.
         */

        $gitAdd =
            shell_exec(
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' add backups 2>&1'
            );


        $gitStatus =
            shell_exec(
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' status --porcelain 2>&1'
            );


        if (
            trim(
                (string)
                $gitStatus
            )
            !==
            ''
        ) {

            $commitMessage =
                'LOVEMI backup '
                .
                date(
                    'Y-m-d H:i:s'
                );


            $gitCommit =
                shell_exec(
                    'git -C '
                    .
                    escapeshellarg(
                        $githubCloneRoot
                    )
                    .
                    ' commit -m '
                    .
                    escapeshellarg(
                        $commitMessage
                    )
                    .
                    ' 2>&1'
                );


            $gitPush =
                shell_exec(
                    'git -C '
                    .
                    escapeshellarg(
                        $githubCloneRoot
                    )
                    .
                    ' push origin main 2>&1'
                );


            /*
             * Detect common push failures.
             */

            if (
                stripos(
                    (string)
                    $gitPush,
                    'fatal:'
                )
                !==
                false
                ||
                stripos(
                    (string)
                    $gitPush,
                    'authentication'
                )
                !==
                false
                ||
                stripos(
                    (string)
                    $gitPush,
                    'rejected'
                )
                !==
                false
            ) {

                error_log(
                    '[LOVEMI GITHUB PUSH] '
                    .
                    (string)
                    $gitPush
                );


                backupCreateResponse(
                    false,
                    'GitHub synchronization could not be pushed. Check the server Git credentials and repository permissions.',
                    [
                        'git_output' =>
                            trim(
                                (string)
                                $gitPush
                            )
                    ],
                    500
                );

            }

        }


        try {

            $audit =
                $pdo->prepare(
                    "
                    INSERT INTO audit_logs
                    (
                        user_id,
                        action,
                        entity_type,
                        entity_id,
                        old_values,
                        new_values,
                        ip_address,
                        user_agent
                    )
                    VALUES
                    (
                        :user_id,
                        'admin_sync_backups_to_github',
                        'backup',
                        NULL,
                        NULL,
                        :new_values,
                        :ip,
                        :agent
                    )
                    "
                );


            $audit->execute(
                [

                    ':user_id' =>
                        $adminId,

                    ':new_values' =>
                        json_encode(
                            [

                                'repository' =>
                                    $githubOwner
                                    .
                                    '/'
                                    .
                                    $githubRepository,

                                'synced_files' =>
                                    $synced

                            ],
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':ip' =>
                        $_SERVER['REMOTE_ADDR']
                        ??
                        null,

                    ':agent' =>
                        $_SERVER['HTTP_USER_AGENT']
                        ??
                        null

                ]
            );

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI GITHUB SYNC AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        backupCreateResponse(
            true,
            'Local backups synchronized with the GitHub backup repository successfully.',
            [

                'repository' =>
                    $githubOwner
                    .
                    '/'
                    .
                    $githubRepository,

                'synced_files' =>
                    $synced

            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GITHUB SYNC] '
            .
            $e->getMessage()
        );


        backupCreateResponse(
            false,
            $e->getMessage(),
            [
                'code' =>
                    'GITHUB_SYNC_ERROR'
            ],
            500
        );

    }

}


/* ============================================================
   DELETE FROM GITHUB
============================================================ */

if (
    $action ===
    'delete_github'
) {

    $repoPath =
        trim(
            (string)(
                $input['path']
                ??
                ''
            )
        );


    $repoPath =
        str_replace(
            '\\',
            '/',
            $repoPath
        );


    if (
        $repoPath === ''
        ||
        str_contains(
            $repoPath,
            '..'
        )
        ||
        str_starts_with(
            $repoPath,
            '/'
        )
        ||
        !str_starts_with(
            $repoPath,
            'backups/'
        )
    ) {

        backupCreateResponse(
            false,
            'Invalid GitHub backup path.',
            [],
            403
        );

    }


    try {

        if (
            !is_dir(
                $githubCloneRoot
            )
        ) {

            backupEnsureDirectory(
                dirname(
                    $githubCloneRoot
                )
            );


            $cloneCommand =
                'git clone '
                .
                escapeshellarg(
                    $githubRemote
                )
                .
                ' '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' 2>&1';


            shell_exec(
                $cloneCommand
            );

        }


        $pullCommand =
            'git -C '
            .
            escapeshellarg(
                $githubCloneRoot
            )
            .
            ' pull --ff-only origin main 2>&1';


        shell_exec(
            $pullCommand
        );


        $target =
            realpath(
                $githubCloneRoot
                .
                DIRECTORY_SEPARATOR
                .
                str_replace(
                    '/',
                    DIRECTORY_SEPARATOR,
                    $repoPath
                )
            );


        $root =
            realpath(
                $githubCloneRoot
            );


        if (
            $target === false
            ||
            $root === false
        ) {

            backupCreateResponse(
                false,
                'GitHub backup was not found.',
                [],
                404
            );

        }


        $prefix =
            rtrim(
                $root,
                DIRECTORY_SEPARATOR
            )
            .
            DIRECTORY_SEPARATOR;


        if (
            strpos(
                $target,
                $prefix
            )
            !==
            0
            ||
            !is_file(
                $target
            )
        ) {

            backupCreateResponse(
                false,
                'Invalid GitHub backup target.',
                [],
                403
            );

        }


        $relativeName =
            substr(
                $target,
                strlen(
                    $githubCloneRoot
                )
            );


        $relativeName =
            ltrim(
                str_replace(
                    DIRECTORY_SEPARATOR,
                    '/',
                    $relativeName
                ),
                '/'
            );


        $gitRm =
            shell_exec(
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' rm -- '
                .
                escapeshellarg(
                    $relativeName
                )
                .
                ' 2>&1'
            );


        $gitStatus =
            shell_exec(
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' status --porcelain 2>&1'
            );


        if (
            trim(
                (string)
                $gitStatus
            )
            !==
            ''
        ) {

            shell_exec(
                'git -C '
                .
                escapeshellarg(
                    $githubCloneRoot
                )
                .
                ' commit -m '
                .
                escapeshellarg(
                    'Delete LOVEMI backup '
                    .
                    basename(
                        $target
                    )
                )
                .
                ' 2>&1'
            );


            $push =
                shell_exec(
                    'git -C '
                    .
                    escapeshellarg(
                        $githubCloneRoot
                    )
                    .
                    ' push origin main 2>&1'
                );


            if (
                stripos(
                    (string)
                    $push,
                    'fatal:'
                )
                !==
                false
            ) {

                error_log(
                    '[LOVEMI GITHUB DELETE PUSH] '
                    .
                    (string)
                    $push
                );


                backupCreateResponse(
                    false,
                    'The GitHub deletion was staged locally but could not be pushed.',
                    [],
                    500
                );

            }

        }


        try {

            $audit =
                $pdo->prepare(
                    "
                    INSERT INTO audit_logs
                    (
                        user_id,
                        action,
                        entity_type,
                        entity_id,
                        old_values,
                        new_values,
                        ip_address,
                        user_agent
                    )
                    VALUES
                    (
                        :user_id,
                        'admin_delete_github_backup',
                        'backup',
                        NULL,
                        :old_values,
                        NULL,
                        :ip,
                        :agent
                    )
                    "
                );


            $audit->execute(
                [

                    ':user_id' =>
                        $adminId,

                    ':old_values' =>
                        json_encode(
                            [
                                'github_path' =>
                                    $repoPath
                            ],
                            JSON_UNESCAPED_UNICODE
                        ),

                    ':ip' =>
                        $_SERVER['REMOTE_ADDR']
                        ??
                        null,

                    ':agent' =>
                        $_SERVER['HTTP_USER_AGENT']
                        ??
                        null

                ]
            );

        } catch (
            Throwable $auditError
        ) {

            error_log(
                '[LOVEMI GITHUB DELETE AUDIT] '
                .
                $auditError->getMessage()
            );

        }


        backupCreateResponse(
            true,
            'GitHub backup deleted successfully.',
            [
                'github_path' =>
                    $repoPath
            ]
        );

    } catch (
        Throwable $e
    ) {

        error_log(
            '[LOVEMI GITHUB DELETE] '
            .
            $e->getMessage()
        );


        backupCreateResponse(
            false,
            $e->getMessage(),
            [],
            500
        );

    }

}


/* ============================================================
   UNKNOWN ACTION
============================================================ */

backupCreateResponse(
    false,
    'Unknown backup action.',
    [
        'code' =>
            'UNKNOWN_ACTION',

        'allowed_actions' =>
            [

                'create',
                'delete_local',
                'restore_local',
                'sync_github',
                'delete_github'

            ]

    ],
    422
);