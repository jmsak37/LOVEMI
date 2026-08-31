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
    'Cache-Control: no-store, no-cache, must-revalidate, max-age=0'
);

header(
    'Pragma: no-cache'
);

header(
    'Expires: 0'
);


/* ============================================================
   JSON RESPONSE
============================================================ */

function backupListResponse(
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


    header(
        'Content-Type: application/json; charset=utf-8'
    );


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
        '[LOVEMI BACKUP LIST DB] '
        .
        $e->getMessage()
    );


    backupListResponse(
        false,
        'Database connection failed.',
        [
            'code' =>
                'DATABASE_ERROR'
        ],
        500
    );

}


/* ============================================================
   AUTHENTICATION
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

    backupListResponse(
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
        '[LOVEMI BACKUP LIST AUTH] '
        .
        $e->getMessage()
    );


    backupListResponse(
        false,
        'Unable to verify administrator permissions.',
        [],
        500
    );

}


if (
    !$admin
) {

    backupListResponse(
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

    backupListResponse(
        false,
        'The LOVEMI project directory could not be resolved.',
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


$githubRepository =
    'LOVEMI-back-up-files';


$githubOwner =
    'jmsak37';


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
   DOWNLOAD LOCAL ACTION
============================================================ */

$action =
    strtolower(
        trim(
            (string)(
                $_GET['action']
                ??
                ''
            )
        )
    );


if (
    $action ===
    'download'
) {

    $backupId =
        (int)(
            $_GET['id']
            ??
            0
        );


    if (
        $backupId <= 0
    ) {

        backupListResponse(
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

                    status,

                    file_size,

                    created_at

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

    } catch (
        Throwable $e
    ) {

        backupListResponse(
            false,
            'Unable to load the backup record.',
            [],
            500
        );

    }


    if (
        !$backup
    ) {

        backupListResponse(
            false,
            'Backup record not found.',
            [],
            404
        );

    }


    $requestedPath =
        trim(
            (string)
            $backup['file_path']
        );


    if (
        $requestedPath === ''
    ) {

        backupListResponse(
            false,
            'This backup does not have a local path.',
            [],
            404
        );

    }


    /*
     * Normalize and restrict to the backup directory.
     */

    $absolutePath =
        realpath(
            $requestedPath
        );


    $backupRootReal =
        realpath(
            $localBackupRoot
        );


    if (
        $absolutePath === false
        ||
        $backupRootReal === false
    ) {

        backupListResponse(
            false,
            'The local backup file no longer exists.',
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
            $absolutePath,
            $prefix
        )
        !==
        0
        &&
        $absolutePath
        !==
        $backupRootReal
    ) {

        backupListResponse(
            false,
            'Invalid backup path.',
            [],
            403
        );

    }


    /*
     * If a folder backup was created because it contained
     * ten files or fewer, package the folder temporarily so
     * the administrator can download it conveniently.
     */

    $downloadPath =
        $absolutePath;


    $temporaryZip =
        null;


    if (
        is_dir(
            $absolutePath
        )
    ) {

        if (
            !class_exists(
                'ZipArchive'
            )
        ) {

            backupListResponse(
                false,
                'PHP ZipArchive is required to download folder backups.',
                [],
                500
            );

        }


        if (
            !is_dir(
                $restoreRoot
            )
        ) {

            @mkdir(
                $restoreRoot,
                0775,
                true
            );

        }


        $temporaryZip =
            $restoreRoot
            .
            DIRECTORY_SEPARATOR
            .
            'download_'
            .
            $backupId
            .
            '_'
            .
            bin2hex(
                random_bytes(
                    5
                )
            )
            .
            '.zip';


        $zip =
            new ZipArchive();


        if (
            $zip->open(
                $temporaryZip,
                ZipArchive::CREATE
                |
                ZipArchive::OVERWRITE
            )
            !==
            true
        ) {

            backupListResponse(
                false,
                'Unable to create a temporary download archive.',
                [],
                500
            );

        }


        $iterator =
            new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator(
                    $absolutePath,
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


            $realFile =
                $file->getRealPath();


            if (
                $realFile === false
            ) {

                continue;

            }


            $relative =
                substr(
                    $realFile,
                    strlen(
                        $absolutePath
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
                $realFile,
                $relative
            );

        }


        $zip->close();


        $downloadPath =
            $temporaryZip;

    }


    if (
        !is_file(
            $downloadPath
        )
    ) {

        backupListResponse(
            false,
            'The backup file could not be found.',
            [],
            404
        );

    }


    $downloadName =
        basename(
            $downloadPath
        );


    header(
        'Content-Type: application/zip'
    );

    header(
        'Content-Disposition: attachment; filename="'
        .
        addslashes(
            $backup['file_name']
        )
        .
        '"'
    );

    header(
        'Content-Length: '
        .
        (string)
        filesize(
            $downloadPath
        )
    );


    readfile(
        $downloadPath
    );


    if (
        $temporaryZip
        &&
        is_file(
            $temporaryZip
        )
    ) {

        @unlink(
            $temporaryZip
        );

    }


    exit;

}


/* ============================================================
   GITHUB DOWNLOAD ACTION
============================================================ */

if (
    $action ===
    'github_download'
) {

    $repoPath =
        trim(
            (string)(
                $_GET['path']
                ??
                ''
            )
        );


    if (
        $repoPath === ''
    ) {

        backupListResponse(
            false,
            'GitHub backup path is required.',
            [],
            422
        );

    }


    $repoPath =
        str_replace(
            '\\',
            '/',
            $repoPath
        );


    if (
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
        preg_match(
            '/^[A-Za-z]:/',
            $repoPath
        )
    ) {

        backupListResponse(
            false,
            'Invalid GitHub backup path.',
            [],
            403
        );

    }


    /*
     * Ensure repository exists locally.
     */

    if (
        !is_dir(
            $githubCloneRoot
        )
    ) {

        if (
            !is_dir(
                dirname(
                    $githubCloneRoot
                )
            )
        ) {

            @mkdir(
                dirname(
                    $githubCloneRoot
                ),
                0775,
                true
            );

        }


        $command =
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


        $output =
            shell_exec(
                $command
            );


        if (
            !is_dir(
                $githubCloneRoot
            )
        ) {

            error_log(
                '[LOVEMI BACKUP GITHUB CLONE] '
                .
                (string)
                $output
            );


            backupListResponse(
                false,
                'Unable to clone the GitHub backup repository. Configure Git authentication on the server first.',
                [],
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


    $candidate =
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


    $githubRootReal =
        realpath(
            $githubCloneRoot
        );


    if (
        $candidate === false
        ||
        $githubRootReal === false
    ) {

        backupListResponse(
            false,
            'The requested GitHub backup does not exist.',
            [],
            404
        );

    }


    $githubPrefix =
        rtrim(
            $githubRootReal,
            DIRECTORY_SEPARATOR
        )
        .
        DIRECTORY_SEPARATOR;


    if (
        strpos(
            $candidate,
            $githubPrefix
        )
        !==
        0
    ) {

        backupListResponse(
            false,
            'Invalid GitHub backup path.',
            [],
            403
        );

    }


    if (
        !is_file(
            $candidate
        )
    ) {

        backupListResponse(
            false,
            'Only downloadable GitHub files are supported by this action.',
            [],
            422
        );

    }


    header(
        'Content-Type: application/octet-stream'
    );


    header(
        'Content-Disposition: attachment; filename="'
        .
        addslashes(
            basename(
                $candidate
            )
        )
        .
        '"'
    );


    header(
        'Content-Length: '
        .
        (string)
        filesize(
            $candidate
        )
    );


    readfile(
        $candidate
    );


    exit;

}


/* ============================================================
   LOAD BACKUP RECORDS
============================================================ */

try {

    $stmt =
        $pdo->query(
            "
            SELECT

                b.id,

                b.created_by,

                b.file_name,

                b.file_path,

                b.status,

                b.file_size,

                b.created_at,

                u.username AS creator_username,

                u.full_names AS creator_name

            FROM backup_logs b

            LEFT JOIN users u
                ON u.id =
                    b.created_by

            ORDER BY

                b.created_at DESC,

                b.id DESC
            "
        );


    $backups =
        $stmt->fetchAll();

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BACKUP RECORDS] '
        .
        $e->getMessage()
    );


    backupListResponse(
        false,
        'Unable to load backup records.',
        [],
        500
    );

}


/* ============================================================
   LOCAL BACKUP DIRECTORY
============================================================ */

if (
    !is_dir(
        $localBackupRoot
    )
) {

    @mkdir(
        $localBackupRoot,
        0775,
        true
    );

}


/* ============================================================
   ENRICH RECORDS
============================================================ */

$totalLocal =
    count(
        $backups
    );


$totalSize =
    0;


foreach (
    $backups
    as &$backup
) {

    $backupPath =
        (string)
        $backup['file_path'];


    $backup['is_zip'] =
        strtolower(
            pathinfo(
                (string)
                $backup['file_name'],
                PATHINFO_EXTENSION
            )
        )
        ===
        'zip';


    $backup['github_synced'] =
        false;


    $backup['github_path'] =
        'backups/'
        .
        $backup['file_name'];


    if (
        $backupPath !== ''
    ) {

        $real =
            realpath(
                $backupPath
            );


        if (
            $real !== false
        ) {

            if (
                is_file(
                    $real
                )
            ) {

                $backup['file_size'] =
                    (int)
                    filesize(
                        $real
                    );

                $totalSize +=
                    (int)
                    $backup['file_size'];

            }


            if (
                is_dir(
                    $real
                )
            ) {

                $size =
                    0;


                $iterator =
                    new RecursiveIteratorIterator(
                        new RecursiveDirectoryIterator(
                            $real,
                            FilesystemIterator::SKIP_DOTS
                        ),
                        RecursiveIteratorIterator::LEAVES_ONLY
                    );


                foreach (
                    $iterator
                    as $file
                ) {

                    if (
                        $file->isFile()
                    ) {

                        $size +=
                            (int)
                            $file->getSize();

                    }

                }


                $backup['file_size'] =
                    $size;


                $totalSize +=
                    $size;

            }

        }

    }


    /*
     * Check the GitHub clone if it exists.
     */

    if (
        is_dir(
            $githubCloneRoot
        )
    ) {

        $gitFile =
            $githubCloneRoot
            .
            DIRECTORY_SEPARATOR
            .
            'backups'
            .
            DIRECTORY_SEPARATOR
            .
            $backup['file_name'];


        if (
            is_file(
                $gitFile
            )
        ) {

            $backup['github_synced'] =
                true;


            $backup['github_path'] =
                'backups/'
                .
                $backup['file_name'];

        }

    }

}

unset(
    $backup
);


/* ============================================================
   GITHUB STATUS
============================================================ */

$githubStatus =
    [

        'repository' =>
            $githubOwner
            .
            '/'
            .
            $githubRepository,

        'remote' =>
            $githubRemote,

        'local_clone' =>
            $githubCloneRoot,

        'available' =>
            is_dir(
                $githubCloneRoot
            )

    ];


/* ============================================================
   GITHUB FILE COUNT
============================================================ */

$githubCount =
    0;


if (
    is_dir(
        $githubCloneRoot
        .
        DIRECTORY_SEPARATOR
        .
        'backups'
    )
) {

    try {

        $iterator =
            new FilesystemIterator(
                $githubCloneRoot
                .
                DIRECTORY_SEPARATOR
                .
                'backups',
                FilesystemIterator::SKIP_DOTS
            );


        foreach (
            $iterator
            as $item
        ) {

            if (
                $item->isFile()
            ) {

                $githubCount++;

            }

        }

    } catch (
        Throwable $e
    ) {

        $githubCount =
            0;

    }

}


/* ============================================================
   ADMIN AVATAR
============================================================ */

$avatar =
    null;


try {

    $avatarStmt =
        $pdo->prepare(
            "
            SELECT
                file_path

            FROM photos

            WHERE

                user_id =
                    :user_id

                AND photo_type =
                    'profile'

                AND is_primary =
                    1

                AND approval_status =
                    'approved'

            ORDER BY
                id DESC

            LIMIT 1
            "
        );


    $avatarStmt->execute(
        [
            ':user_id' =>
                $adminId
        ]
    );


    $avatar =
        $avatarStmt->fetchColumn()
        ?:
        null;

} catch (
    Throwable $e
) {


}


/* ============================================================
   UPDATE SESSION ACTIVITY
============================================================ */

try {

    $activityStmt =
        $pdo->prepare(
            "
            UPDATE user_sessions

            SET
                last_activity_at =
                    CURRENT_TIMESTAMP

            WHERE

                id =
                    :session_id

                AND user_id =
                    :user_id

            LIMIT 1
            "
        );


    $activityStmt->execute(
        [

            ':session_id' =>
                $sessionId,

            ':user_id' =>
                $adminId

        ]
    );

} catch (
    Throwable $e
) {

    error_log(
        '[LOVEMI BACKUP ACTIVITY] '
        .
        $e->getMessage()
    );

}


/* ============================================================
   RESPONSE
============================================================ */

backupListResponse(
    true,
    'Backups loaded successfully.',
    [

        'admin' => [

            'id' =>
                (int)
                $admin['id'],

            'username' =>
                $admin['username'],

            'full_names' =>
                $admin['full_names'],

            'email' =>
                $admin['email'],

            'role_id' =>
                (int)
                $admin['role_id'],

            'role_name' =>
                $admin['role_name'],

            'role_slug' =>
                $admin['role_slug'],

            'avatar_url' =>
                $avatar

        ],


        'summary' => [

            'local_count' =>
                $totalLocal,

            'github_count' =>
                $githubCount,

            'total_size' =>
                $totalSize,

            'repository' =>
                $githubOwner
                .
                '/'
                .
                $githubRepository

        ],


        'backups' =>
            $backups,


        'github' =>
            $githubStatus

    ]
);