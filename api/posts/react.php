<?php

declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');


if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}


function reactResponse(
    bool $success,
    string $message,
    array $extra = [],
    int $status = 200
): never {

    http_response_code($status);

    echo json_encode(
        array_merge(
            [
                'success' => $success,
                'message' => $message
            ],
            $extra
        ),
        JSON_UNESCAPED_UNICODE |
        JSON_UNESCAPED_SLASHES
    );

    exit;
}


if (
    ($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST'
) {

    reactResponse(
        false,
        'Only POST requests are allowed.',
        [],
        405
    );

}


$userId =
    isset(
        $_SESSION['lovemi_user_id']
    )
        ?
        (int)
        $_SESSION['lovemi_user_id']
        :
        0;


if ($userId <= 0) {

    reactResponse(
        false,
        'Please log in first.',
        [],
        401
    );

}


$input =
    json_decode(
        file_get_contents(
            'php://input'
        ) ?: '{}',
        true
    );


$postId =
    (int)(
        $input['post_id']
        ??
        0
    );


$reaction =
    $input['reaction']
    ??
    null;


if (
    !in_array(
        $reaction,
        [
            null,
            '',
            'like',
            'dislike'
        ],
        true
    )
) {

    reactResponse(
        false,
        'Invalid reaction.',
        [],
        422
    );

}


try {

    $pdo =
        db();

} catch (Throwable $e) {

    reactResponse(
        false,
        'Database connection failed.',
        [],
        500
    );

}


$pdo->exec(
    "
    CREATE TABLE IF NOT EXISTS post_reactions
    (
        id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,

        post_id BIGINT UNSIGNED NOT NULL,

        user_id BIGINT UNSIGNED NOT NULL,

        reaction VARCHAR(20) NOT NULL,

        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ON UPDATE CURRENT_TIMESTAMP,

        PRIMARY KEY(id),

        UNIQUE KEY uq_post_reaction_user
            (post_id,user_id)

    )
    ENGINE=InnoDB
    DEFAULT CHARSET=utf8mb4
    "
);


$postStmt =
    $pdo->prepare(
        "
        SELECT id

        FROM posts

        WHERE

            id = :post_id

          AND approval_status = 'approved'

          AND visibility = 'public'

          AND deleted_at IS NULL

        LIMIT 1
        "
    );


$postStmt->execute(
    [
        ':post_id' =>
            $postId
    ]
);


if (!$postStmt->fetch()) {

    reactResponse(
        false,
        'This post is not available.',
        [],
        404
    );

}


try {

    $pdo->beginTransaction();


    if (
        $reaction === null
        ||
        $reaction === ''
    ) {

        $delete =
            $pdo->prepare(
                "
                DELETE FROM post_reactions

                WHERE post_id = :post_id

                  AND user_id = :user_id

                LIMIT 1
                "
            );


        $delete->execute(
            [
                ':post_id' =>
                    $postId,

                ':user_id' =>
                    $userId
            ]
        );

    } else {

        $upsert =
            $pdo->prepare(
                "
                INSERT INTO post_reactions
                (
                    post_id,
                    user_id,
                    reaction,
                    created_at,
                    updated_at
                )
                VALUES
                (
                    :post_id,
                    :user_id,
                    :reaction,
                    CURRENT_TIMESTAMP,
                    CURRENT_TIMESTAMP
                )

                ON DUPLICATE KEY UPDATE

                    reaction =
                        VALUES(reaction),

                    updated_at =
                        CURRENT_TIMESTAMP
                "
            );


        $upsert->execute(
            [
                ':post_id' =>
                    $postId,

                ':user_id' =>
                    $userId,

                ':reaction' =>
                    $reaction

            ]
        );

    }


    $pdo->commit();

} catch (Throwable $e) {

    if (
        $pdo->inTransaction()
    ) {

        $pdo->rollBack();

    }


    error_log(
        '[LOVEMI REACTION] ' .
        $e->getMessage()
    );


    reactResponse(
        false,
        'Unable to save reaction.',
        [],
        500
    );

}


$count =
    $pdo->prepare(
        "
        SELECT

            SUM(
                CASE
                    WHEN reaction = 'like'
                    THEN 1
                    ELSE 0
                END
            ) AS likes,

            SUM(
                CASE
                    WHEN reaction = 'dislike'
                    THEN 1
                    ELSE 0
                END
            ) AS dislikes

        FROM post_reactions

        WHERE post_id = :post_id
        "
    );


$count->execute(
    [
        ':post_id' =>
            $postId
    ]
);


$counts =
    $count->fetch();


$mine =
    $pdo->prepare(
        "
        SELECT reaction

        FROM post_reactions

        WHERE post_id = :post_id

          AND user_id = :user_id

        LIMIT 1
        "
    );


$mine->execute(
    [
        ':post_id' =>
            $postId,

        ':user_id' =>
            $userId
    ]
);


$myReaction =
    $mine->fetchColumn()
    ?:
    null;


reactResponse(
    true,
    'Reaction updated.',
    [
        'data' =>
            [

                'like_count' =>
                    (int)(
                        $counts['likes']
                        ??
                        0
                    ),

                'dislike_count' =>
                    (int)(
                        $counts['dislikes']
                        ??
                        0
                    ),

                'my_reaction' =>
                    $myReaction

            ]
    ]
);