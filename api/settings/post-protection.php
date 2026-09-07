<?php
declare(strict_types=1);

require_once __DIR__ . '/../../config/database.php';

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('Expires: 0');

if(session_status()!==PHP_SESSION_ACTIVE)session_start();

function contentProtectionResponse(bool $success,string $message,array $data=[],int $status=200):never{
    http_response_code($status);
    echo json_encode(array_merge(['success'=>$success,'message'=>$message],$data),JSON_UNESCAPED_UNICODE|JSON_UNESCAPED_SLASHES);
    exit;
}

$userId=(int)($_SESSION['lovemi_user_id']??0);
if($userId<=0)contentProtectionResponse(false,'Please log in first.',['code'=>'AUTHENTICATION_REQUIRED'],401);

try{$pdo=db();}catch(Throwable $e){
    error_log('[LOVEMI CONTENT PROTECTION DB] '.$e->getMessage());
    contentProtectionResponse(false,'Unable to connect to the database.',['code'=>'DATABASE_ERROR'],500);
}

try{
    $u=$pdo->prepare("SELECT id,is_active,is_suspended,is_deleted FROM users WHERE id=:user_id LIMIT 1");
    $u->execute([':user_id'=>$userId]);
    $user=$u->fetch(PDO::FETCH_ASSOC);
}catch(Throwable $e){
    contentProtectionResponse(false,'Unable to verify your account.',['code'=>'USER_LOOKUP_FAILED'],500);
}
if(!$user)contentProtectionResponse(false,'Account not found.',['code'=>'USER_NOT_FOUND'],404);
if((int)$user['is_deleted']===1 || (int)$user['is_suspended']===1 || (int)$user['is_active']!==1){
    contentProtectionResponse(false,'Your account is currently unavailable.',['code'=>'ACCOUNT_UNAVAILABLE'],403);
}

/*
 * Important repair:
 * Initialize the protection table automatically if an earlier migration was
 * not installed. This removes the "Unable to initialize content protection"
 * failure for valid LOVEMI accounts.
 */
try{
    $pdo->exec("
        CREATE TABLE IF NOT EXISTS user_content_security (
            user_id BIGINT UNSIGNED NOT NULL PRIMARY KEY,
            default_allow_repost TINYINT(1) NOT NULL DEFAULT 1,
            default_allow_video_download TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    ");
    $ensure=$pdo->prepare("INSERT INTO user_content_security(user_id) VALUES(:user_id) ON DUPLICATE KEY UPDATE user_id=user_id");
    $ensure->execute([':user_id'=>$userId]);
}catch(Throwable $e){
    error_log('[LOVEMI CONTENT PROTECTION INIT] '.$e->getMessage());
    contentProtectionResponse(false,'Unable to initialize content protection. The protection storage could not be prepared.',['code'=>'SECURITY_ROW_FAILED'],500);
}

if(($_SERVER['REQUEST_METHOD']??'GET')==='GET'){
    $action=trim((string)($_GET['action']??'list'));
    if($action!=='list')contentProtectionResponse(false,'Invalid request.',['code'=>'INVALID_ACTION'],422);

    try{
        $stmt=$pdo->prepare("
            SELECT id,content,allow_repost,allow_video_download,media_protection_enabled,created_at,updated_at
            FROM posts
            WHERE user_id=:user_id AND deleted_at IS NULL
            ORDER BY created_at DESC,id DESC
            LIMIT 200
        ");
        $stmt->execute([':user_id'=>$userId]);
        $posts=$stmt->fetchAll(PDO::FETCH_ASSOC);
        foreach($posts as &$post){
            $post['id']=(int)$post['id'];
            $post['allow_repost']=(int)$post['allow_repost'];
            $post['allow_video_download']=(int)$post['allow_video_download'];
            $post['media_protection_enabled']=(int)($post['media_protection_enabled']??0);
        }
        unset($post);
        contentProtectionResponse(true,'Posts loaded successfully.',['posts'=>$posts]);
    }catch(Throwable $e){
        error_log('[LOVEMI CONTENT PROTECTION LIST] '.$e->getMessage());
        contentProtectionResponse(false,'Unable to load your posts.',['code'=>'POST_LIST_FAILED'],500);
    }
}

if(($_SERVER['REQUEST_METHOD']??'')!=='POST'){
    contentProtectionResponse(false,'Only GET and POST requests are allowed.',['code'=>'METHOD_NOT_ALLOWED'],405);
}

$raw=file_get_contents('php://input');
$input=json_decode((string)$raw,true);
if(!is_array($input))$input=$_POST;
$action=trim((string)($input['action']??''));

if($action==='defaults'){
    $allowRepost=(int)($input['default_allow_repost']??1);
    $allowVideoDownload=(int)($input['default_allow_video_download']??1);
    if(!in_array($allowRepost,[0,1],true)||!in_array($allowVideoDownload,[0,1],true)){
        contentProtectionResponse(false,'Invalid protection values.',['code'=>'INVALID_PROTECTION_VALUE'],422);
    }
    try{
        $stmt=$pdo->prepare("
            UPDATE user_content_security
            SET default_allow_repost=:allow_repost,
                default_allow_video_download=:allow_video_download
            WHERE user_id=:user_id
            LIMIT 1
        ");
        $stmt->execute([
            ':allow_repost'=>$allowRepost,
            ':allow_video_download'=>$allowVideoDownload,
            ':user_id'=>$userId
        ]);
        contentProtectionResponse(true,'Content protection defaults saved successfully.',[
            'content_security'=>[
                'default_allow_repost'=>$allowRepost,
                'default_allow_video_download'=>$allowVideoDownload
            ]
        ]);
    }catch(Throwable $e){
        error_log('[LOVEMI CONTENT PROTECTION DEFAULTS] '.$e->getMessage());
        contentProtectionResponse(false,'Unable to save the protection defaults.',['code'=>'DEFAULT_UPDATE_FAILED'],500);
    }
}

if($action==='apply_all'){
    $allowRepost=(int)($input['allow_repost']??1);
    $allowVideoDownload=(int)($input['allow_video_download']??1);
    if(!in_array($allowRepost,[0,1],true)||!in_array($allowVideoDownload,[0,1],true)){
        contentProtectionResponse(false,'Invalid protection values.',['code'=>'INVALID_PROTECTION_VALUE'],422);
    }

    try{
        $pdo->beginTransaction();

        $stmt=$pdo->prepare("
            UPDATE posts
            SET allow_repost=:allow_repost,
                allow_video_download=:allow_video_download
            WHERE user_id=:user_id AND deleted_at IS NULL
        ");
        $stmt->execute([
            ':allow_repost'=>$allowRepost,
            ':allow_video_download'=>$allowVideoDownload,
            ':user_id'=>$userId
        ]);
        $affected=$stmt->rowCount();

        $defaultStmt=$pdo->prepare("
            UPDATE user_content_security
            SET default_allow_repost=:allow_repost,
                default_allow_video_download=:allow_video_download
            WHERE user_id=:user_id LIMIT 1
        ");
        $defaultStmt->execute([
            ':allow_repost'=>$allowRepost,
            ':allow_video_download'=>$allowVideoDownload,
            ':user_id'=>$userId
        ]);

        $pdo->commit();
        contentProtectionResponse(true,"Protection applied to {$affected} post(s).",['affected'=>$affected]);
    }catch(Throwable $e){
        if($pdo->inTransaction())$pdo->rollBack();
        error_log('[LOVEMI CONTENT PROTECTION ALL] '.$e->getMessage());
        contentProtectionResponse(false,'Unable to apply protection to your posts.',['code'=>'APPLY_ALL_FAILED'],500);
    }
}

if($action==='post'){
    $postId=(int)($input['post_id']??0);
    $allowRepost=(int)($input['allow_repost']??1);
    $allowVideoDownload=(int)($input['allow_video_download']??1);

    if($postId<=0)contentProtectionResponse(false,'Invalid post.',['code'=>'INVALID_POST'],422);
    if(!in_array($allowRepost,[0,1],true)||!in_array($allowVideoDownload,[0,1],true)){
        contentProtectionResponse(false,'Invalid protection values.',['code'=>'INVALID_PROTECTION_VALUE'],422);
    }

    try{
        $stmt=$pdo->prepare("
            UPDATE posts
            SET allow_repost=:allow_repost,
                allow_video_download=:allow_video_download
            WHERE id=:post_id AND user_id=:user_id AND deleted_at IS NULL
            LIMIT 1
        ");
        $stmt->execute([
            ':allow_repost'=>$allowRepost,
            ':allow_video_download'=>$allowVideoDownload,
            ':post_id'=>$postId,
            ':user_id'=>$userId
        ]);

        if($stmt->rowCount()!==1){
            $check=$pdo->prepare("SELECT id FROM posts WHERE id=:post_id AND user_id=:user_id AND deleted_at IS NULL LIMIT 1");
            $check->execute([':post_id'=>$postId,':user_id'=>$userId]);
            if(!$check->fetchColumn()){
                contentProtectionResponse(false,'The post was not found or does not belong to you.',['code'=>'POST_NOT_FOUND'],404);
            }
        }
        contentProtectionResponse(true,'Post protection saved successfully.',[
            'post'=>[
                'id'=>$postId,
                'allow_repost'=>$allowRepost,
                'allow_video_download'=>$allowVideoDownload
            ]
        ]);
    }catch(Throwable $e){
        error_log('[LOVEMI CONTENT PROTECTION POST] '.$e->getMessage());
        contentProtectionResponse(false,'Unable to update this post.',['code'=>'POST_UPDATE_FAILED'],500);
    }
}

contentProtectionResponse(false,'Invalid content protection action.',['code'=>'INVALID_ACTION'],422);
